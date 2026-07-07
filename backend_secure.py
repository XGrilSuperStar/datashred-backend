import os
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import Depends, FastAPI, HTTPException, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy import JSON, Boolean, Column, DateTime, Integer, String, create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import stripe
import bcrypt
import jwt
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler

# --- CONFIGURATION & STRIPE LAYER ---
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:pass@localhost/optout_db")
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "sk_test_your_key_here")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "whsec_your_secret_here")
stripe.api_key = STRIPE_SECRET_KEY

# --- AUTH / SESSION CONFIGURATION ---
# JWT_SECRET_KEY and ADMIN_SECRET_KEY MUST be set as real env vars in production.
# The app refuses to start with the placeholder defaults outside of local dev,
# so nobody accidentally ships with a guessable session-signing key.
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ADMIN_SECRET_KEY = os.getenv("ADMIN_SECRET_KEY")
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")

if ENVIRONMENT == "production" and (not JWT_SECRET_KEY or not ADMIN_SECRET_KEY):
    raise RuntimeError(
        "JWT_SECRET_KEY and ADMIN_SECRET_KEY must be set in the environment before "
        "running in production. Generate strong random values, e.g. `openssl rand -hex 32`."
    )

JWT_SECRET_KEY = JWT_SECRET_KEY or "dev-only-insecure-key-do-not-use-in-production"
ADMIN_SECRET_KEY = ADMIN_SECRET_KEY or "dev-only-insecure-admin-key"
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 24 * 7  # sessions last 7 days, then require re-login

# Allowed frontend origin(s) for CORS. Set FRONTEND_ORIGIN in the environment
# once the site has a real domain -- do not leave this as "*" in production.
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "http://localhost:3000")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- DATABASE TABLE MODEL ---
class Customer(Base):
    __tablename__ = "customers"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    first_name = Column(String)
    last_name = Column(String)

    # Tier Tracking
    scan_credits = Column(Integer, default=0)
    is_annual_subscriber = Column(Boolean, default=False)
    annual_expires_at = Column(DateTime, nullable=True)

    progress_log = Column(JSON, default=dict)
    activity_timeline = Column(JSON, default=list)
    last_scan_date = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# --- BACKGROUND SCHEDULER (QUARTERLY SWEEPS) ---
scheduler = BackgroundScheduler()
scheduler.start()

app = FastAPI(title="dataShred Central API")

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Only the real frontend origin can call this API with credentials.
# Never combine allow_origins=["*"] with allow_credentials=True -- browsers
# reject that combination anyway, but it signals the policy isn't scoped.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization", "X-Admin-Key"],
)

# --- SERVE FRONTEND (index.html) FROM THE SAME SERVICE ---
# API routes below are registered first and take priority; this catch-all
# only serves index.html for the root and any non-API path (client-side nav).
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import os as _os

_STATIC_DIR = _os.path.dirname(_os.path.abspath(__file__))

@app.get("/")
def serve_index():
    return FileResponse(_os.path.join(_STATIC_DIR, "index.html"))


def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

# --- PASSWORD HASHING HELPERS ---
def hash_password(raw_password: str) -> str:
    return bcrypt.hashpw(raw_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(raw_password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(raw_password.encode("utf-8"), password_hash.encode("utf-8"))

# --- JWT SESSION TOKEN HELPERS ---
def create_session_token(customer_id: int) -> str:
    payload = {
        "customer_id": customer_id,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def get_current_customer_id(authorization: str = Header(None)) -> int:
    """Extracts and verifies the customer_id from the Bearer token.
    This replaces trusting a client-supplied customer_id query param --
    a customer can only ever act on their own account."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header.")
    token = authorization.removeprefix("Bearer ").strip()
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired. Please sign in again.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid session token.")
    return payload["customer_id"]

def verify_admin_key(x_admin_key: str = Header(None)):
    """Admin key now travels as a header, not a URL query param, so it
    never ends up in server access logs, browser history, or proxy logs."""
    if not x_admin_key or x_admin_key != ADMIN_SECRET_KEY:
        raise HTTPException(status_code=403, detail="Invalid admin master key.")

# --- VALIDATION OBJECTS ---
class UserAuthForm(BaseModel):
    email: EmailStr
    password: str

class UserRegisterForm(BaseModel):
    email: EmailStr
    password: str
    first_name: str
    last_name: str

class CheckoutForm(BaseModel):
    tier: str

class AdminGrantForm(BaseModel):
    customer_id: int
    tier_choice: str

# --- AUTHENTICATION ENDPOINTS ---

@app.post("/api/v1/auth/register")
@limiter.limit("5/minute")
def register(request: Request, form: UserRegisterForm, db=Depends(get_db)):
    if db.query(Customer).filter(Customer.email == form.email).first():
        raise HTTPException(status_code=400, detail="Account already exists.")
    if len(form.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")
    new_user = Customer(
        email=form.email,
        password_hash=hash_password(form.password),
        first_name=form.first_name,
        last_name=form.last_name,
        progress_log={"spokeo": {"status": "pending"}, "whitepages": {"status": "pending"}},
        activity_timeline=[{"time": datetime.now().strftime("%I:%M %p"), "event": "Account Created", "details": "Secure profile entry established."}]
    )
    db.add(new_user)
    db.commit()
    token = create_session_token(new_user.id)
    return {"status": "success", "token": token}

@app.post("/api/v1/auth/login")
@limiter.limit("10/minute")
def login(request: Request, form: UserAuthForm, db=Depends(get_db)):
    user = db.query(Customer).filter(Customer.email == form.email).first()
    if not user or not verify_password(form.password, user.password_hash):
        # Same error whether the email doesn't exist or the password is wrong --
        # don't reveal which one, so accounts can't be enumerated.
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    token = create_session_token(user.id)
    return {"status": "success", "token": token}

@app.post("/api/v1/auth/logout")
def logout(customer_id: int = Depends(get_current_customer_id)):
    # JWTs are stateless, so "logout" is enforced client-side by discarding
    # the token. If you need real server-side revocation later (e.g. for a
    # "log out all devices" feature), add a token-blocklist table keyed by
    # a jti claim and check it here.
    return {"status": "success"}

# --- DASHBOARD & CONTROL ENDPOINTS ---
# customer_id now comes from the verified token, never from the request --
# this closes the hole where anyone could pass any customer_id and read
# or modify someone else's account.

@app.get("/api/v1/dashboard")
def get_dashboard(customer_id: int = Depends(get_current_customer_id), db=Depends(get_db)):
    user = db.query(Customer).filter(Customer.id == customer_id).first()
    if not user: raise HTTPException(status_code=404, detail="User profile missing.")

    is_annual_active = user.is_annual_subscriber and user.annual_expires_at and user.annual_expires_at > datetime.utcnow()

    return {
        "status": "active",
        "scan_credits": user.scan_credits,
        "is_annual_active": is_annual_active,
        "expiry_date": user.annual_expires_at.strftime("%Y-%m-%d") if user.annual_expires_at else None,
        "customer_profile": {"name": f"{user.first_name} {user.last_name}"},
        "agent_progress": user.progress_log,
        "timeline": user.activity_timeline
    }

@app.post("/api/v1/dashboard/reset-scan")
def trigger_scan(customer_id: int = Depends(get_current_customer_id), db=Depends(get_db)):
    user = db.query(Customer).filter(Customer.id == customer_id).first()
    if not user: raise HTTPException(status_code=404, detail="User missing.")

    is_annual_active = user.is_annual_subscriber and user.annual_expires_at and user.annual_expires_at > datetime.utcnow()

    if not is_annual_active:
        if user.scan_credits < 1:
            raise HTTPException(status_code=402, detail="No scan credits remaining.")
        user.scan_credits -= 1

    timestamp = datetime.now().strftime("%I:%M %p")
    user.activity_timeline = [
        {"time": timestamp, "event": "Initialization", "details": "Autonomous dataShred core engine spawned successfully."},
        {"time": timestamp, "event": "Scanning", "details": "Crawling database indexes for matching criteria..."}
    ]

    for broker in user.progress_log.keys():
        user.progress_log[broker] = {"status": "pending", "notes": "Dispatched."}

    db.commit()
    return {"status": "success", "message": "Scrub tracking session initialized."}

# --- STRIPE CHECKOUT ---

@app.post("/api/v1/payments/create-checkout")
def create_checkout(form: CheckoutForm, customer_id: int = Depends(get_current_customer_id), db=Depends(get_db)):
    if form.tier not in ("single", "annual"):
        raise HTTPException(status_code=400, detail="Invalid plan selected.")
    user = db.query(Customer).filter(Customer.id == customer_id).first()
    if not user: raise HTTPException(status_code=404, detail="User missing.")

    price_id = os.getenv("STRIPE_PRICE_SINGLE") if form.tier == "single" else os.getenv("STRIPE_PRICE_ANNUAL")
    session = stripe.checkout.Session.create(
        mode="payment" if form.tier == "single" else "subscription",
        line_items=[{"price": price_id, "quantity": 1}],
        customer_email=user.email,
        metadata={"customer_id": str(customer_id), "tier_choice": form.tier},
        success_url=f"{FRONTEND_ORIGIN}/?payment=success",
        cancel_url=f"{FRONTEND_ORIGIN}/?payment=cancelled",
    )
    return {"checkout_url": session.url}

# --- AUTOMATED STRIPE WEBHOOK LISTENER ---

@app.post("/api/v1/payments/webhook")
async def stripe_webhook_listener(request: Request, db=Depends(get_db)):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except (ValueError, stripe.error.SignatureVerificationError):
        raise HTTPException(status_code=400, detail="Security verification failed.")

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        customer_id = session.get("metadata", {}).get("customer_id")
        purchased_tier = session.get("metadata", {}).get("tier_choice")

        if customer_id:
            user = db.query(Customer).filter(Customer.id == int(customer_id)).first()
            if user:
                if purchased_tier == "single":
                    user.scan_credits += 1
                elif purchased_tier == "annual":
                    user.is_annual_subscriber = True
                    user.annual_expires_at = datetime.utcnow() + timedelta(days=365)
                    user.scan_credits += 1
                db.commit()

    return {"status": "success"}

# --- OWNER ADMINISTRATIVE CONTROL CORE ---
# admin_secret now arrives as an X-Admin-Key header, never a URL query param.

@app.post("/api/v1/admin/grant-access")
@limiter.limit("20/minute")
def admin_grant_access(request: Request, form: AdminGrantForm, db=Depends(get_db), _=Depends(verify_admin_key)):
    user = db.query(Customer).filter(Customer.id == form.customer_id).first()
    if not user: raise HTTPException(status_code=404, detail="User not found.")

    if form.tier_choice == "single":
        user.scan_credits += 1
    elif form.tier_choice == "annual":
        user.is_annual_subscriber = True
        user.annual_expires_at = datetime.utcnow() + timedelta(days=365)
        user.scan_credits += 1

    db.commit()
    return {"status": "success", "message": f"Successfully upgraded user {user.email}."}

# --- AUTOMATED BACKGROUND QUARTERLY CLEANUP TIMER ---
def run_automatic_annual_refreshes():
    db = SessionLocal()
    try:
        now = datetime.utcnow()
        ninety_days_ago = now - timedelta(days=90)
        due_users = db.query(Customer).filter(
            Customer.is_annual_subscriber == True, Customer.annual_expires_at > now, Customer.last_scan_date <= ninety_days_ago
        ).all()
        for user in due_users:
            for broker in user.progress_log.keys():
                user.progress_log[broker] = {"status": "pending", "notes": "Quarterly automated sweep triggered."}
            user.last_scan_date = now
        db.commit()
    finally: db.close()

scheduler.add_job(run_automatic_annual_refreshes, 'interval', days=1)
