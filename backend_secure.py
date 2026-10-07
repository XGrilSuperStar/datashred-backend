import os
import urllib.request
import urllib.parse
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
OWNER_EMAIL = os.getenv("OWNER_EMAIL", "")
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY", "")
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

# Force the psycopg2 driver (what requirements.txt installs) whatever scheme the host provides.
for _prefix in ("postgres://", "postgresql://", "postgresql+psycopg://"):
    if DATABASE_URL.startswith(_prefix):
        DATABASE_URL = "postgresql+psycopg2://" + DATABASE_URL[len(_prefix):]
        break

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

class Broker(Base):
    __tablename__ = "brokers"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    dba = Column(String, default="")
    website = Column(String, default="")
    opt_out_email = Column(String, default="")
    opt_out_phone = Column(String, default="")
    opt_out_url = Column(String, default="")
    notes = Column(String, default="")
    sources = Column(JSON, default=list)

Base.metadata.create_all(bind=engine)


def seed_brokers():
    """Loads data/brokers.json into the brokers table; adds any names not already there."""
    import json
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "brokers.json")
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        rows = json.load(f)
    db = SessionLocal()
    try:
        existing = {n for (n,) in db.query(Broker.name).all()}
        for r in rows:
            if r["name"] in existing:
                continue
            db.add(Broker(**{k: r.get(k, "" if k != "sources" else []) for k in
                             ("name", "dba", "website", "opt_out_email", "opt_out_phone", "opt_out_url", "notes", "sources")}))
            existing.add(r["name"])
        db.commit()
    finally:
        db.close()

seed_brokers()

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

def verify_recaptcha(token: str) -> bool:
     """Calls Google's siteverify endpoint to confirm the checkbox was solved
     by a real browser, not a bot hitting the API directly."""
    if not RECAPTCHA_SECRET_KEY:
        # Fails closed in production (no key = registration blocked) rather
        # than silently skipping the check.
        return ENVIRONMENT != "production"
    if not token:
        return False
    try:
        data = urllib.parse.urlencode({
            "secret": RECAPTCHA_SECRET_KEY,
            "response": token,
        }).encode()
        req = urllib.request.Request("https://google.com", data=data)
        with urllib.request.urlopen(req, timeout=5) as resp:
            result = json.loads(resp.read().decode())
            return bool(result.get("success"))
    except Exception:
        return False
       
