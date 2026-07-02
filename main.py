import os
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy import JSON, Boolean, Column, DateTime, Integer, String, create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import stripe

# --- CONFIGURATION & STRIPE LAYER ---
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:pass@localhost/optout_db")
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "sk_test_your_key_here")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "whsec_your_secret_here")
stripe.api_key = STRIPE_SECRET_KEY

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- DATABASE TABLE MODEL ---
class Customer(Base):
    __tablename__ = "customers"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
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

# Allow your frontend webpage to talk to this backend securely
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

# --- VALIDATION OBJECTS ---
class UserAuthForm(BaseModel):
    email: EmailStr
    password: str

class UserRegisterForm(BaseModel):
    email: EmailStr
    password: str
    first_name: str
    last_name: str

# --- AUTHENTICATION ENDPOINTS ---

@app.post("/api/v1/auth/register")
def register(form: UserRegisterForm, db=Depends(get_db)):
    if db.query(Customer).filter(Customer.email == form.email).first():
        raise HTTPException(status_code=400, detail="Account already exists.")
    new_user = Customer(
        email=form.email, password=form.password, first_name=form.first_name, last_name=form.last_name,
        progress_log={"spokeo": {"status": "pending"}, "whitepages": {"status": "pending"}},
        activity_timeline=[{"time": datetime.now().strftime("%I:%M %p"), "event": "Account Created", "details": "Secure profile entry established."}]
    )
    db.add(new_user)
    db.commit()
    return {"status": "success", "customer_id": new_user.id}

@app.post("/api/v1/auth/login")
def login(form: UserAuthForm, db=Depends(get_db)):
    user = db.query(Customer).filter(Customer.email == form.email, Customer.password == form.password).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    return {"status": "success", "customer_id": user.id}

# --- DASHBOARD & CONTROL ENDPOINTS ---

@app.get("/api/v1/dashboard")
def get_dashboard(customer_id: int, db=Depends(get_db)):
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
def trigger_scan(customer_id: int, db=Depends(get_db)):
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

@app.post("/api/v1/admin/grant-access")
def admin_grant_access(customer_id: int, tier_choice: str, admin_secret: str, db=Depends(get_db)):
    if admin_secret != os.getenv("ADMIN_SECRET_KEY", "super_secret_admin_pass"):
        raise HTTPException(status_code=403, detail="Invalid admin master key.")
    
    user = db.query(Customer).filter(Customer.id == customer_id).first()
    if not user: raise HTTPException(status_code=404, detail="User not found.")

    if tier_choice == "single":
        user.scan_credits += 1
    elif tier_choice == "annual":
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
