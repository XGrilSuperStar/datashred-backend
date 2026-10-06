import os
import time
import requests
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
from fastapi.responses import FileResponse

# Playwright Web Automation Layer
from playwright.sync_api import sync_playwright
from playwright_stealth import stealth_sync

# --- CONFIGURATION & STRIPE LAYER ---
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    DATABASE_URL = "postgresql://user:pass@localhost/optout_db"
elif DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "sk_test_your_key_here")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "whsec_your_secret_here")
stripe.api_key = STRIPE_SECRET_KEY

# 2Captcha API Key Setup
CAPTCHA_SOLVER_API_KEY = os.getenv("2CAPTCHA_API_KEY", "YOUR_CAPTCHA_SOLVER_API_KEY")

# --- AUTH / SESSION CONFIGURATION ---
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ADMIN_SECRET_KEY = os.getenv("ADMIN_SECRET_KEY")
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")

if ENVIRONMENT == "production" and (not JWT_SECRET_KEY or not ADMIN_SECRET_KEY):
    raise RuntimeError(
        "JWT_SECRET_KEY and ADMIN_SECRET_KEY must be set in the environment before "
        "running in production. Generate strong random values."
    )

JWT_SECRET_KEY = JWT_SECRET_KEY or "dev-only-insecure-key-do-not-use-in-production"
ADMIN_SECRET_KEY = ADMIN_SECRET_KEY or "dev-only-insecure-admin-key"
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 24 * 7  

FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "http://localhost:3000")

engine = create_engine(DATABASE_URL, pool_recycle=1800, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- DATA REGISTRY MAPPING ---
DATA_BROKERS = [
    {"name": "BeenVerified", "url": "https://beenverified.com", "site_key": "6Ld2SF4UAAAAAInM547D1ft4vjU96b5E_abc123"},
    {"name": "Whitepages", "url": "https://whitepages.com", "site_key": "6Lc3VF4UAAAAAMuN458D1ft4vjU96b5E_xyz789"},
    {"name": "Radaris", "url": "https://radaris.com", "site_key": "6Ld4GF4UAAAAAGhK349D1ft4vjU96b5E_qwe456"},
    {"name": "Spokeo", "url": "https://spokeo.com", "site_key": "6Lf5HF4UAAAAAJuL231D1ft4vjU96b5E_rty012"},
    {"name": "Intelius", "url": "https://intelius.com", "site_key": "6L66JF4UAAAAANmP890D1ft4vjU96b5E_uio345"},
    {"name": "PeopleLooker", "url": "https://peoplelooker.com", "site_key": "6L77KF4UAAAAAOlQ567D1ft4vjU96b5E_pas678"},
    {"name": "PeopleFinders", "url": "https://peoplefinders.com", "site_key": "6L88LF4UAAAAAPkR123D1ft4vjU96b5E_dfg901"}
]

# --- DATABASE TABLE MODEL ---
class Customer(Base):
    __tablename__ = "customers"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    first_name = Column(String)
    last_name = Column(String)

    scan_credits = Column(Integer, default=0)
    is_annual_subscriber = Column(Boolean, default=False)
    annual_expires_at = Column(DateTime, nullable=True)

    progress_log = Column(JSON, default=dict)
    activity_timeline = Column(JSON, default=list)
    last_scan_date = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# --- BACKGROUND SCHEDULER ---
scheduler = BackgroundScheduler()
scheduler.start()

app = FastAPI(title="dataShred Central API")

# Global track manager to store live job states securely
jobs = {}

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization", "X-Admin-Key"],
)

_STATIC_DIR = os.path.dirname(os.path.abspath(__file__))

@app.get("/")
def serve_index():
    return FileResponse(os.path.join(_STATIC_DIR, "index.html"))

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

# --- CORE WEB WORKER AUTOMATION & CAPTCHA BYPASS LAYER ---

def run_opt_out_automation_worker(customer_id: int, user_profile: dict):
    """Asynchronous browser task coordinating clean field insertion and CAPTCHA clearing loops."""
    print(f"[*] Initializing background browser processing thread for user #{customer_id}")
    
    db = SessionLocal()
    try:
        p = sync_playwright().start()
        browser = p.chromium.launch(
            headless=True,
            args=["--disable-blink-features=AutomationControlled", "--no-sandbox", "--disable-infobars"]
        )
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        )
        page = context.new_page()
        stealth_sync(page)

        user = db.query(Customer).filter(Customer.id == customer_id).first()
        if not user:
            print("[-] Worker database reference dropped. Profile detached.")
            return

        for broker in DATA_BROKERS:
            b_name = broker["name"]
            print(f"[*] Automated Worker: Navigating to target portal context -> {b_name}")
            
            try:
                user.progress_log[b_name.lower()] = {"status": "processing", "notes": "Intercepting challenge wall..."}
                user.activity_timeline.append({
                    "time": datetime.now().strftime("%I:%M %p"),
                    "event": "Bypassing",
                    "details": f"Acquiring reCAPTCHA challenge parameter grids from {b_name}."
                })
                db.commit()

                page.goto(broker["url"], wait_until="networkidle", timeout=45000)
                
                page.fill("input[name='first_name']", user_profile["first_name"])
                time.sleep(0.5)
                page.fill("input[name='last_name']", user_profile["last_name"])
                time.sleep(0.4)
                page.fill("input[name='email']", user_profile["throwaway_email"])

                submit_payload = {
                    "key": CAPTCHA_SOLVER_API_KEY,
                    "method": "userrecaptcha",
                    "googlekey": broker["site_key"],
                    "pageurl": broker["url"],
                    "json": 1
                }
                
                res = requests.post("https://2captcha.com", data=submit_payload, timeout=15).json()
                if res.get("status") != 1:
                    user.progress_log[broker["name"].lower()] = {"status": "error", "notes": "Solver service refused connection tokens."}
                    db.commit()
                    continue

                task_id = res.get("request")
                validation_token = None
                
                for _ in range(36):  
                    time.sleep(5)
                    check = requests.get(f"https://2captcha.com{CAPTCHA_SOLVER_API_KEY}&action=get&id={task_id}&json=1", timeout=15).json()
                    if check.get("status") == 1:
                        validation_token = check.get("request")
                        break
                    if check.get("request") != "CAPCHA_NOT_READY":
                        break

                if validation_token:
