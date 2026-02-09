import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base, Session

from passlib.context import CryptContext
import jwt

# -------------------------------------------------
# App
# -------------------------------------------------
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # şimdilik açık; sonra domain bazlı kısıtlarız
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------
# Config
# -------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
JWT_SECRET = os.getenv("JWT_SECRET", "change-this-secret")
JWT_ALG = "HS256"
JWT_EXPIRES_MIN = int(os.getenv("JWT_EXPIRES_MIN", "60"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

Base = declarative_base()

def _fix_database_url(url: str) -> str:
    # Render bazen "postgres://" verir; SQLAlchemy "postgresql://" ister
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql://", 1)
    return url

if not DATABASE_URL:
    # Local çalışırken hata vermesin diye; Render’da mutlaka env var olacak
    DATABASE_URL = "sqlite:///./dev.db"

DATABASE_URL = _fix_database_url(DATABASE_URL)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# -------------------------------------------------
# DB Model
# -------------------------------------------------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# -------------------------------------------------
# Schemas
# -------------------------------------------------
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class AuthResponse(BaseModel):
    token: str

# -------------------------------------------------
# Helpers
# -------------------------------------------------
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def hash_password(password: str) -> str:
    password = password[:72]  # bcrypt limiti
    return pwd_context.hash(password)

def create_token(email: str) -> str:
    payload = {
        "sub": email,
        "exp": datetime.utcnow() + timedelta(minutes=JWT_EXPIRES_MIN),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

# -------------------------------------------------
# Endpoints
# -------------------------------------------------
@app.get("/")
def read_root():
    return {"message": "UrunGetir backend ayakta 🚀"}

@app.get("/hello")
def hello():
    return {"message": "Merhaba Hakan! Backend çalışıyor 😎"}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/auth/register")
def register(body: RegisterRequest, db: Session = Depends(get_db)):
    email = body.email.lower().strip()
    if len(body.password) < 6:
        raise HTTPException(status_code=400, detail="Şifre en az 6 karakter olmalı.")

    existing = db.query(User).filter(User.email == email).first()
    if existing:
        raise HTTPException(status_code=409, detail="Bu e-posta zaten kayıtlı.")

    user = User(email=email, password_hash=hash_password(body.password))
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_token(user.email)
    return {"token": token}

@app.post("/auth/login", response_model=AuthResponse)
def login(body: LoginRequest, db: Session = Depends(get_db)):
    email = body.email.lower().strip()
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="E-posta veya şifre hatalı.")

    token = create_token(user.email)
    return {"token": token}
