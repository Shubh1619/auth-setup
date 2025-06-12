from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Form, BackgroundTasks, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from passlib.context import CryptContext
from secrets import token_urlsafe
from dotenv import load_dotenv
from typing import Dict
from pydantic import BaseModel, EmailStr
import re
import os
import logging
from datetime import datetime, timedelta
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from fastapi.templating import Jinja2Templates
import psycopg2
from psycopg2.extras import RealDictCursor, DictCursor
from psycopg2 import errors as pg_errors

# Import your user schemas and auth logic
from schemas.user import User, LoginRequest, ForgotPasswordRequest
from models.db import get_db_connection, create_users_table
from utils.auth_utils import hash_password, verify_password
from models.db import DATABASE_URL

# Load environment variables
load_dotenv()

# Setup logging
logger = logging.getLogger("Vavastapak")
logging.basicConfig(level=logging.INFO)

# FastAPI app instance
app = FastAPI()

# CORS for Flutter
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Ensure users table exists
create_users_table()

# ---------- Mail Configuration ----------
conf = ConnectionConfig(
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
    MAIL_FROM=os.getenv("MAIL_FROM"),
    MAIL_PORT=int(os.getenv("MAIL_PORT")),
    MAIL_SERVER=os.getenv("MAIL_SERVER"),
    MAIL_FROM_NAME=os.getenv("MAIL_FROM_NAME"),
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=False,
)

# ---------- Email Function ----------
async def send_email(subject: str, email_to: str, body: str, is_html: bool = False):
    message = MessageSchema(
        subject=subject,
        recipients=[email_to],
        body=body,
        subtype="html" if is_html else "plain",
    )
    fm = FastMail(conf)
    await fm.send_message(message)

# ---------- Reset Token Storage ----------
reset_tokens: Dict[str, Dict[str, any]] = {}

# ---------- Password Reset Form Rendering ----------
templates = Jinja2Templates(directory="templates")

@app.get("/reset-password", response_class=HTMLResponse)
async def show_reset_form(request: Request, token: str):
    for email, token_data in reset_tokens.items():
        if token_data["token"] == token:
            if token_data["expires"] < datetime.utcnow():
                reset_tokens.pop(email, None)
                return templates.TemplateResponse("token_expired.html", {"request": request})
            return templates.TemplateResponse("reset.html", {"request": request, "token": token})
    return templates.TemplateResponse("token_expired.html", {"request": request})

# ---------- Reset Password Model ----------
class ResetPasswordPayload(BaseModel):
    token: str
    new_password: str
    confirm_password: str



# ================== USER REGISTRATION ENDPOINT ===================

@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(user: User):
    hashed_password = hash_password(user.password)
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO users (name, email, password, mobile, role) VALUES (%s, %s, %s, %s, %s)",
                    (user.name, user.email, hashed_password, user.mobile, user.role)
                )
                conn.commit()
        return {"message": "User registered successfully"}
    except pg_errors.UniqueViolation as e:
        error_msg = str(e)
        if "email" in error_msg.lower():
            raise HTTPException(status_code=400, detail="Email already exists")
        elif "mobile" in error_msg.lower():
            raise HTTPException(status_code=400, detail="Mobile number already exists")
        else:
            raise HTTPException(status_code=400, detail="User already exists")
    except Exception as e:
        logger.error(f"PostgreSQL Error during registration: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# ================== LOGIN ENDPOINT ===================

@app.post("/login")
def login(login_request: LoginRequest):
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT * FROM users WHERE email=%s", (login_request.email,))
            user = cursor.fetchone()

    if user is None or not verify_password(login_request.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    return {"message": "Login successful", "name": user["name"], "role": user["role"]}

# ================== FORGOT PASSWORD ENDPOINT ===================

@app.post("/forgot-password/")
async def forgot_password(payload: ForgotPasswordRequest, background_tasks: BackgroundTasks):
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE email=%s", (payload.email,))
            user = cursor.fetchone()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    token = token_urlsafe(32)
    expiry = datetime.utcnow() + timedelta(minutes=10)
    reset_tokens[payload.email] = {"token": token, "expires": expiry}

    reset_link = f"https://your-domain.com/reset-password?token={token}"

    subject = "Reset Your Password"
    body = f"""
    Hello,

    Click the link below to reset your password (valid for 10 minutes):

    {reset_link}

    If you did not request this, ignore this email.

    — Vavastapak Team
    """

    background_tasks.add_task(send_email, subject=subject, email_to=payload.email, body=body, is_html=False)

    return {"message": f"Password reset link sent to {payload.email}."}


# ================== RESET PASSWORD ENDPOINT ===================

@app.post("/reset-password/", status_code=status.HTTP_200_OK)
async def reset_password(payload: ResetPasswordPayload):
    user_email = None

    # Find matching email from reset token
    for email, token_data in reset_tokens.items():
        if token_data["token"] == payload.token:
            if token_data["expires"] < datetime.utcnow():
                reset_tokens.pop(email, None)
                raise HTTPException(status_code=400, detail="Token has expired")
            user_email = email
            break

    # Invalid token
    if not user_email:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    # Password match check
    if payload.new_password != payload.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    try:
        hashed_password = hash_password(payload.new_password)

        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("UPDATE users SET password=%s WHERE email=%s", (hashed_password, user_email))
                conn.commit()

        # Clean up the token
        reset_tokens.pop(user_email, None)

        return {"message": "✅ Password successfully reset. You can now log in."}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error updating password: {str(e)}")

# ================== TESTING ENDPOINTS ===================

@app.get("/users")
def get_all_users():
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("SELECT id, name, email, mobile, role FROM users")
                users = cursor.fetchall()
        return {"users": users}
    except Exception as e:
        logger.error(f"DB error fetching users: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")



@app.delete("/users/delete-all")
def delete_all_users():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("DELETE FROM users")
                conn.commit()
        return {"message": "All users deleted successfully"}
    except Exception as e:
        logger.error(f"DB error deleting users: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# Prints the database URL for debugging or logging purposes
print("DB URL used:", DATABASE_URL)