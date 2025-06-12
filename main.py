from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Form, BackgroundTasks, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from passlib.context import CryptContext
import pymysql
import requests
import os
import re
from twilio.rest import Client
from dotenv import load_dotenv
from secrets import token_urlsafe
from typing import Dict
from pydantic import BaseModel, EmailStr
import uuid
from datetime import datetime
import logging
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from fastapi.templating import Jinja2Templates

# Load environment variables
load_dotenv()

# Setup logging
logger = logging.getLogger("trinetra")
logging.basicConfig(level=logging.INFO)


# FastAPI app instance
app = FastAPI()

# CORS middleware for Flutter frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Import your user models and DB utils (assumed present)
from schemas.user import User, LoginRequest, ForgotPasswordRequest
from models.db import get_db_connection, create_users_table
from utils.auth_utils import hash_password, verify_password

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

# ---------- Email Sending Function ----------
async def send_email(subject: str, email_to: str, body: str, is_html: bool = False):
    message = MessageSchema(
        subject=subject,
        recipients=[email_to],
        body=body,
        subtype="html" if is_html else "plain",
    )
    fm = FastMail(conf)
    await fm.send_message(message)

# ---------- Alert sending function ----------

def dms_to_decimal(dms: str) -> float:
    """Convert DMS (degrees°minutes'seconds"N/S/E/W) to decimal degrees."""
    match = re.match(r"(\d+)°(\d+)'([\d.]+)\"?([NSEW])", dms.strip())
    if not match:
        raise ValueError(f"Invalid DMS format: {dms}")
    deg, minutes, seconds, direction = match.groups()
    decimal = int(deg) + int(minutes) / 60 + float(seconds) / 3600
    return -decimal if direction in ['S', 'W'] else decimal



# Temporary in-memory token store (use Redis or DB for production)
reset_tokens: Dict[str, Dict[str, any]] = {}


# --------------- Pydantic Models -----------------

class ResetPasswordPayload(BaseModel):
    token: str
    new_password: str
    confirm_password: str

#================================= HTML Response  =========================================
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


# ======================================= Endpoints =======================================


# Register endpoint
@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(user: User):
    try:
        hashed_password = hash_password(user.password)
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO users (name, email, password, mobile) VALUES (%s, %s, %s, %s)",
                (user.name, user.email, hashed_password, user.mobile),
            )
        connection.commit()
        connection.close()
        return {"message": "User registered successfully"}
    except pymysql.MySQLError as e:
        if e.args[0] == 1062:  # Duplicate entry error code in MySQL
            error_msg = str(e)
            if "email" in error_msg.lower():
                raise HTTPException(status_code=400, detail="Email already exists")
            elif "mobile" in error_msg.lower():
                raise HTTPException(status_code=400, detail="Mobile number already exists")
            else:
                raise HTTPException(status_code=400, detail="Email or mobile already exists")
        else:
            logger.error(f"MySQL Error during registration: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

# Login endpoint
@app.post("/login")
def login(login_request: LoginRequest):
    connection = get_db_connection()
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE email=%s", (login_request.email,))
        user = cursor.fetchone()
    connection.close()

    if user is None or not verify_password(login_request.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    return {"message": "Login successful", "name": user["name"]}


# 🔑 Forgot Password
@app.post("/forgot-password/", status_code=status.HTTP_200_OK)
async def forgot_password(payload: ForgotPasswordRequest, background_tasks: BackgroundTasks):
    connection = get_db_connection()
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE email=%s", (payload.email,))
        user = cursor.fetchone()
    connection.close()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Generate and store token with expiry (e.g., 30 minutes)
    from datetime import datetime, timedelta

    token = token_urlsafe(32)
    expiry = datetime.utcnow() + timedelta(minutes=10)
    reset_tokens[payload.email] = {"token": token, "expires": expiry}

    reset_link = f"https://................................../reset-password?token={token}"

    subject = "Reset Your Password"
    body = f"""
    Hello,

    We received a request to reset the password for your  account.

    Please click the link below to reset your password (valid for 10 minutes):

    {reset_link}

    If you did not request this, you can safely ignore this email. Your account is secure.

    Thank you for using – Your Shield of Safety.

    Warm regards,
    The .... Team
    """

    background_tasks.add_task(send_email, subject=subject, email_to=payload.email, body=body, is_html=False)

    return {"message": f"Password reset link sent to {payload.email}."}


# 🔑 Verify token and reset password
@app.post("/reset-password/", status_code=status.HTTP_200_OK)
async def reset_password(payload: ResetPasswordPayload):
    from datetime import datetime

    # Validate token and expiry
    user_email = None
    for email, token_data in reset_tokens.items():
        if token_data["token"] == payload.token:
            if token_data["expires"] < datetime.utcnow():
                reset_tokens.pop(email, None)
                raise HTTPException(status_code=400, detail="Token expired")
            user_email = email
            break

    if not user_email:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    if payload.new_password != payload.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    # Hash and update password
    hashed_password = hash_password(payload.new_password)

    connection = get_db_connection()
    with connection.cursor() as cursor:
        cursor.execute("UPDATE users SET password=%s WHERE email=%s", (hashed_password, user_email))
        connection.commit()
    connection.close()

    # Remove token once used
    reset_tokens.pop(user_email, None)

    return {"message": "Password successfully reset. You can now login."}





#============================= TESTING ENDPOINTS =============================


# Get all users
@app.get("/users")
def get_all_users():
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute("SELECT id, name, email, mobile FROM users")
            users = cursor.fetchall()
        connection.close()
        return {"users": users}
    except pymysql.MySQLError as e:
        logger.error(f"DB error fetching users: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# ⚠️ Dangerous: Delete all users (for testing only)
# Uncomment and protect with authentication before enabling in production
@app.delete("/users/delete-all")
def delete_all_users():
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM users")
        connection.commit()
        connection.close()
        return {"message": "All users deleted successfully"}
    except pymysql.MySQLError as e:
        logger.error(f"DB error deleting users: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
