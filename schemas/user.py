### user.py
from pydantic import BaseModel, EmailStr 

class User(BaseModel):
    name: str
    email: EmailStr
    password: str
    mobile: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordPayload(BaseModel):
    token: str
    new_password: str
    confirm_password: str

# ---------- Request Schema ----------
class EmailSchema(BaseModel):
    email_to: EmailStr
    subject: str
    body: str

