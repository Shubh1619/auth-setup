from passlib.context import CryptContext
from passlib.exc import UnknownHashError

# Initialize CryptContext for password hashing and verification
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt algorithm.
    :param password: Plain text password
    :return: Hashed password
    """
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify if a plain password matches the hashed password.
    Gracefully handles invalid hash formats.
    :param plain_password: Plain text password
    :param hashed_password: Hashed password
    :return: True if passwords match, False otherwise
    """
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except UnknownHashError:
        # The hash is not a valid bcrypt hash
        return False
