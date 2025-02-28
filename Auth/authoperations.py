from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Argon2 hasher
ph = PasswordHasher()

def hash_password(password: str, use_argon2: bool = True) -> str:
    """
    Securely hashes a password using Argon2 (recommended) or PBKDF2 (fallback).
    
    :param password: The plain-text password to hash.
    :param use_argon2: Whether to use Argon2 (default: True). If False, falls back to PBKDF2.
    :return: Hashed password string.
    """
    if use_argon2:
        return ph.hash(password)  # Argon2 (best security)
    else:
        return generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)  # PBKDF2 (fallback)

def verify_password(stored_hash: str, password: str, use_argon2: bool = True) -> bool:
    """
    Verifies a password against the stored hash.

    :param stored_hash: The hashed password stored in the database.
    :param password: The plain-text password entered by the user.
    :param use_argon2: Whether to verify using Argon2 (default: True). If False, uses PBKDF2.
    :return: True if the password matches, False otherwise.
    """
    try:
        if use_argon2:
            return ph.verify(stored_hash, password)  # Verify using Argon2
        else:
            return check_password_hash(stored_hash, password)  # Verify using PBKDF2
    except VerifyMismatchError:
        return False  # Password does not match
    except Exception as e:
        print(f"Error verifying password: {e}")  # Log errors (avoid exposing details to users)
        return False
