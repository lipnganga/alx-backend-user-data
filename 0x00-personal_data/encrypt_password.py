#!/usr/bin/env python3
"""
Password Encryption and Validation Module
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    Encrypts a password with bcrypt

    Args:
        password: the string password to encrypt

    Returns:
        Bytes string of the encrypted password
    """
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validates that the provided password matches the hashed password

    Args:
        hashed_password: bytes string of the hashed password
        password: the string password to validate

    Returns:
        True if the password matches, False otherwise
    """
    return bcrypt.checkpw(password.encode(), hashed_password)


def main():

    password = "myAmazingPlaintextPassword"
    print(f"Password: {password}")

    hashed_password = hash_password(password)
    print(f"Hashed Password: {hashed_password}")

    is_validated = is_valid(hashed_password, password)
    print(f"Is Valid: {is_validated}")

    is_validated = is_valid(hashed_password, "FakePassword")
    print(f"Is Valid: {is_validated}")

if __name__ == "__main__":
    main()
