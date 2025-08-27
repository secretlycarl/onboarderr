"""
Crypto utilities for Onboarderr

This module provides cryptographic utilities for password hashing,
encryption, and security operations.
"""

import hashlib
import hmac
import base64
import os
from typing import Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_salt() -> str:
    """
    Generate a random salt for password hashing.
    
    Returns:
        Base64-encoded salt
    """
    return base64.b64encode(os.urandom(32)).decode()

def hash_password(password: str, salt: str) -> str:
    """
    Hash a password with a salt using PBKDF2.
    
    Args:
        password: Plain text password
        salt: Base64-encoded salt
        
    Returns:
        Base64-encoded hash
    """
    # Decode salt from base64
    salt_bytes = base64.b64decode(salt)
    
    # Create PBKDF2 key derivation function
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_bytes,
        iterations=100000,
    )
    
    # Generate key from password
    key = kdf.derive(password.encode())
    
    # Return base64-encoded hash
    return base64.b64encode(key).decode()

def verify_password(password: str, salt: str, stored_hash: str) -> bool:
    """
    Verify a password against a stored hash.
    
    Args:
        password: Plain text password to verify
        salt: Base64-encoded salt used for hashing
        stored_hash: Base64-encoded stored hash
        
    Returns:
        True if password matches, False otherwise
    """
    try:
        # Generate hash from provided password
        computed_hash = hash_password(password, salt)
        
        # Compare with stored hash
        return hmac.compare_digest(computed_hash, stored_hash)
    except Exception:
        return False

def generate_fernet_key() -> str:
    """
    Generate a proper Fernet key.
    
    Returns:
        Base64-encoded Fernet key
    """
    return Fernet.generate_key().decode()

def update_secret_key_in_env(env_file: str = ".env") -> bool:
    """
    Update the SECRET_KEY in the environment file with a proper Fernet key.
    
    Args:
        env_file: Path to the environment file
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Generate new Fernet key
        new_key = generate_fernet_key()
        
        # Read the current file
        with open(env_file, 'r') as f:
            lines = f.readlines()
        
        # Update or add SECRET_KEY
        key_updated = False
        for i, line in enumerate(lines):
            if line.startswith('SECRET_KEY='):
                lines[i] = f'SECRET_KEY={new_key}\n'
                key_updated = True
                break
        
        # If SECRET_KEY wasn't found, add it
        if not key_updated:
            lines.append(f'SECRET_KEY={new_key}\n')
        
        # Write back to file
        with open(env_file, 'w') as f:
            f.writelines(lines)
        
        # Update current environment
        os.environ['SECRET_KEY'] = new_key
        
        print(f"[INFO] Updated SECRET_KEY in {env_file}")
        return True
        
    except Exception as e:
        print(f"[ERROR] Failed to update SECRET_KEY: {e}")
        return False 