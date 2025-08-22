"""
Environment utilities for Onboarderr

This module provides utilities for safely managing environment variables,
including API key hashing and secure storage.
"""

import os
import hashlib
import secrets
from pathlib import Path
from typing import Tuple, Optional

def safe_set_key(env_path: str, key: str, value: str) -> bool:
    """
    Safely set a key-value pair in the environment file.
    
    Args:
        env_path: Path to the environment file
        key: Environment variable key
        value: Environment variable value
        
    Returns:
        True if successful, False otherwise
    """
    try:
        debug_log(f"Setting environment variable: {key}={value[:10] if len(value) > 10 else value}...")
        
        # Read the current file
        lines = []
        if os.path.exists(env_path):
            with open(env_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        
        # Find and update the key, or add it if not found
        key_found = False
        for i, line in enumerate(lines):
            if line.strip().startswith(f'{key}='):
                lines[i] = f'{key}={value}\n'
                key_found = True
                break
        
        if not key_found:
            lines.append(f'{key}={value}\n')
        
        # Write back to file
        with open(env_path, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        
        # Update current environment
        os.environ[key] = value
        debug_log(f"Successfully set environment variable: {key}")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to set environment variable {key}: {e}")
        return False

def hash_api_key(api_key: str) -> str:
    """
    Hash an API key for secure storage.
    
    Args:
        api_key: The API key to hash
        
    Returns:
        Hashed API key
    """
    return hashlib.sha256(api_key.encode()).hexdigest()

def save_api_key_with_hash(env_path: str, key: str, api_key: str) -> bool:
    """
    Save an API key with its hash for verification.
    
    Args:
        env_path: Path to the environment file
        key: Base key name (e.g., "PLEX_TOKEN")
        api_key: The API key to save
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Save the API key
        if not safe_set_key(env_path, key, api_key):
            return False
        
        # Save the hash
        hash_key = f"{key}_HASH"
        hash_value = hash_api_key(api_key)
        if not safe_set_key(env_path, hash_key, hash_value):
            return False
        
        return True
    except Exception as e:
        print(f"[ERROR] Failed to save API key {key}: {e}")
        return False

def verify_api_key(key: str, api_key: str) -> bool:
    """
    Verify an API key against its stored hash.
    
    Args:
        key: Base key name (e.g., "PLEX_TOKEN")
        api_key: The API key to verify
        
    Returns:
        True if the API key matches the stored hash, False otherwise
    """
    try:
        hash_key = f"{key}_HASH"
        stored_hash = os.getenv(hash_key)
        if not stored_hash:
            return False
        
        current_hash = hash_api_key(api_key)
        return current_hash == stored_hash
    except Exception as e:
        print(f"[ERROR] Failed to verify API key {key}: {e}")
        return False

def generate_salt() -> str:
    """
    Generate a random salt for password hashing.
    
    Returns:
        Base64 encoded salt
    """
    return secrets.token_urlsafe(32)

def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """
    Hash a password with a salt.
    
    Args:
        password: The password to hash
        salt: Optional salt (will generate if not provided)
        
    Returns:
        Tuple of (salt, hashed_password)
    """
    if salt is None:
        salt = generate_salt()
    
    # Combine password and salt
    combined = password + salt
    
    # Hash the combined string
    hashed = hashlib.sha256(combined.encode()).hexdigest()
    
    return salt, hashed

def verify_password(password: str, stored_hash: str, stored_salt: str) -> bool:
    """
    Verify a password against stored hash and salt.
    
    Args:
        password: The password to verify
        stored_hash: The stored password hash
        stored_salt: The stored password salt
        
    Returns:
        True if password matches, False otherwise
    """
    try:
        _, computed_hash = hash_password(password, stored_salt)
        return computed_hash == stored_hash
    except Exception as e:
        print(f"[ERROR] Failed to verify password: {e}")
        return False

def save_password_with_hash(env_path: str, key: str, password: str) -> bool:
    """
    Save a password with its hash and salt.
    
    Args:
        env_path: Path to the environment file
        key: Base key name (e.g., "SITE_PASSWORD")
        password: The password to save
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Generate hash and salt
        salt, hashed = hash_password(password)
        
        # Save the password (without quotes)
        if not safe_set_key(env_path, key, password):
            return False
        
        # Save the hash (without quotes)
        hash_key = f"{key}_HASH"
        if not safe_set_key(env_path, hash_key, hashed):
            return False
        
        # Save the salt (without quotes)
        salt_key = f"{key}_SALT"
        if not safe_set_key(env_path, salt_key, salt):
            return False
        
        return True
    except Exception as e:
        print(f"[ERROR] Failed to save password {key}: {e}")
        return False

def get_env_file_path() -> str:
    """
    Get the path to the environment file.
    
    Returns:
        Path to the environment file
    """
    return os.path.join(os.getcwd(), ".env")

def ensure_env_file_exists() -> bool:
    """
    Ensure the environment file exists.
    
    Returns:
        True if file exists or was created, False otherwise
    """
    env_path = get_env_file_path()
    if not os.path.exists(env_path):
        try:
            # Create empty .env file
            Path(env_path).touch()
            print(f"[INFO] Created environment file: {env_path}")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to create environment file: {e}")
            return False
    return True

def reload_environment() -> bool:
    """
    Reload environment variables from file.
    
    Returns:
        True if successful, False otherwise
    """
    try:
        debug_log("Reloading environment variables")
        from dotenv import load_dotenv
        load_dotenv(override=True)
        debug_log("Environment variables reloaded successfully")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to reload environment: {e}")
        return False

def debug_log(message: str) -> None:
    """
    Log a debug message only if FLASK_DEBUG is enabled.
    
    Args:
        message: The debug message to log
    """
    try:
        flask_debug = os.getenv("FLASK_DEBUG", "0") == "1"
        if flask_debug:
            print(f"[DEBUG] {message}")
    except Exception:
        # If there's any error checking debug mode, don't log
        pass 