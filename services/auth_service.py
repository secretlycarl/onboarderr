"""
Auth Service

This module provides the AuthService class for handling authentication,
security, and auth-related business logic.
"""

import os
import time
import hashlib
import hmac
import base64
from typing import Dict, Optional, Any, List
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json

def debug_log(message: str) -> None:
    """Log a debug message only if FLASK_DEBUG is enabled."""
    try:
        flask_debug = os.getenv("FLASK_DEBUG", "0") == "1"
        if flask_debug:
            print(f"[DEBUG] {message}")
    except Exception:
        pass

debug_log("Importing crypto_utils in auth service")
from utils.crypto_utils import verify_password


class AuthService:
    """
    Service class for handling authentication and security logic.
    
    This class extracts all authentication and security-related business logic from app.py
    and provides a clean interface for authentication operations.
    """
    
    def __init__(self, config_instance=None):
        """Initialize the auth service."""
        self.config = config_instance
        self._secret_key = None
        self._fernet = None
        self._initialized = False
    
    def initialize(self) -> None:
        """Initialize the auth service."""
        debug_log(f"[DEBUG] Initializing auth service")
        self._secret_key = self.config.get("SECRET_KEY")
        if self._secret_key:
            try:
                # SECRET_KEY should already be a proper Fernet key (base64-encoded)
                # If it's not properly formatted, generate a new one
                if len(self._secret_key) != 44:  # Fernet keys are 44 characters
                    debug_log(f"[WARN] SECRET_KEY appears to be invalid, generating new Fernet key")
                    from utils.crypto_utils import update_secret_key_in_env
                    update_secret_key_in_env('.env')
                    # Reload the config to get the new key
                    self._secret_key = self.config.get("SECRET_KEY")
                
                self._fernet = Fernet(self._secret_key.encode())
                self._initialized = True
                debug_log(f"[INFO] Auth service initialized successfully")
            except Exception as e:
                debug_log(f"[ERROR] Failed to initialize Fernet cipher: {e}")
                # Try to generate a new key if the current one is invalid
                try:
                    debug_log(f"[INFO] Attempting to generate new Fernet key")
                    from utils.crypto_utils import update_secret_key_in_env
                    update_secret_key_in_env('.env')
                    # Reload the config to get the new key
                    self._secret_key = self.config.get("SECRET_KEY")
                    self._fernet = Fernet(self._secret_key.encode())
                    self._initialized = True
                    debug_log(f"[INFO] Auth service initialized successfully with new key")
                except Exception as e2:
                    debug_log(f"[ERROR] Failed to generate new Fernet key: {e2}")
        else:
            debug_log(f"[WARN] No secret key configured, auth service not fully initialized")
        
        # Debug: Show what password values are available
        debug_log(f"[DEBUG] Auth service password check:")
        debug_log(f"[DEBUG] - ADMIN_PASSWORD: {bool(self.config.get('ADMIN_PASSWORD'))}")
        debug_log(f"[DEBUG] - ADMIN_PASSWORD_HASH: {bool(self.config.get('ADMIN_PASSWORD_HASH'))}")
        debug_log(f"[DEBUG] - ADMIN_PASSWORD_SALT: {bool(self.config.get('ADMIN_PASSWORD_SALT'))}")
        debug_log(f"[DEBUG] - SITE_PASSWORD: {bool(self.config.get('SITE_PASSWORD'))}")
        debug_log(f"[DEBUG] - SITE_PASSWORD_HASH: {bool(self.config.get('SITE_PASSWORD_HASH'))}")
        debug_log(f"[DEBUG] - SITE_PASSWORD_SALT: {bool(self.config.get('SITE_PASSWORD_SALT'))}")
    
    def cleanup(self) -> None:
        """Clean up the auth service."""
        self._secret_key = None
        self._fernet = None
        self._initialized = False
        debug_log(f"[DEBUG] Auth service cleaned up")
    
    def is_initialized(self) -> bool:
        """Check if the auth service is properly initialized."""
        return self._initialized
    
    def generate_secret_key(self) -> str:
        """
        Generate a new secret key.
        
        Returns:
            Generated secret key
        """
        return Fernet.generate_key().decode()
    
    def authenticate_user(self, password: str) -> Dict[str, Any]:
        """
        Authenticate a user with the provided password.
        
        Args:
            password: The password to authenticate
            
        Returns:
            Dictionary with authentication result
        """
        try:
            debug_log(f"[DEBUG] Authenticating user with password length: {len(password)}")
            
            # Get hashed passwords and salts from config
            admin_password_hash = self.config.get("ADMIN_PASSWORD_HASH")
            admin_password_salt = self.config.get("ADMIN_PASSWORD_SALT")
            site_password_hash = self.config.get("SITE_PASSWORD_HASH")
            site_password_salt = self.config.get("SITE_PASSWORD_SALT")
            
            # For backward compatibility, check plain text passwords if hashes don't exist
            admin_password_plain = self.config.get("ADMIN_PASSWORD")
            site_password_plain = self.config.get("SITE_PASSWORD")
            
            debug_log(f"[DEBUG] Admin password hash exists: {bool(admin_password_hash)}")
            debug_log(f"[DEBUG] Admin password salt exists: {bool(admin_password_salt)}")
            debug_log(f"[DEBUG] Site password hash exists: {bool(site_password_hash)}")
            debug_log(f"[DEBUG] Site password salt exists: {bool(site_password_salt)}")
            debug_log(f"[DEBUG] Admin password plain exists: {bool(admin_password_plain)}")
            debug_log(f"[DEBUG] Site password plain exists: {bool(site_password_plain)}")
            
            # Check admin password
            admin_authenticated = False
            if admin_password_hash and admin_password_salt:
                debug_log(f"[DEBUG] Attempting admin authentication with hash/salt")
                debug_log(f"[DEBUG] Admin salt: {admin_password_salt[:10]}...")
                debug_log(f"[DEBUG] Admin hash: {admin_password_hash[:10]}...")
                admin_authenticated = verify_password(password, admin_password_salt, admin_password_hash)
                debug_log(f"[DEBUG] Admin hash authentication result: {admin_authenticated}")
            elif admin_password_plain:
                # Fallback to plain text for backward compatibility
                debug_log(f"[DEBUG] Attempting admin authentication with plain text")
                debug_log(f"[DEBUG] Admin plain password: {admin_password_plain[:3]}...")
                admin_authenticated = (password == admin_password_plain)
                debug_log(f"[DEBUG] Admin plain text authentication result: {admin_authenticated}")
            
            # Check site password
            site_authenticated = False
            if site_password_hash and site_password_salt:
                debug_log(f"[DEBUG] Attempting site authentication with hash/salt")
                debug_log(f"[DEBUG] Site salt: {site_password_salt[:10]}...")
                debug_log(f"[DEBUG] Site hash: {site_password_hash[:10]}...")
                site_authenticated = verify_password(password, site_password_salt, site_password_hash)
                debug_log(f"[DEBUG] Site hash authentication result: {site_authenticated}")
            elif site_password_plain:
                # Fallback to plain text for backward compatibility
                debug_log(f"[DEBUG] Attempting site authentication with plain text")
                debug_log(f"[DEBUG] Site plain password: {site_password_plain[:3]}...")
                site_authenticated = (password == site_password_plain)
                debug_log(f"[DEBUG] Site plain text authentication result: {site_authenticated}")
            
            # Determine authentication result
            if admin_authenticated:
                user_type = "admin"
                debug_log(f"[INFO] Successful authentication for {user_type} user")
                return {
                    "success": True,
                    "user_type": user_type,
                    "message": "Authentication successful"
                }
            elif site_authenticated:
                user_type = "user"
                debug_log(f"[INFO] Successful authentication for {user_type} user")
                return {
                    "success": True,
                    "user_type": user_type,
                    "message": "Authentication successful"
                }
            else:
                debug_log(f"[WARN] Failed authentication attempt - no matching passwords found")
                return {
                    "success": False,
                    "error": "Invalid password"
                }
                
        except Exception as e:
            debug_log(f"[ERROR] Authentication failed: {e}")
            return {
                "success": False,
                "error": "Authentication error"
            }
    
    def create_session(self, user_type: str) -> Dict[str, Any]:
        """
        Create a new session for the authenticated user.
        
        Args:
            user_type: The type of user (admin, user, etc.)
            
        Returns:
            Dictionary with session data
        """
        try:
            # Generate session ID
            session_id = base64.b64encode(os.urandom(32)).decode('utf-8')
            
            # Create session data
            session_data = {
                "authenticated": True,
                "admin_authenticated": (user_type == "admin"),
                "session_id": session_id,
                "user_type": user_type,
                "created_at": int(time.time()),
                "last_activity": int(time.time())
            }
            
            debug_log(f"[INFO] Created session for {user_type} user")
            
            return session_data
            
        except Exception as e:
            debug_log(f"[ERROR] Failed to create session: {e}")
            return {}
    
    def validate_session(self, session_data: Dict[str, Any]) -> bool:
        """
        Validate a session.
        
        Args:
            session_data: The session data to validate
            
        Returns:
            True if session is valid, False otherwise
        """
        try:
            if not session_data:
                return False
            
            # Check if session has required fields
            if not session_data.get("authenticated"):
                return False
            
            # Check if session is not too old (24 hours)
            current_time = int(time.time())
            session_age = current_time - session_data.get("created_at", 0)
            if session_age > 86400:  # 24 hours
                return False
            
            # Update last activity
            session_data["last_activity"] = current_time
            
            return True
            
        except Exception as e:
            debug_log(f"[ERROR] Session validation failed: {e}")
            return False
    
    def log_security_event(self, event_type: str, ip: str, details: Dict[str, Any]) -> None:
        """
        Log a security event.
        
        Args:
            event_type: The type of security event
            ip: The IP address involved
            details: Additional details about the event
        """
        if not self.config.get_bool("ENABLE_AUDIT_LOGGING", True):
            return
        
        log_entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event_type": event_type,
            "ip_address": ip,
            "details": details
        }
        
        try:
            # Load existing logs
            log_file = "security_log.json"
            logs = []
            
            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8') as f:
                    logs = json.load(f)
            
            # Add new log entry
            logs.append(log_entry)
            
            # Keep only last 90 days of logs
            retention_days = self.config.get_int("AUDIT_LOG_RETENTION_DAYS", 90)
            cutoff_time = time.time() - (retention_days * 86400)
            
            # Filter logs by timestamp
            filtered_logs = []
            for log in logs:
                try:
                    log_timestamp = time.mktime(time.strptime(log.get("timestamp", ""), "%Y-%m-%dT%H:%M:%SZ"))
                    if log_timestamp > cutoff_time:
                        filtered_logs.append(log)
                except:
                    # If timestamp parsing fails, keep the log
                    filtered_logs.append(log)
            
            # Save filtered logs
            with open(log_file, 'w', encoding='utf-8') as f:
                json.dump(filtered_logs, f, indent=2)
            
            debug_log(f"[DEBUG] Logged security event: {event_type}")
            
        except Exception as e:
            debug_log(f"[ERROR] Failed to log security event: {e}")
    
    def get_service_status(self) -> Dict[str, Any]:
        """
        Get the current status of the auth service.
        
        Returns:
            Dictionary containing service status information
        """
        return {
            'initialized': self.is_initialized(),
            'secret_key_configured': bool(self._secret_key),
            'fernet_available': bool(self._fernet),
            'audit_logging_enabled': self.config.get_bool("ENABLE_AUDIT_LOGGING", True)
        } 