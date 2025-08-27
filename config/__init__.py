"""
Configuration module for Onboarderr

This module provides centralized configuration management for the application.
It handles loading environment variables, validation, and provides access to
all application settings.
"""

import os
import re
import requests
import secrets
import shutil
from pathlib import Path
from dotenv import load_dotenv, set_key
from typing import Dict, Any, Optional, Tuple
import threading

def debug_log(message: str) -> None:
    """Log a debug message only if FLASK_DEBUG is enabled."""
    try:
        flask_debug = os.getenv("FLASK_DEBUG", "0") == "1"
        if flask_debug:
            print(f"[DEBUG] {message}")
    except Exception:
        pass

def update_env_with_missing_variables():
    """Compare .env and empty.env, add missing variables to .env while preserving existing values and comments"""
    if not os.path.exists('empty.env'):
        print('[WARN] empty.env not found, skipping .env update')
        return
    
    if not os.path.exists('.env'):
        print('[WARN] .env not found, copying empty.env to .env')
        shutil.copyfile('empty.env', '.env')
        return
    
    try:
        # Read empty.env to get all expected variables
        with open('empty.env', 'r', encoding='utf-8') as f:
            empty_env_content = f.read()
        
        # Parse empty.env to get variable names and default values
        empty_vars = {}
        for line in empty_env_content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                empty_vars[key.strip()] = value.strip()
        
        # Read current .env
        with open('.env', 'r', encoding='utf-8') as f:
            current_env_content = f.read()
        
        # Parse current .env to get existing variables
        current_vars = {}
        current_lines = current_env_content.split('\n')
        for line in current_lines:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                current_vars[key.strip()] = value.strip()
        
        # Find missing variables
        missing_vars = {}
        for key, default_value in empty_vars.items():
            if key not in current_vars:
                missing_vars[key] = default_value
        
        if missing_vars:
            print(f'\n[INFO] Found {len(missing_vars)} missing variables in .env, adding them...')
            
            # Add missing variables to the end of .env file
            with open('.env', 'a', encoding='utf-8') as f:
                f.write('\n')
                for key, value in missing_vars.items():
                    f.write(f'{key}={value}\n')
                    print(f'[INFO] Added: {key}={value}')
            
            print('[INFO] .env file updated successfully\n')
        else:
            print('[INFO] .env file is up to date with empty.env\n')
            
    except Exception as e:
        print(f'[ERROR] Failed to update .env file: {e}')

def ensure_secret_key():
    """Ensure SECRET_KEY is set in the environment file"""
    env_path = '.env'
    with open(env_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    found = False
    for i, line in enumerate(lines):
        if line.strip().startswith('SECRET_KEY='):
            found = True
            if line.strip() == 'SECRET_KEY=' or line.strip() == 'SECRET_KEY=""':
                # Generate and set a new key
                new_key = secrets.token_urlsafe(48)
                lines[i] = f'SECRET_KEY={new_key}\n'
            break
    if not found:
        new_key = secrets.token_urlsafe(48)
        lines.append(f'SECRET_KEY={new_key}\n')
    with open(env_path, 'w', encoding='utf-8') as f:
        f.writelines(lines)

class Config:
    """Centralized configuration management with validation"""
    
    def __init__(self, env_file: str = ".env"):
        """
        Initialize configuration with environment file.
        
        Args:
            env_file: Path to the environment file to load
        """
        self.env_file = env_file
        self.env_path = Path(env_file)
        # Remove validation from constructor to avoid delays
        # Validation will be done lazily only when needed
        debug_log("Configuration initialized successfully")
    
    def _validate_config(self):
        """Validate critical configuration values - called only when needed"""
        self._validate_timeouts()
        self._validate_rate_limits()
        self._validate_cache_settings()
        # Remove API validation from here - it's too expensive for every page load
    
    def _validate_api_credentials(self):
        """Validate API credentials if they are configured - called only when needed"""
        # Import here to avoid circular imports
        from utils.logging_utils import log_error
        
        # Only validate if credentials are provided
        plex_token = self.get("PLEX_TOKEN")
        plex_url = self.get("PLEX_URL")
        
        if plex_token and plex_url:
            is_valid, message = self.validate_api_connection("PLEX", plex_url, plex_token)
            if not is_valid:
                log_error("config_validation", f"Plex API validation failed: {message}", 
                         {"api_type": "PLEX", "url": plex_url})
        
        abs_token = self.get("AUDIOBOOKSHELF_TOKEN")
        abs_url = self.get("AUDIOBOOKSHELF_URL")
        
        if abs_token and abs_url:
            is_valid, message = self.validate_api_connection("ABS", abs_url, abs_token)
            if not is_valid:
                log_error("config_validation", f"Audiobookshelf API validation failed: {message}", 
                         {"api_type": "ABS", "url": abs_url})
    
    def _validate_timeouts(self):
        """Validate timeout values are within reasonable bounds"""
        # Import here to avoid circular imports
        from utils.logging_utils import log_error
        
        timeouts = {
            'PLEX_API_TIMEOUT': (5, 60),
            'ABS_API_TIMEOUT': (5, 60),
            'DISCORD_API_TIMEOUT': (3, 30),
            'GENERAL_API_TIMEOUT': (3, 30)
        }
        
        for key, (min_val, max_val) in timeouts.items():
            value = self.get_int(key, 10)
            if not min_val <= value <= max_val:
                log_error("config_validation", f"Invalid timeout value for {key}: {value}. Using default.", 
                         {"value": value, "min": min_val, "max": max_val})
    
    def _validate_rate_limits(self):
        """Validate rate limiting values"""
        # Import here to avoid circular imports
        from utils.logging_utils import log_error
        
        rate_limits = {
            'RATE_LIMIT_IP_SUSPICIOUS_THRESHOLD': (5, 100),
            'RATE_LIMIT_IP_BAN_THRESHOLD': (10, 200),
            'RATE_LIMIT_MAX_LOGIN_ATTEMPTS': (1, 20),
            'RATE_LIMIT_MAX_FORM_SUBMISSIONS': (1, 10)
        }
        
        for key, (min_val, max_val) in rate_limits.items():
            value = self.get_int(key, 5)
            if not min_val <= value <= max_val:
                log_error("config_validation", f"Invalid rate limit value for {key}: {value}. Using default.", 
                         {"value": value, "min": min_val, "max": max_val})
    
    def _validate_cache_settings(self):
        """Validate cache TTL values"""
        # Import here to avoid circular imports
        from utils.logging_utils import log_error
        
        cache_settings = {
            'LIBRARY_CACHE_TTL': (3600, 604800),  # 1 hour to 1 week
            'POSTER_REFRESH_INTERVAL': (3600, 604800)
        }
        
        for key, (min_val, max_val) in cache_settings.items():
            value = self.get_int(key, 86400)
            if not min_val <= value <= max_val:
                log_error("config_validation", f"Invalid cache value for {key}: {value}. Using default.", 
                         {"value": value, "min": min_val, "max": max_val})
    
    def get(self, key: str, default: Any = None) -> str:
        """Get environment variable with validation"""
        value = os.getenv(key, default)
        # Only log sensitive values in debug mode, and only once per key
        if key.endswith('_PASSWORD') or key.endswith('_TOKEN') or key.endswith('_HASH') or key.endswith('_SALT'):
            # Don't log sensitive values at all
            pass
        else:
            # Only log non-sensitive values in debug mode, and only for important keys
            if key in ['PLEX_URL', 'AUDIOBOOKSHELF_URL', 'SERVER_NAME', 'ACCENT_COLOR']:
                debug_log(f"Config get {key}: {value}")
        return value
    
    def get_int(self, key: str, default: int = 0) -> int:
        """Get integer environment variable with validation"""
        # Import here to avoid circular imports
        from utils.logging_utils import log_error
        
        try:
            value = os.getenv(key, str(default))
            return int(value)
        except (ValueError, TypeError):
            log_error("config_validation", f"Invalid integer value for {key}: {os.getenv(key)}", 
                     {"key": key, "value": os.getenv(key)})
            return default
    
    def get_bool(self, key: str, default: bool = False) -> bool:
        """Get boolean environment variable"""
        value = os.getenv(key, str(default)).lower()
        return value in ('true', '1', 'yes', 'on')
    
    def get_poster_refresh_mode(self) -> bool:
        """Get poster refresh mode - incremental or full"""
        mode = os.getenv("POSTER_REFRESH_MODE", "incremental").lower()
        return mode in ('incremental', 'true', '1', 'yes', 'on')
    
    def validate_url(self, url: str, name: str = "URL") -> bool:
        """Validate URL format"""
        if not url:
            return False
        try:
            if not url.startswith(('http://', 'https://')):
                url = f"http://{url}"
            # Basic URL validation
            return '://' in url and '.' in url.split('://')[1]
        except Exception:
            return False
    
    def validate_token(self, token: str, name: str = "Token") -> bool:
        """Validate token format with API-specific checks"""
        if not token:
            return False
        
        token = token.strip()
        
        # Basic length validation
        if len(token) < 10 or len(token) > 1000:
            return False
        
        # API-specific format validation
        if "PLEX" in name.upper():
            # Plex tokens are typically alphanumeric, 20-40 characters
            if not re.match(r'^[a-zA-Z0-9]{20,40}$', token):
                return False
        elif "ABS" in name.upper() or "AUDIOBOOKSHELF" in name.upper():
            # Audiobookshelf tokens are typically JWT-like or alphanumeric
            if not re.match(r'^[a-zA-Z0-9\-_\.]{20,}$', token):
                return False
        elif "DISCORD" in name.upper():
            # Discord webhook URLs should contain discord.com
            if "discord.com" not in token.lower():
                return False
        
        return True
    
    def validate_api_connection(self, api_type: str, url: str, token: str) -> Tuple[bool, str]:
        """Validate API connection by making a test call"""
        if not self.validate_token(token, api_type):
            return False, "Invalid token format"
        
        try:
            headers = {}
            if api_type.upper() == "PLEX":
                headers = {"X-Plex-Token": token}
                test_url = f"{url}/library/sections"
            elif api_type.upper() in ["ABS", "AUDIOBOOKSHELF"]:
                headers = {"Authorization": f"Bearer {token}"}
                test_url = f"{url}/api/libraries"
            else:
                return False, "Unsupported API type"
            
            timeout = self.get_int(f"{api_type.upper()}_API_TIMEOUT", 10)
            response = requests.get(test_url, headers=headers, timeout=timeout)
            
            if response.status_code == 200:
                return True, "Connection successful"
            elif response.status_code == 401:
                return False, "Authentication failed - invalid token"
            elif response.status_code == 403:
                return False, "Access denied - insufficient permissions"
            else:
                return False, f"API returned status code {response.status_code}"
                
        except requests.exceptions.Timeout:
            return False, "Connection timed out"
        except requests.exceptions.ConnectionError:
            return False, "Failed to connect to API server"
        except Exception as e:
            return False, f"Connection error: {str(e)}"
    
    def validate_email(self, email: str) -> bool:
        """Basic email validation"""
        if not email:
            return False
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    def set(self, key: str, value: str) -> bool:
        """
        Set a configuration value in the environment file.
        
        Args:
            key: Configuration key
            value: Value to set
            
        Returns:
            True if successful, False otherwise
        """
        try:
            set_key(self.env_path, key, value)
            # Update current environment
            os.environ[key] = value
            return True
        except Exception as e:
            print(f"[ERROR] Failed to set config {key}: {e}")
            return False
    
    def is_setup_complete(self) -> bool:
        """
        Check if initial setup is complete.
        
        Returns:
            True if setup is complete, False otherwise
        """
        setup_complete = self.get_bool("SETUP_COMPLETE", False)
        # Only log setup complete checks in verbose debug mode
        if os.getenv("VERBOSE_DEBUG", "0") == "1":
            debug_log(f"Setup complete check: {setup_complete}")
        return setup_complete
    
    def get_service_urls(self) -> Dict[str, str]:
        """
        Get all service URLs from configuration.
        
        Returns:
            Dictionary of service names to URLs
        """
        service_keys = [
            'PLEX', 'LIDARR', 'RADARR', 'SONARR', 'TAUTULLI', 'QBITTORRENT', 'IMMICH',
            'PROWLARR', 'BAZARR', 'PULSARR', 'AUDIOBOOKSHELF', 'OVERSEERR', 'JELLYSEERR'
        ]
        return {key: self.get(key, "") for key in service_keys}
    
    def _load_environment(self):
        """Load environment variables from file."""
        debug_log(f"Loading environment from {self.env_file}")
        load_dotenv(self.env_file, override=True)
        debug_log("Environment loaded successfully")
    
    def reload(self):
        """Reload environment variables from file."""
        debug_log(f"Reloading configuration from {self.env_file}")
        self._load_environment()
        debug_log("Configuration reloaded successfully")
    
    def get_server_name(self) -> str:
        """
        Get the server name from configuration.
        
        Returns:
            Server name or default value
        """
        return self.get("SERVER_NAME", "Onboarderr")
    
    def get_accent_color(self) -> str:
        """
        Get the accent color from configuration.
        
        Returns:
            Accent color or default value
        """
        return self.get("ACCENT_COLOR", "#f4b700")

# Global configuration instance
debug_log("Creating global configuration instance")
_config_instance = None
_config_lock = threading.Lock()
_environment_loaded = False
_env_lock = threading.Lock()

def _load_environment_once():
    """Load environment variables only once at startup"""
    global _environment_loaded
    if not _environment_loaded:
        with _env_lock:
            if not _environment_loaded:
                debug_log("Loading environment from .env")
                load_dotenv(".env", override=True)
                debug_log("Environment loaded successfully")
                _environment_loaded = True

def get_config() -> Config:
    """Get the global configuration instance."""
    global _config_instance
    if _config_instance is None:
        with _config_lock:
            if _config_instance is None:  # Double-checked locking
                debug_log("Initializing new Config instance")
                _load_environment_once()  # Load environment once before creating config
                _config_instance = Config(".env")
    return _config_instance

# Initialize global variables
debug_mode = get_config().get_bool("FLASK_DEBUG", False)
js_debug_mode = get_config().get_bool("JS_DEBUG", False)

def reload_config():
    """Reload configuration from environment variables"""
    global _config_instance, debug_mode, js_debug_mode, _environment_loaded
    debug_log("Reloading configuration")
    _environment_loaded = False  # Reset environment loading flag
    _load_environment_once()  # Reload environment
    _config_instance = Config(".env")
    debug_mode = _config_instance.get_bool("FLASK_DEBUG", False)
    js_debug_mode = _config_instance.get_bool("JS_DEBUG", False)
    debug_log("Configuration reloaded successfully")

def initialize_environment():
    """Initialize environment variables and global configuration"""
    global MOVIES_SECTION_ID, SHOWS_SECTION_ID, AUDIOBOOKS_SECTION_ID, debug_mode
    
    # Update .env with missing variables on startup
    update_env_with_missing_variables()
    
    # Ensure SECRET_KEY is set
    ensure_secret_key()
    
    # Initialize section IDs from environment
    MOVIES_SECTION_ID = os.getenv("MOVIES_ID")
    SHOWS_SECTION_ID = os.getenv("SHOWS_ID")
    AUDIOBOOKS_SECTION_ID = os.getenv("AUDIOBOOKS_ID")
    
    # Update debug_mode from environment to ensure it's current
    # This ensures debug_mode is always up to date with the latest .env value
    debug_mode = os.getenv("FLASK_DEBUG", "0") == "1"
    
    debug_log(f"Environment initialized - Movies ID: {MOVIES_SECTION_ID}, Shows ID: {SHOWS_SECTION_ID}, Audiobooks ID: {AUDIOBOOKS_SECTION_ID}")
    debug_log(f"Debug mode: {debug_mode}")
    
    return debug_mode

# Initialize environment after config is loaded
initialize_environment() 