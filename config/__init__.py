"""
Configuration module for Onboarderr

This module provides centralized configuration management for the application.
It handles loading environment variables, validation, and provides access to
all application settings.
"""

import os
from pathlib import Path
from dotenv import load_dotenv, set_key
from typing import Dict, Any, Optional

def debug_log(message: str) -> None:
    """Log a debug message only if FLASK_DEBUG is enabled."""
    try:
        flask_debug = os.getenv("FLASK_DEBUG", "0") == "1"
        if flask_debug:
            print(f"[DEBUG] {message}")
    except Exception:
        pass

class Config:
    """Centralized configuration management for Onboarderr."""
    
    def __init__(self, env_file: str = ".env"):
        """
        Initialize configuration with environment file.
        
        Args:
            env_file: Path to the environment file to load
        """
        debug_log(f"Initializing configuration with env file: {env_file}")
        self.env_file = env_file
        self.env_path = Path(env_file)
        self._load_environment()
        debug_log("Configuration initialized successfully")
    
    def _load_environment(self):
        """Load environment variables from the specified file."""
        if self.env_path.exists():
            debug_log(f"Loading environment from {self.env_file}")
            load_dotenv(self.env_path, override=True)
            debug_log("Environment loaded successfully")
        else:
            print(f"[WARN] Environment file {self.env_file} not found")
    
    def get(self, key: str, default: Any = None) -> str:
        """
        Get a configuration value.
        
        Args:
            key: Configuration key
            default: Default value if key not found
            
        Returns:
            Configuration value as string
        """
        value = os.getenv(key, default)
        if key.endswith('_PASSWORD') or key.endswith('_TOKEN') or key.endswith('_HASH') or key.endswith('_SALT'):
            # Don't log sensitive values
            debug_log(f"Config get {key}: {'*' * len(str(value)) if value else 'None'}")
        else:
            debug_log(f"Config get {key}: {value}")
        return value
    
    def get_int(self, key: str, default: int = 0) -> int:
        """
        Get a configuration value as integer.
        
        Args:
            key: Configuration key
            default: Default value if key not found
            
        Returns:
            Configuration value as integer
        """
        try:
            return int(self.get(key, default))
        except (ValueError, TypeError):
            return default
    
    def get_bool(self, key: str, default: bool = False) -> bool:
        """
        Get a configuration value as boolean.
        
        Args:
            key: Configuration key
            default: Default value if key not found
            
        Returns:
            Configuration value as boolean
        """
        value = self.get(key, str(default)).lower()
        return value in ('true', 'yes', '1', 'on')
    
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
config = Config(".env")

def get_config() -> Config:
    """Get the global configuration instance."""
    return config 