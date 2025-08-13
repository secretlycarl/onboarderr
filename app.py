# app.py

# Flask and Flask extensions
from flask import Flask, render_template, render_template_string, request, redirect, url_for, session, jsonify, g
from flask_wtf.csrf import generate_csrf
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Standard library imports
import json
import os
import time
import secrets
import tempfile
import sys
import threading
import queue
import hashlib
import base64
import hmac
import re
import string
import random
import platform
import subprocess
import signal
import shutil
import webbrowser
from datetime import datetime, timezone
from collections import defaultdict, OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import io

# Third-party imports
import requests
import xml.etree.ElementTree as ET
from dotenv import load_dotenv, set_key
import psutil
from PIL import Image
from plexapi.server import PlexServer

import ipaddress
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Before load_dotenv()
if not os.path.exists('.env') and os.path.exists('empty.env'):
    print('\n[WARN] .env file not found. Copying empty.env to .env for you.\n')
    shutil.copyfile('empty.env', '.env')

# ============================================================================
# ERROR LOGGING SYSTEM
# ============================================================================

# Global error logging state
error_log = []
error_lock = Lock()

def log_error(error_type, message, details=None, exception=None):
    """Centralized error logging with recovery information"""
    error_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "type": error_type,
        "message": message,
        "details": details or {},
        "exception": str(exception) if exception else None,
        "traceback": None
    }
    
    if exception:
        import traceback
        error_entry["traceback"] = traceback.format_exc()
    
    with error_lock:
        error_log.append(error_entry)
        # Keep only last 100 errors to prevent memory leaks
        if len(error_log) > 100:
            error_log[:] = error_log[-100:]
        
        # Clean up old error entries (older than 24 hours)
        current_time = time.time()
        cutoff_time = current_time - 86400
        error_log[:] = [
            entry for entry in error_log 
            if 'timestamp' in entry and 
            datetime.fromisoformat(entry['timestamp'].rstrip('Z')).timestamp() > cutoff_time
        ]
    
    # Simple print for now since debug_mode might not be available yet
    print(f"[ERROR] {error_type}: {message}")
    if exception:
        print(f"[ERROR] Exception: {exception}")
    
    # Try to use debug_mode if it's available
    try:
        if 'debug_mode' in globals() and debug_mode:
            print(f"[ERROR] {error_type}: {message}")
            if exception:
                print(f"[ERROR] Exception: {exception}")
    except NameError:
        pass  # debug_mode not defined yet

def log_debug(debug_type, message, details=None):
    """Centralized debug logging"""
    # Use the helper function to safely check debug mode status
    if is_debug_mode():
        print(f"[DEBUG] {debug_type}: {message}")
        if details:
            print(f"[DEBUG] {debug_type} details: {details}")

def log_info(info_type, message, details=None):
    """Centralized info logging"""
    # Always print info messages
    print(f"[INFO] {info_type}: {message}")
    
    # Print additional details if debug mode is enabled
    if is_debug_mode() and details:
        print(f"[INFO] {info_type} details: {details}")

def log_warning(warning_type, message, details=None):
    """Centralized warning logging"""
    # Always print warning messages
    print(f"[WARN] {warning_type}: {message}")
    
    # Print additional details if debug mode is enabled
    if is_debug_mode() and details:
        print(f"[WARN] {warning_type} details: {details}")

def is_debug_mode():
    """Helper function to safely check debug mode status"""
    global debug_mode
    try:
        return debug_mode
    except NameError:
        return False

# ============================================================================
# CENTRALIZED CONFIGURATION MANAGEMENT
# ============================================================================

class Config:
    """Centralized configuration management with validation"""
    
    def __init__(self):
        self._load_environment()
        self._validate_config()
    
    def _load_environment(self):
        """Load environment variables once at startup"""
        load_dotenv()
    
    def _validate_config(self):
        """Validate critical configuration values"""
        self._validate_timeouts()
        self._validate_rate_limits()
        self._validate_cache_settings()
        self._validate_api_credentials()
    
    def _validate_api_credentials(self):
        """Validate API credentials if they are configured"""
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
        cache_settings = {
            'LIBRARY_CACHE_TTL': (3600, 604800),  # 1 hour to 1 week
            'POSTER_REFRESH_INTERVAL': (3600, 604800)
        }
        
        for key, (min_val, max_val) in cache_settings.items():
            value = self.get_int(key, 86400)
            if not min_val <= value <= max_val:
                log_error("config_validation", f"Invalid cache value for {key}: {value}. Using default.", 
                         {"value": value, "min": min_val, "max": max_val})
    
    def get(self, key, default=None):
        """Get environment variable with validation"""
        return os.getenv(key, default)
    
    def get_int(self, key, default=0):
        """Get integer environment variable with validation"""
        try:
            value = os.getenv(key, str(default))
            return int(value)
        except (ValueError, TypeError):
            log_error("config_validation", f"Invalid integer value for {key}: {os.getenv(key)}", 
                     {"key": key, "value": os.getenv(key)})
            return default
    
    def get_bool(self, key, default=False):
        """Get boolean environment variable"""
        value = os.getenv(key, str(default)).lower()
        return value in ('true', '1', 'yes', 'on')
    
    def get_poster_refresh_mode(self):
        """Get poster refresh mode - incremental or full"""
        mode = os.getenv("POSTER_REFRESH_MODE", "incremental").lower()
        return mode in ('incremental', 'true', '1', 'yes', 'on')
    
    def validate_url(self, url, name="URL"):
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
    
    def validate_token(self, token, name="Token"):
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
            import re
            if not re.match(r'^[a-zA-Z0-9]{20,40}$', token):
                return False
        elif "ABS" in name.upper() or "AUDIOBOOKSHELF" in name.upper():
            # Audiobookshelf tokens are typically JWT-like or alphanumeric
            import re
            if not re.match(r'^[a-zA-Z0-9\-_\.]{20,}$', token):
                return False
        elif "DISCORD" in name.upper():
            # Discord webhook URLs should contain discord.com
            if "discord.com" not in token.lower():
                return False
        
        return True
    
    def validate_api_connection(self, api_type, url, token):
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
    
    def validate_email(self, email):
        """Basic email validation"""
        if not email:
            return False
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

# Global configuration instance
config = Config()

# Initialize debug_mode early to ensure logging works from the start
debug_mode = config.get_bool("FLASK_DEBUG", False)

def reload_config():
    """Reload configuration from environment variables"""
    global config, debug_mode
    config = Config()
    debug_mode = config.get_bool("FLASK_DEBUG", False)

# ============================================================================
# IMPROVED STATE MANAGEMENT AND ERROR HANDLING
# ============================================================================

class DownloadStatus:
    """Enum-like class for download status tracking"""
    IDLE = "idle"
    QUEUED = "queued"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class DownloadProgress:
    """Class for tracking download progress with better error handling"""
    def __init__(self, library_name="", total=0):
        self.current = 0
        self.total = total
        self.successful = 0
        self.failed = 0
        self.library_name = library_name
        self.status = DownloadStatus.IDLE
        self.error_message = ""
        self.start_time = None
        self.end_time = None
        self.retry_count = 0
        self.max_retries = 3
    
    def start(self):
        """Start the download process"""
        self.status = DownloadStatus.IN_PROGRESS
        self.start_time = time.time()
        self.error_message = ""
    
    def complete(self, successful=True):
        """Complete the download process"""
        self.status = DownloadStatus.COMPLETED if successful else DownloadStatus.FAILED
        self.end_time = time.time()
    
    def fail(self, error_message=""):
        """Mark download as failed"""
        self.status = DownloadStatus.FAILED
        self.failed += 1
        self.error_message = error_message
        self.end_time = time.time()
    
    def can_retry(self):
        """Check if download can be retried"""
        return self.retry_count < self.max_retries and self.status == DownloadStatus.FAILED
    
    def retry(self):
        """Increment retry count and reset status"""
        self.retry_count += 1
        self.status = DownloadStatus.QUEUED
        self.error_message = ""

# Global poster download state with improved error handling and resource limits
poster_download_queue = queue.Queue(maxsize=1000)  # Limit queue size to prevent memory leaks
poster_download_lock = Lock()
poster_download_running = False
poster_download_progress = {}
abs_download_in_progress = False
abs_download_completed = False
abs_download_queued = False

# Resource limits for poster downloads
POSTER_DOWNLOAD_LIMITS = {
    'max_concurrent_downloads': 5,
    'max_download_size_mb': 2,
    'max_downloads_per_hour': 1000,
    'max_progress_entries': 50,
    'max_cache_size_mb': 100
}

# API rate limiting configuration
API_RATE_LIMITS = {
    'plex': {'requests_per_second': 10, 'burst_limit': 20},
    'abs': {'requests_per_second': 5, 'burst_limit': 10},
    'discord': {'requests_per_second': 2, 'burst_limit': 5},
    'general': {'requests_per_second': 20, 'burst_limit': 50}
}

# Rate limiting state tracking
api_request_timestamps = {
    'plex': [],
    'abs': [],
    'discord': [],
    'general': []
}
api_rate_limit_lock = Lock()



def retry_operation(operation, max_retries=3, delay=1.0, backoff_factor=2.0, 
                   exceptions=(Exception,), operation_name="operation"):
    """Retry an operation with exponential backoff and proper error handling"""
    last_exception = None
    
    for attempt in range(max_retries):
        try:
            return operation()
        except exceptions as e:
            last_exception = e
            if attempt < max_retries - 1:
                sleep_time = delay * (backoff_factor ** attempt)
                log_error("retry_operation", f"{operation_name} attempt {attempt + 1} failed, retrying in {sleep_time}s", 
                         {"attempt": attempt + 1, "max_retries": max_retries, "operation": operation_name}, e)
                time.sleep(sleep_time)
            else:
                log_error("retry_operation", f"All {max_retries} attempts failed for {operation_name}", 
                         {"attempts": max_retries, "operation": operation_name}, e)
                raise last_exception
    
    raise last_exception

def safe_operation(operation, error_message, error_type="general", 
                  default_return=None, log_error_flag=True):
    """Safely execute an operation with comprehensive error handling"""
    try:
        return operation()
    except Exception as e:
        if log_error_flag:
            log_error(error_type, error_message, {}, e)
        if default_return is not None:
            return default_return
        raise

def safe_api_call(api_func, timeout=None, max_retries=3, operation_name="api_call"):
    """Safely execute API calls with proper error handling and timeouts"""
    def api_operation():
        if timeout:
            return api_func(timeout=timeout)
        return api_func()
    
    try:
        return retry_operation(
            api_operation,
            max_retries=max_retries,
            delay=1.0,
            backoff_factor=2.0,
            exceptions=(requests.exceptions.RequestException, requests.exceptions.Timeout),
            operation_name=operation_name
        )
    except requests.exceptions.Timeout:
        log_error("api_timeout", f"API call timed out after {timeout}s", {"operation": operation_name})
        raise
    except requests.exceptions.ConnectionError:
        log_error("api_connection", f"Failed to connect to API", {"operation": operation_name})
        raise
    except requests.exceptions.HTTPError as e:
        log_error("api_http_error", f"HTTP error in API call: {e}", {"operation": operation_name, "status_code": e.response.status_code})
        raise
    except Exception as e:
        log_error("api_unknown", f"Unexpected error in API call: {e}", {"operation": operation_name})
        raise

# Adaptive restart configuration with error handling
RESTART_DELAY_SECONDS = config.get_int("RESTART_DELAY_SECONDS", 5)
POSTER_DOWNLOAD_TIMEOUT = config.get_int("POSTER_DOWNLOAD_TIMEOUT", 300)
IMMEDIATE_RESTART_DELAY = config.get_int("IMMEDIATE_RESTART_DELAY", 5)
STANDARD_RESTART_DELAY = config.get_int("STANDARD_RESTART_DELAY", 5)

# Library caching infrastructure
LIBRARY_CACHE_TTL = config.get_int("LIBRARY_CACHE_TTL", 43200)
POSTER_REFRESH_INTERVAL = config.get_int("POSTER_REFRESH_INTERVAL", 43200)
library_cache = {}
library_cache_timestamp = 0
library_cache_lock = Lock()

# Rate limiting state with improved structure
class RateLimitManager:
    """Centralized rate limiting state management"""
    def __init__(self):
        self.failed_attempts = defaultdict(list)  # IP -> list of timestamps
        self.lockout_end_times = defaultdict(float)  # IP -> lockout end timestamp
        self.form_submissions = defaultdict(lambda: defaultdict(list))  # IP -> form_type -> list of submission timestamps
        self.banned_ips = set()  # Set of banned IPs
        self.whitelisted_ips = set()  # Set of whitelisted IPs
        self.first_failed_attempt_ips = set()  # IPs that have had their first failed login attempt
        self.lockout_notified_ips = set()  # IPs that have been notified about lockouts
        self.lock = Lock()
    
    def cleanup_expired_data(self, current_time):
        """Clean up expired rate limit data"""
        with self.lock:
            # Clean up failed attempts older than 24 hours
            cutoff_time = current_time - 86400
            for ip in list(self.failed_attempts.keys()):
                self.failed_attempts[ip] = [
                    t for t in self.failed_attempts[ip] 
                    if t > cutoff_time
                ]
                if not self.failed_attempts[ip]:
                    del self.failed_attempts[ip]
            
            # Clean up expired lockouts
            expired_ips = [
                ip for ip, end_time in self.lockout_end_times.items()
                if current_time >= end_time
            ]
            for ip in expired_ips:
                del self.lockout_end_times[ip]
            
            # Clean up form submissions older than 24 hours
            for ip in list(self.form_submissions.keys()):
                for form_type in list(self.form_submissions[ip].keys()):
                    self.form_submissions[ip][form_type] = [
                        t for t in self.form_submissions[ip][form_type]
                        if t > cutoff_time
                    ]
                    if not self.form_submissions[ip][form_type]:
                        del self.form_submissions[ip][form_type]
                if not self.form_submissions[ip]:
                    del self.form_submissions[ip]

# Global rate limit manager
rate_limit_manager = RateLimitManager()
rate_limit_data = {
    'failed_attempts': rate_limit_manager.failed_attempts,
    'lockout_end_times': rate_limit_manager.lockout_end_times,
    'form_submissions': rate_limit_manager.form_submissions,
    'banned_ips': rate_limit_manager.banned_ips,
    'whitelisted_ips': rate_limit_manager.whitelisted_ips,
    'first_failed_attempt_ips': rate_limit_manager.first_failed_attempt_ips,
    'lockout_notified_ips': rate_limit_manager.lockout_notified_ips
}

# --- Rate Limiting Constants ---
RATE_LIMIT_THRESHOLDS = {
    'suspicious': config.get_int("RATE_LIMIT_IP_SUSPICIOUS_THRESHOLD", 20),
    'ban': config.get_int("RATE_LIMIT_IP_BAN_THRESHOLD", 50),
    'max_attempts': config.get_int("RATE_LIMIT_MAX_LOGIN_ATTEMPTS", config.get_int("RATE_LIMIT_LOGIN_ATTEMPTS", 5))
}

def is_running_in_docker():
    """Detect if the application is running inside a Docker container"""
    try:
        with open('/proc/1/cgroup', 'r') as f:
            return any('docker' in line for line in f)
    except (FileNotFoundError, PermissionError):
        # Check for Docker environment variables
        return any(var in os.environ for var in ['DOCKER_CONTAINER', 'KUBERNETES_SERVICE_HOST'])

# Application configuration
# APP_PORT will be set after load_dotenv() is called

def get_app_url():
    """Determine the correct URL to open in browser"""
    port = APP_PORT
    
    # Check if we're in Docker
    if is_running_in_docker():
        # In Docker, we need to determine the external URL
        # This could be localhost if port is mapped, or a different host
        # For now, we'll use localhost as the most common case
        return f"http://localhost:{port}"
    else:
        # Native installation
        return f"http://localhost:{port}"

def open_browser_delayed():
    """Open browser after a delay to ensure server is running"""
    time.sleep(2)  # Wait for Flask to start
    try:
        url = get_app_url()
        print(f"\n[INFO] Opening browser to: {url}")
        webbrowser.open(url)
    except Exception as e:
        print(f"[WARN] Failed to open browser: {e}")
        print(f"[INFO] Please manually open: {get_app_url()}")

# Rate limiting functions
def get_client_ip():
    """Get the client's IP address, handling proxies"""
    try:
        if request.headers.get('X-Forwarded-For'):
            return request.headers.get('X-Forwarded-For').split(',')[0].strip()
        elif request.headers.get('X-Real-IP'):
            return request.headers.get('X-Real-IP')
        else:
            return request.remote_addr
    except RuntimeError:
        # Handle case where request context is not available
        return "127.0.0.1"

def is_valid_ip_range(ip_range):
    """Validate IP range format (e.g., 192.168.1.0/24)"""
    import re
    import ipaddress
    
    try:
        # Check if it's a valid IP range
        ipaddress.ip_network(ip_range, strict=False)
        return True
    except ValueError:
        return False

def is_valid_single_ip(ip):
    """Validate single IP address format"""
    import re
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return bool(re.match(ip_pattern, ip))

def is_valid_ip_or_range(ip_or_range):
    """Validate if input is either a single IP or IP range"""
    return is_valid_single_ip(ip_or_range) or is_valid_ip_range(ip_or_range)

def ip_in_range(client_ip, ip_range):
    """Check if client IP is within the specified IP range"""
    import ipaddress
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
        client_ip_obj = ipaddress.ip_address(client_ip)
        return client_ip_obj in network
    except ValueError:
        return False

def is_ip_whitelisted(ip):
    """Check if IP is whitelisted (supports both single IPs and ranges)"""
    # First check for exact matches
    if ip in rate_limit_data['whitelisted_ips']:
        return True
    
    # Then check if IP is within any whitelisted ranges
    for whitelisted_item in rate_limit_data['whitelisted_ips']:
        if '/' in whitelisted_item:  # This is an IP range
            if ip_in_range(ip, whitelisted_item):
                return True
    
    return False

def is_ip_banned(ip):
    """Check if IP is banned (supports both single IPs and ranges)"""
    # First check for exact matches
    if ip in rate_limit_data['banned_ips']:
        return True
    
    # Then check if IP is within any banned ranges
    for banned_item in rate_limit_data['banned_ips']:
        if '/' in banned_item:  # This is an IP range
            if ip_in_range(ip, banned_item):
                return True
    
    return False

def check_first_time_ip_access(ip):
    """Check if this is the first time an IP has accessed the site and notify if so"""
    # Check if IP has been logged before by looking at security_log.json
    try:
        log_file = "security_log.json"
        logs = load_json_file(log_file, [])
        
        # Check if this IP has any previous entries in the security log
        for log_entry in logs:
            if log_entry.get("ip_address") == ip:
                # IP has been seen before, don't send notification
                return False
        
        # This is truly a new IP - log the event and send notification
        log_security_event("first_access", ip, "IP accessed the site for the first time")
        return True
        
    except Exception as e:
        if debug_mode:
            print(f"Error checking first time IP access: {e}")
        # If there's an error reading the log, fall back to logging the event
        log_security_event("first_access", ip, "IP accessed the site for the first time")
        return True

def check_first_time_login_success(ip):
    """Check if this is the first time an IP has successfully logged in and notify if so"""
    # Check if IP has been logged before by looking at security_log.json
    try:
        log_file = "security_log.json"
        logs = load_json_file(log_file, [])
        
        # Check if this IP has any previous login_success entries in the security log
        for log_entry in logs:
            if (log_entry.get("ip_address") == ip and 
                log_entry.get("event_type") == "login_success"):
                # IP has successfully logged in before, don't send notification
                return False
        
        # This is truly a new successful login for this IP - log the event and send notification
        log_security_event("login_success", ip, "IP successfully logged in for the first time")
        return True
        
    except Exception as e:
        if debug_mode:
            print(f"Error checking first time login success: {e}")
        # If there's an error reading the log, fall back to logging the event
        log_security_event("login_success", ip, "IP successfully logged in for the first time")
        return True

def add_ip_to_whitelist(ip_or_range):
    """Add IP or IP range to whitelist"""
    if not is_valid_ip_or_range(ip_or_range):
        raise ValueError(f"Invalid IP or IP range format: {ip_or_range}")
    
    rate_limit_data['whitelisted_ips'].add(ip_or_range)
    # Remove from banned list if present
    if ip_or_range in rate_limit_data['banned_ips']:
        rate_limit_data['banned_ips'].remove(ip_or_range)
    # Persist to .env file
    save_ip_lists_to_env()
    log_security_event("ip_whitelisted", ip_or_range, "IP/IP range added to whitelist")

def remove_ip_from_whitelist(ip_or_range):
    """Remove IP or IP range from whitelist"""
    if ip_or_range in rate_limit_data['whitelisted_ips']:
        rate_limit_data['whitelisted_ips'].remove(ip_or_range)
        # Persist to .env file
        save_ip_lists_to_env()
        log_security_event("ip_whitelist_removed", ip_or_range, "IP/IP range removed from whitelist")

def add_ip_to_blacklist(ip_or_range):
    """Add IP or IP range to blacklist (banned)"""
    if not is_valid_ip_or_range(ip_or_range):
        raise ValueError(f"Invalid IP or IP range format: {ip_or_range}")
    
    rate_limit_data['banned_ips'].add(ip_or_range)
    # Remove from whitelist if present
    if ip_or_range in rate_limit_data['whitelisted_ips']:
        rate_limit_data['whitelisted_ips'].remove(ip_or_range)
    # Persist to .env file
    save_ip_lists_to_env()
    log_security_event("ip_banned", ip_or_range, "IP/IP range added to blacklist")

def remove_ip_from_blacklist(ip_or_range):
    """Remove IP or IP range from blacklist"""
    if ip_or_range in rate_limit_data['banned_ips']:
        rate_limit_data['banned_ips'].remove(ip_or_range)
        # Persist to .env file
        save_ip_lists_to_env()
        log_security_event("ip_blacklist_removed", ip_or_range, "IP/IP range removed from blacklist")

def get_ip_lists():
    """Get current IP whitelist and blacklist"""
    return {
        'whitelisted': list(rate_limit_data['whitelisted_ips']),
        'banned': list(rate_limit_data['banned_ips'])
    }

def record_failed_attempt(ip, current_time):
    """Record a single failed attempt"""
    rate_limit_data['failed_attempts'][ip].append(current_time)

def cleanup_old_attempts(ip, cutoff_time):
    """Remove attempts older than cutoff time"""
    rate_limit_data['failed_attempts'][ip] = [
        t for t in rate_limit_data['failed_attempts'][ip] 
        if t > cutoff_time
    ]

def check_threshold_violations(ip, failed_count):
    """Check if IP violates suspicious or ban thresholds"""
    if failed_count >= RATE_LIMIT_THRESHOLDS['ban']:
        rate_limit_data['banned_ips'].add(ip)
        log_security_event("ip_banned", ip, f"IP banned after {failed_count} failed attempts")
        return 'banned'
    elif failed_count >= RATE_LIMIT_THRESHOLDS['suspicious']:
        log_security_event("ip_suspicious", ip, f"IP marked as suspicious after {failed_count} failed attempts")
        return 'suspicious'
    return None

def should_lockout_ip(ip, current_time):
    """Check if IP should be locked out based on recent attempts"""
    max_attempts = RATE_LIMIT_THRESHOLDS['max_attempts']
    
    # Check attempts in last 15 minutes
    recent_attempts = [t for t in rate_limit_data['failed_attempts'][ip] if t > current_time - 900]
    if len(recent_attempts) >= max_attempts:
        return current_time
    
    # Check attempts in last hour (maintain lockout if enough attempts)
    hour_ago = current_time - 3600
    attempts_in_last_hour = [t for t in rate_limit_data['failed_attempts'][ip] if t > hour_ago]
    
    if len(attempts_in_last_hour) >= max_attempts:
        sorted_attempts = sorted(attempts_in_last_hour)
        return sorted_attempts[-max_attempts]
    
    return None

def handle_security_notifications(ip, threshold_result, lockout_start, recent_attempts):
    """Handle security event notifications"""
    # Smart notification logic: Only notify on first failed attempt and when lockout occurs
    if ip not in rate_limit_data['first_failed_attempt_ips']:
        # This is the first failed attempt from this IP
        rate_limit_data['first_failed_attempt_ips'].add(ip)
        log_security_event("login_failed", ip, "First failed login attempt")
    elif lockout_start and ip not in rate_limit_data['lockout_notified_ips']:
        # IP just got locked out, notify about lockout
        rate_limit_data['lockout_notified_ips'].add(ip)
        log_security_event("login_lockout", ip, f"IP locked out after {len(recent_attempts)} failed attempts")

def add_failed_attempt(ip, attempt_type="login"):
    """Record a failed authentication attempt"""
    if is_ip_whitelisted(ip):
        return
    
    current_time = time.time()
    record_failed_attempt(ip, current_time)
    
    # Clean old attempts (older than 24 hours)
    cleanup_old_attempts(ip, current_time - 86400)
    
    # Check thresholds and ban if needed
    failed_count = len(rate_limit_data['failed_attempts'][ip])
    threshold_result = check_threshold_violations(ip, failed_count)
    
    # Check if IP should be locked out
    lockout_start = should_lockout_ip(ip, current_time)
    
    if lockout_start and ip not in rate_limit_data['lockout_end_times']:
        lockout_duration = config.get_int("RATE_LIMIT_LOGIN_LOCKOUT_DURATION", 3600)
        rate_limit_data['lockout_end_times'][ip] = lockout_start + lockout_duration
        if debug_mode:
            print(f"[DEBUG] IP {ip} locked out until {rate_limit_data['lockout_end_times'][ip]}")
    
    # Handle notifications
    recent_attempts = [t for t in rate_limit_data['failed_attempts'][ip] if t > current_time - 900]
    handle_security_notifications(ip, threshold_result, lockout_start, recent_attempts)

def check_rate_limit(ip, limit_type="login", form_type=None):
    """Check if IP is rate limited"""
    if is_ip_whitelisted(ip):
        return False, 0
    
    if is_ip_banned(ip):
        return True, 3600  # 1 hour ban
    
    # Clean up expired lockouts periodically
    cleanup_expired_lockouts()
    
    current_time = time.time()
    
    if limit_type == "login":
        # Check if IP is currently locked out
        if ip in rate_limit_data['lockout_end_times']:
            remaining_time = max(0, rate_limit_data['lockout_end_times'][ip] - current_time)
            
            if remaining_time > 0:
                if debug_mode:
                    print(f"[DEBUG] IP {ip} rate limited, {remaining_time}s remaining")
                return True, remaining_time
            else:
                # Lockout expired, clear it
                del rate_limit_data['lockout_end_times'][ip]
                if debug_mode:
                    print(f"[DEBUG] IP {ip} lockout expired")
        
        # Check if IP should be locked out based on recent attempts
        lockout_start = should_lockout_ip(ip, current_time)
        if lockout_start and ip not in rate_limit_data['lockout_end_times']:
            lockout_duration = config.get_int("RATE_LIMIT_LOGIN_LOCKOUT_DURATION", 3600)
            rate_limit_data['lockout_end_times'][ip] = lockout_start + lockout_duration
            if debug_mode:
                print(f"[DEBUG] IP {ip} lockout started")
            return True, lockout_duration
    
    elif limit_type == "form_submission":
        # Check form submission rate limiting - separate by form type
        if form_type is None:
            return False, 0
            
        submissions = rate_limit_data['form_submissions'][ip][form_type]
        max_submissions = config.get_int("RATE_LIMIT_MAX_FORM_SUBMISSIONS", config.get_int("RATE_LIMIT_FORM_SUBMISSIONS", 1))
        
        # Count submissions in last hour
        recent_submissions = [t for t in submissions if t > current_time - 3600]  # 1 hour
        
        if len(recent_submissions) >= max_submissions:
            # Calculate remaining time until next submission allowed
            oldest_submission = min(recent_submissions)
            next_allowed = oldest_submission + 3600  # 1 hour
            remaining_time = max(0, next_allowed - current_time)
            return True, remaining_time
    
    return False, 0

def add_form_submission(ip, form_type):
    """Record a form submission"""
    if is_ip_whitelisted(ip):
        return
    
    current_time = time.time()
    rate_limit_data['form_submissions'][ip][form_type].append(current_time)
    
    # Clean old submissions (older than 24 hours)
    cutoff_time = current_time - 86400
    rate_limit_data['form_submissions'][ip][form_type] = [
        t for t in rate_limit_data['form_submissions'][ip][form_type] 
        if t > cutoff_time
    ]

def log_security_event(event_type, ip, details):
    """Log security events"""
    if not config.get_bool("ENABLE_AUDIT_LOGGING", True):
        return
    
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "event_type": event_type,
        "ip_address": ip,
        "user_agent": request.headers.get('User-Agent', ''),
        "details": details
    }
    
    try:
        # Load existing logs
        log_file = "security_log.json"
        logs = load_json_file(log_file, [])
        
        # Add new log entry
        logs.append(log_entry)
        
        # Keep only last 90 days of logs
        retention_days = config.get_int("AUDIT_LOG_RETENTION_DAYS", 90)
        cutoff_time = datetime.now(timezone.utc).timestamp() - (retention_days * 86400)
        
        # Filter logs by timestamp (if they have one)
        filtered_logs = []
        for log in logs:
            try:
                log_timestamp = datetime.fromisoformat(log.get("timestamp", "").replace("Z", "+00:00")).timestamp()
                if log_timestamp > cutoff_time:
                    filtered_logs.append(log)
            except:
                # If timestamp parsing fails, keep the log
                filtered_logs.append(log)
        
        # Save filtered logs
        save_json_file(log_file, filtered_logs)
        
        # Send Discord notification for security events using the new function
        send_security_discord_notification(event_type, ip, details)
            
    except Exception as e:
        if debug_mode:
            print(f"Error logging security event: {e}")

def format_time_remaining(seconds):
    """Format remaining time in a human-readable format"""
    if seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours} hour{'s' if hours != 1 else ''} and {minutes} minute{'s' if minutes != 1 else ''}"

def cleanup_expired_lockouts():
    """Clean up expired lockouts from memory using the rate limit manager"""
    current_time = time.time()
    
    try:
        rate_limit_manager.cleanup_expired_data(current_time)
        if debug_mode:
            print(f"[DEBUG] Cleaned up expired rate limit data")
    except Exception as e:
        log_error("rate_limit_cleanup", "Failed to cleanup expired lockouts", {}, e)

def cleanup_poster_progress():
    """Clean up poster download progress to prevent memory leaks"""
    global poster_download_progress
    
    with poster_download_lock:
        # Remove completed downloads older than 1 hour
        current_time = time.time()
        cutoff_time = current_time - 3600
        
        # Clean up progress entries
        if len(poster_download_progress) > POSTER_DOWNLOAD_LIMITS['max_progress_entries']:
            # Remove oldest entries if we exceed the limit
            sorted_entries = sorted(poster_download_progress.items(), 
                                  key=lambda x: x[1].get('start_time', 0))
            entries_to_remove = len(poster_download_progress) - POSTER_DOWNLOAD_LIMITS['max_progress_entries']
            for i in range(entries_to_remove):
                if sorted_entries:
                    del poster_download_progress[sorted_entries[i][0]]
        
        if debug_mode and poster_download_progress:
            print(f"[DEBUG] Cleaned up poster progress, {len(poster_download_progress)} entries remaining")

def check_api_rate_limit(api_type):
    """Check and enforce API rate limits"""
    global api_request_timestamps
    
    with api_rate_limit_lock:
        current_time = time.time()
        timestamps = api_request_timestamps[api_type]
        limits = API_RATE_LIMITS[api_type]
        
        # Remove timestamps older than 1 second
        timestamps[:] = [ts for ts in timestamps if current_time - ts < 1.0]
        
        # Check if we're within rate limits
        if len(timestamps) >= limits['requests_per_second']:
            # Calculate delay needed
            oldest_timestamp = min(timestamps)
            delay_needed = 1.0 - (current_time - oldest_timestamp)
            if delay_needed > 0:
                time.sleep(delay_needed)
        
        # Add current timestamp
        timestamps.append(current_time)
        
        # Enforce burst limit
        if len(timestamps) > limits['burst_limit']:
            # Remove oldest timestamps to stay within burst limit
            timestamps[:] = timestamps[-limits['burst_limit']:]



# Ensure SECRET_KEY is set
def ensure_secret_key():
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

ensure_secret_key()
# Set APP_PORT after loading environment variables
APP_PORT = config.get_int("APP_PORT")

app = Flask(__name__)
app.secret_key = config.get("SECRET_KEY") or os.urandom(24)
csrf = CSRFProtect(app)

# Initialize Flask-Limiter
limiter = Limiter(
    app=app,
    key_func=get_client_ip,  # Use our custom IP detection function
    default_limits=["200 per day", "50 per hour"]
)






# Plex details
PLEX_TOKEN = config.get("PLEX_TOKEN")
PLEX_URL = config.get("PLEX_URL")

@app.context_processor
def inject_server_name():
    return dict(
        SERVER_NAME=config.get("SERVER_NAME", "DefaultName"),
        ABS_ENABLED=config.get("ABS_ENABLED", "yes"),
        AUDIOBOOKSHELF_URL=config.get("AUDIOBOOKSHELF_URL", ""),
        ACCENT_COLOR=config.get("ACCENT_COLOR", "#d33fbc"),
        QUICK_ACCESS_ENABLED=config.get("QUICK_ACCESS_ENABLED", "yes"),
        LIBRARY_CAROUSELS=config.get("LIBRARY_CAROUSELS", ""),
        ONBOARDERR_URL=config.get("ONBOARDERR_URL", "")
    )

@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)

@app.context_processor
def inject_admin_status():
    # Make sure session is available in context
    from flask import session
    return dict(
        is_admin=session.get("admin_authenticated", False),
        logo_filename=get_logo_filename(),
        wordmark_filename=get_wordmark_filename()
    )

@app.context_processor
def inject_favicon_timestamp():
    """Inject favicon timestamp to force browser cache updates"""
    favicon_path = os.path.join('static', 'favicon.webp')
    try:
        # Get file modification time as timestamp
        favicon_timestamp = int(os.path.getmtime(favicon_path))
    except (OSError, FileNotFoundError):
        # If favicon doesn't exist, use current time
        favicon_timestamp = int(time.time())
    return dict(favicon_timestamp=favicon_timestamp)

def get_libraries_from_local_files():
    """
    Get library information from local files only (no Plex API calls).
    Returns library data from library_notes.json and poster directories.
    """
    if is_debug_mode():
        print("[DEBUG] Getting libraries from local files only...")
    
    libraries = []
    library_notes = load_library_notes()
    
    # Get all library IDs from library_notes.json
    for lib_id, note_data in library_notes.items():
        title = note_data.get("title", f"Library {lib_id}")
        # Check if poster directory exists to determine media type
        poster_dir = get_library_poster_dir(lib_id)
        media_type = "show"  # Default to show
        
        if os.path.exists(poster_dir):
            # Try to determine media type from existing posters
            poster_files = [f for f in os.listdir(poster_dir) if f.lower().endswith(('.webp', '.jpg', '.jpeg', '.png'))]
            if poster_files:
                # Check first poster's metadata to determine media type
                first_poster = poster_files[0]
                json_path = os.path.join(poster_dir, first_poster.rsplit('.', 1)[0] + '.json')
                if os.path.exists(json_path):
                    try:
                        with open(json_path, 'r', encoding='utf-8') as f:
                            meta = json.load(f)
                            # Check if it's a music artist
                            if meta.get('type') == 'artist' or 'artist' in meta.get('title', '').lower():
                                media_type = "artist"
                            elif meta.get('type') == 'movie':
                                media_type = "movie"
                            elif meta.get('type') == 'show':
                                media_type = "show"
                    except (IOError, json.JSONDecodeError):
                        pass
        
        libraries.append({
            "title": title,
            "key": lib_id,
            "media_type": media_type
        })
        
        if debug_mode:
            print(f"[DEBUG] Found local library: {title} (ID: {lib_id}, Type: {media_type})")
    
    if debug_mode:
        print(f"[DEBUG] Total libraries from local files: {len(libraries)}")
    
    return libraries

def get_plex_libraries(force_refresh=False):
    """
    Get Plex libraries with caching support and improved error handling.
    Args:
        force_refresh: If True, bypass cache and fetch fresh data
    """
    global library_cache, library_cache_timestamp
    
    current_time = time.time()
    
    # Check if we have valid cached data
    if not force_refresh and library_cache and (current_time - library_cache_timestamp) < LIBRARY_CACHE_TTL:
        if debug_mode:
            print(f"[DEBUG] Using cached library data (age: {current_time - library_cache_timestamp:.1f}s)")
        return library_cache
    
    # Get Plex credentials with validation
    plex_token = config.get("PLEX_TOKEN")
    plex_url = config.get("PLEX_URL")
    
    if debug_mode:
        print("[DEBUG] Getting Plex libraries...")
        print(f"[DEBUG] PLEX_URL = {plex_url}")
        print(f"[DEBUG] PLEX_TOKEN = {plex_token[:10]}..." if plex_token else "[DEBUG] PLEX_TOKEN = None")
    
    # Validate Plex configuration
    if not config.validate_token(plex_token, "PLEX_TOKEN"):
        log_error("plex_config", "Invalid Plex token", {"has_token": bool(plex_token)})
        return []
    
    if not config.validate_url(plex_url, "PLEX_URL"):
        log_error("plex_config", "Invalid Plex URL", {"url": plex_url})
        return []
    
    headers = {"X-Plex-Token": plex_token}
    
    # Ensure plex_url has a scheme
    if plex_url and not plex_url.startswith(('http://', 'https://')):
        plex_url = f"http://{plex_url}"  # Default to http if no scheme provided
        if debug_mode:
            print(f"[DEBUG] Added scheme to PLEX_URL: {plex_url}")
    
    url = f"{plex_url}/library/sections"
    if debug_mode:
        print(f"[DEBUG] Making request to: {url}")
    
    def fetch_plex_libraries():
        """Inner function for retry mechanism"""
        timeout = config.get_int("PLEX_API_TIMEOUT", 10)
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        return response.text
    
    try:
        # Use retry mechanism for Plex API calls
        response_text = retry_operation(
            fetch_plex_libraries,
            max_retries=3,
            delay=2.0,
            operation_name="plex_library_fetch"
        )
        
        root = ET.fromstring(response_text)
        libraries = []
        
        for directory in root.findall(".//Directory"):
            title = directory.attrib.get("title")
            key = directory.attrib.get("key")
            media_type = directory.attrib.get("type")
            
            if title and key:
                libraries.append({
                    "title": title, 
                    "key": key, 
                    "media_type": media_type
                })
                if debug_mode:
                    print(f"[DEBUG] Found library: {title} (ID: {key}, Type: {media_type})")
        
        if debug_mode:
            print(f"[DEBUG] Total libraries found: {len(libraries)}")
        
        # Update cache with thread safety
        with library_cache_lock:
            library_cache = libraries
            library_cache_timestamp = current_time
        
        return libraries
        
    except requests.exceptions.MissingSchema as e:
        log_error("plex_url", f"Invalid Plex URL (missing scheme): {plex_url}", {"original_url": plex_url}, e)
        raise
    except requests.exceptions.RequestException as e:
        log_error("plex_connection", f"Failed to connect to Plex: {e}", {"url": url}, e)
        raise
    except ET.ParseError as e:
        log_error("plex_parse", "Failed to parse Plex XML response", {"url": url}, e)
        raise
    except Exception as e:
        log_error("plex_unknown", "Unexpected error fetching Plex libraries", {"url": url}, e)
        raise

# --- File read/write: always use utf-8 encoding and os.path.join ---
def compare_local_vs_server_metadata(local_meta, server_item):
    """
    Compare local metadata with server metadata to detect changes.
    Returns True if metadata has changed and needs re-download.
    
    Args:
        local_meta: Local metadata dictionary
        server_item: Server item dictionary with attributes
        
    Returns:
        bool: True if metadata has changed
    """
    if not local_meta or not server_item:
        return True
    
    # Compare key metadata fields - only thumb changes should trigger re-download
    # Title and year changes are usually just metadata updates, not poster changes
    thumb_local = local_meta.get('thumb', '')
    thumb_server = server_item.get('thumb', '')
    
    # If local metadata doesn't have thumb field, it's an old format file
    # We should only trigger re-download if the server has a thumb and local doesn't
    if not thumb_local and thumb_server:
        if debug_mode:
            print(f"[DEBUG] Old metadata format detected, adding thumb field: '{thumb_server}'")
        return True
    
    # Only trigger re-download if the thumb URL has actually changed
    if str(thumb_local).strip() != str(thumb_server).strip():
        if debug_mode:
            print(f"[DEBUG] Thumb URL change detected: '{thumb_local}' -> '{thumb_server}'")
        return True
    
    return False

def smart_check_library_posters(library_id, plex_url, headers):
    """
    Smart check for library posters - compares local files with server and determines what needs updating.
    
    Args:
        library_id: Library ID to check
        plex_url: Plex server URL
        headers: Request headers with token
        
    Returns:
        dict: {
            'needs_download': bool,
            'new_items': list,
            'changed_items': list,
            'removed_count': int,
            'server_offline': bool,
            'error': str
        }
    """
    result = {
        'needs_download': False,
        'new_items': [],
        'changed_items': [],
        'removed_count': 0,
        'server_offline': False,
        'error': None
    }
    
    try:
        # Check if server is reachable
        test_url = f"{plex_url}/library/sections/{library_id}/all"
        response = requests.get(test_url, headers=headers, timeout=5)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        if debug_mode:
            print(f"[DEBUG] Server offline for library {library_id}: {e}")
        result['server_offline'] = True
        return result
    
    try:
        # Get current server items
        response = requests.get(test_url, headers=headers, timeout=10)
        response.raise_for_status()
        root = ET.fromstring(response.content)
        
        # Collect current items from server
        current_items = []
        current_rating_keys = set()
        
        for el in root.findall(".//Video"):
            thumb = el.attrib.get("thumb")
            rating_key = el.attrib.get("ratingKey")
            title = el.attrib.get("title")
            year = el.attrib.get("year")
            if thumb and rating_key:
                item = {"thumb": thumb, "ratingKey": rating_key, "title": title, "year": year}
                current_items.append(item)
                current_rating_keys.add(rating_key)
        
        for el in root.findall(".//Directory"):
            thumb = el.attrib.get("thumb")
            rating_key = el.attrib.get("ratingKey")
            title = el.attrib.get("title")
            if thumb and rating_key and not any(i["ratingKey"] == rating_key for i in current_items):
                item = {"thumb": thumb, "ratingKey": rating_key, "title": title}
                current_items.append(item)
                current_rating_keys.add(rating_key)
        
        # Clean up deleted posters
        result['removed_count'] = cleanup_deleted_posters(library_id, current_rating_keys)
        
        # Get existing poster rating keys and metadata
        existing_keys = get_existing_poster_rating_keys(library_id)
        poster_dir = get_library_poster_dir(library_id)
        
        # Check each server item
        for item in current_items:
            rating_key = item["ratingKey"]
            
            if rating_key not in existing_keys:
                # New item - needs download
                result['new_items'].append(item)
                result['needs_download'] = True
            else:
                # Existing item - check if metadata changed
                meta_file = os.path.join(poster_dir, f"poster_{rating_key}.json")
                if os.path.exists(meta_file):
                    try:
                        with open(meta_file, 'r', encoding='utf-8') as f:
                            local_meta = json.load(f)
                        
                        if compare_local_vs_server_metadata(local_meta, item):
                            result['changed_items'].append(item)
                            result['needs_download'] = True
                    except (IOError, json.JSONDecodeError) as e:
                        if debug_mode:
                            print(f"[DEBUG] Error reading local metadata for {rating_key}: {e}")
                        result['changed_items'].append(item)
                        result['needs_download'] = True
                else:
                    # Missing metadata file
                    result['changed_items'].append(item)
                    result['needs_download'] = True
        
        if debug_mode:
            print(f"[DEBUG] Smart check for library {library_id}: {len(result['new_items'])} new, {len(result['changed_items'])} changed, {result['removed_count']} removed")
        
    except Exception as e:
        if debug_mode:
            print(f"[ERROR] Error in smart check for library {library_id}: {e}")
        result['error'] = str(e)
    
    return result

def smart_check_abs_posters(abs_url, headers):
    """
    Smart check for ABS posters - compares local files with server and determines what needs updating.
    
    Args:
        abs_url: ABS server URL
        headers: Request headers with token
        
    Returns:
        dict: {
            'needs_download': bool,
            'new_items': list,
            'changed_items': list,
            'removed_count': int,
            'server_offline': bool,
            'error': str
        }
    """
    result = {
        'needs_download': False,
        'new_items': [],
        'changed_items': [],
        'removed_count': 0,
        'server_offline': False,
        'error': None
    }
    
    try:
        # Check if server is reachable
        test_url = f"{abs_url}/api/libraries"
        response = requests.get(test_url, headers=headers, timeout=5)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        if debug_mode:
            print(f"[DEBUG] ABS server offline: {e}")
        result['server_offline'] = True
        return result
    
    try:
        # Get ABS libraries
        response = requests.get(test_url, headers=headers, timeout=10)
        response.raise_for_status()
        libraries_data = response.json()
        
        # Extract libraries from the response
        libraries = libraries_data.get('libraries', [])
        if not isinstance(libraries, list):
            if debug_mode:
                print(f"[DEBUG] Unexpected libraries format: {type(libraries)}")
            return result
        
        audiobook_dir = os.path.join("static", "posters", "audiobooks")
        os.makedirs(audiobook_dir, exist_ok=True)
        
        # Get existing ABS poster files - use the actual file naming convention
        existing_books = set()
        if os.path.exists(audiobook_dir):
            # Load all existing audiobook metadata to get book IDs
            for f in os.listdir(audiobook_dir):
                if f.endswith('.json'):
                    try:
                        meta_path = os.path.join(audiobook_dir, f)
                        with open(meta_path, 'r', encoding='utf-8') as meta_file:
                            meta = json.load(meta_file)
                            book_id = meta.get('id')
                            library_id = meta.get('library_id')
                            if book_id and library_id:
                                book_key = f"abs_book_{library_id}_{book_id}"
                                existing_books.add(book_key)
                    except (IOError, json.JSONDecodeError):
                        continue
            
            if debug_mode:
                print(f"[DEBUG] Found {len(existing_books)} existing ABS books")
                if len(existing_books) > 0:
                    print(f"[DEBUG] Sample existing books: {list(existing_books)[:5]}")
        
        # Check each library
        for library in libraries:
            library_id = library.get('id')
            if not library_id:
                continue
            
            # Get books in this library
            books_url = f"{abs_url}/api/libraries/{library_id}/items"
            books_response = requests.get(books_url, headers=headers, timeout=10)
            books_response.raise_for_status()
            books_data = books_response.json()
            
            current_books = set()
            
            for book in books_data.get('results', []):
                book_id = book.get('id')
                if not book_id:
                    continue
                
                book_key = f"abs_book_{library_id}_{book_id}"
                current_books.add(book_key)
                
                if book_key not in existing_books:
                    # New book - needs download
                    if debug_mode:
                        print(f"[DEBUG] New ABS book detected: {book_key}")
                    result['new_items'].append({
                        'library_id': library_id,
                        'book_id': book_id,
                        'book': book
                    })
                    result['needs_download'] = True
                else:
                    # Existing book - check if metadata changed
                    meta_file = os.path.join(audiobook_dir, f"{book_key}.json")
                    if os.path.exists(meta_file):
                        try:
                            with open(meta_file, 'r', encoding='utf-8') as f:
                                local_meta = json.load(f)
                            
                            # Compare key metadata fields - use same field paths as when saving
                            server_title = book.get('title', '')
                            # Extract author from the same nested structure as when saving
                            media = book.get('media', {})
                            metadata = media.get('metadata', {})
                            server_author = metadata.get('authorName', '')
                            local_title = local_meta.get('title', '')
                            local_author = local_meta.get('author', '')
                            
                            # Add debug logging to see what's being compared
                            if debug_mode and (server_title != local_title or server_author != local_author):
                                print(f"[DEBUG] Metadata mismatch for book {book_id}:")
                                print(f"  Server title: '{server_title}' vs Local title: '{local_title}'")
                                print(f"  Server author: '{server_author}' vs Local author: '{local_author}'")
                            
                            if (server_title != local_title or server_author != local_author):
                                result['changed_items'].append({
                                    'library_id': library_id,
                                    'book_id': book_id,
                                    'book': book
                                })
                                result['needs_download'] = True
                        except (IOError, json.JSONDecodeError):
                            result['changed_items'].append({
                                'library_id': library_id,
                                'book_id': book_id,
                                'book': book
                            })
                            result['needs_download'] = True
                    else:
                        # Missing metadata file
                        result['changed_items'].append({
                            'library_id': library_id,
                            'book_id': book_id,
                            'book': book
                        })
                        result['needs_download'] = True
            
            # Clean up deleted books - this is more complex with the current file naming
            # For now, we'll skip cleanup to avoid breaking existing files
            # TODO: Implement proper cleanup when file naming is standardized
            pass
        
        if debug_mode:
            print(f"[DEBUG] Smart check for ABS: {len(result['new_items'])} new, {len(result['changed_items'])} changed, {result['removed_count']} removed")
        
    except Exception as e:
        if debug_mode:
            print(f"[ERROR] Error in smart ABS check: {e}")
        result['error'] = str(e)
    
    return result

def determine_download_needs(libraries, abs_enabled=True):
    """
    Determine what downloads are needed using smart logic.
    
    Args:
        libraries: List of library dictionaries
        abs_enabled: Whether ABS is enabled
        
    Returns:
        dict: {
            'plex_needs_download': bool,
            'abs_needs_download': bool,
            'plex_results': list of smart check results,
            'abs_result': smart check result,
            'any_server_offline': bool,
            'total_new': int,
            'total_changed': int,
            'total_removed': int
        }
    """
    result = {
        'plex_needs_download': False,
        'abs_needs_download': False,
        'plex_results': [],
        'abs_result': None,
        'any_server_offline': False,
        'total_new': 0,
        'total_changed': 0,
        'total_removed': 0
    }
    
    # Get Plex credentials
    plex_token = os.getenv("PLEX_TOKEN")
    plex_url = os.getenv("PLEX_URL")
    
    if not plex_token or not plex_url:
        if debug_mode:
            print("[DEBUG] No Plex credentials available for smart check")
        return result
    
    headers = {"X-Plex-Token": plex_token}
    
    # Check Plex libraries
    for lib in libraries:
        # Check if Plex downloads were recently completed for this library (within last 6 hours)
        # This prevents unnecessary re-downloads when coming from services form or setup
        plex_completion_file = os.path.join("static", "posters", str(lib["key"]), ".last_completion")
        if os.path.exists(plex_completion_file):
            try:
                with open(plex_completion_file, 'r') as f:
                    last_completion_time = float(f.read().strip())
                time_since_completion = time.time() - last_completion_time
                
                # If completed within last 6hr, skip download for this library
                if time_since_completion < 21600:  # 6hr
                    if debug_mode:
                        print(f"[DEBUG] Plex downloads for library {lib['key']} completed {time_since_completion:.1f} seconds ago, skipping re-download")
                    result['plex_results'].append({
                        'needs_download': False,
                        'new_items': [],
                        'changed_items': [],
                        'removed_count': 0,
                        'server_offline': False,
                        'error': None,
                        'skipped_recent_completion': True
                    })
                    continue
            except (IOError, ValueError) as e:
                if debug_mode:
                    print(f"[DEBUG] Could not read Plex completion timestamp for library {lib['key']}: {e}")
        
        lib_result = smart_check_library_posters(lib["key"], plex_url, headers)
        result['plex_results'].append(lib_result)
        
        if lib_result['server_offline']:
            result['any_server_offline'] = True
        
        if lib_result['needs_download']:
            result['plex_needs_download'] = True
            result['total_new'] += len(lib_result['new_items'])
            result['total_changed'] += len(lib_result['changed_items'])
            result['total_removed'] += lib_result['removed_count']
    
    # Check ABS if enabled
    if abs_enabled:
        abs_url = os.getenv("AUDIOBOOKSHELF_URL")
        if abs_url:
            # Check if ABS downloads were recently completed (within last 6 hours)
            # This prevents unnecessary re-downloads when coming from services form or setup
            abs_completion_file = os.path.join("static", "posters", "audiobooks", ".last_completion")
            if os.path.exists(abs_completion_file):
                try:
                    with open(abs_completion_file, 'r') as f:
                        last_completion_time = float(f.read().strip())
                    time_since_completion = time.time() - last_completion_time
                    
                    # If completed within last 6hr, skip download
                    if time_since_completion < 21600:  # 6 hours = 21600 seconds
                        if debug_mode:
                            print(f"[DEBUG] ABS downloads completed {time_since_completion:.1f} seconds ago, skipping re-download")
                        result['abs_result'] = {
                            'needs_download': False,
                            'new_items': [],
                            'changed_items': [],
                            'removed_count': 0,
                            'server_offline': False,
                            'error': None,
                            'skipped_recent_completion': True
                        }
                        return result
                except (IOError, ValueError) as e:
                    if debug_mode:
                        print(f"[DEBUG] Could not read ABS completion timestamp: {e}")
            
            abs_headers = get_abs_headers()
            abs_result = smart_check_abs_posters(abs_url, abs_headers)
            result['abs_result'] = abs_result
            
            if abs_result['server_offline']:
                result['any_server_offline'] = True
            
            if abs_result['needs_download']:
                result['abs_needs_download'] = True
                result['total_new'] += len(abs_result['new_items'])
                result['total_changed'] += len(abs_result['changed_items'])
                result['total_removed'] += abs_result['removed_count']
    
    if debug_mode:
        print(f"[DEBUG] Download needs determined: Plex={result['plex_needs_download']}, ABS={result['abs_needs_download']}")
        print(f"[DEBUG] Totals: {result['total_new']} new, {result['total_changed']} changed, {result['total_removed']} removed")
    
    return result

def process_smart_library_download(lib, smart_result):
    """
    Process smart library downloads using pre-determined smart check results.
    
    Args:
        lib: Library dictionary with key and title
        smart_result: Smart check result from smart_check_library_posters
    """
    section_id = lib["key"]
    library_name = lib["title"]
    
    if debug_mode:
        print(f"[DEBUG] Processing smart download for {library_name}: {len(smart_result['new_items'])} new, {len(smart_result['changed_items'])} changed")
    
    # Get Plex credentials
    plex_token = os.getenv("PLEX_TOKEN")
    plex_url = os.getenv("PLEX_URL")
    
    if not plex_token or not plex_url:
        if debug_mode:
            print(f"[ERROR] No Plex credentials available for smart download of {library_name}")
        return
    
    headers = {"X-Plex-Token": plex_token}
    lib_dir = get_library_poster_dir(section_id)
    os.makedirs(lib_dir, exist_ok=True)
    
    # Combine new and changed items
    items_to_download = smart_result['new_items'] + smart_result['changed_items']
    
    if not items_to_download:
        if debug_mode:
            print(f"[DEBUG] No items to download for {library_name}")
        return
    
    # Download items with ThreadPoolExecutor
    successful_downloads = 0
    
    with ThreadPoolExecutor(max_workers=POSTER_DOWNLOAD_LIMITS['max_concurrent_downloads']) as executor:
        futures = []
        for i, item in enumerate(items_to_download):
            future = executor.submit(download_single_poster_with_metadata, item, lib_dir, i, headers)
            futures.append(future)
        
        # Wait for completion and update progress
        for i, future in enumerate(as_completed(futures)):
            if future.result():
                successful_downloads += 1
            
            # Update progress
            with poster_download_lock:
                lib_id = lib["key"]
                if lib_id in poster_download_progress:
                    poster_download_progress[lib_id].update({
                        'current': successful_downloads,
                        'last_update': time.time()
                    })
    
    if debug_mode:
        print(f"[INFO] Smart download for {library_name}: Downloaded {successful_downloads}/{len(items_to_download)} posters")
    
    # Save completion timestamp to prevent unnecessary re-downloads
    try:
        plex_completion_file = os.path.join(lib_dir, ".last_completion")
        with open(plex_completion_file, 'w') as f:
            f.write(str(time.time()))
        if debug_mode:
            print(f"[DEBUG] Saved Plex completion timestamp for library {section_id} to {plex_completion_file}")
    except Exception as e:
        if debug_mode:
            print(f"[DEBUG] Could not save Plex completion timestamp for library {section_id}: {e}")

def process_smart_abs_download(smart_result):
    """
    Process smart ABS downloads using pre-determined smart check results.
    
    Args:
        smart_result: Smart check result from smart_check_abs_posters
    """
    if debug_mode:
        print(f"[DEBUG] Processing smart ABS download: {len(smart_result['new_items'])} new, {len(smart_result['changed_items'])} changed")
    
    # Get ABS credentials
    abs_url = os.getenv("AUDIOBOOKSHELF_URL")
    if not abs_url:
        if debug_mode:
            print("[ERROR] No ABS URL available for smart download")
        return
    
    headers = get_abs_headers()
    audiobook_dir = os.path.join("static", "posters", "audiobooks")
    os.makedirs(audiobook_dir, exist_ok=True)
    
    # Combine new and changed items
    items_to_download = smart_result['new_items'] + smart_result['changed_items']
    
    if not items_to_download:
        if debug_mode:
            print("[DEBUG] No ABS items to download")
        return
    
    # Download items
    successful_downloads = 0
    
    for item in items_to_download:
        try:
            library_id = item['library_id']
            book_id = item['book_id']
            book = item['book']
            
            # Download the book poster
            if download_abs_book_poster(abs_url, book, library_id, audiobook_dir, successful_downloads, headers):
                successful_downloads += 1
        except Exception as e:
            if debug_mode:
                print(f"[ERROR] Failed to download ABS poster for book {item.get('book_id', 'unknown')}: {e}")
    
    if debug_mode:
        print(f"[INFO] Smart ABS download: Downloaded {successful_downloads}/{len(items_to_download)} posters")
    
    # Save completion timestamp to prevent unnecessary re-downloads
    try:
        abs_completion_file = os.path.join(audiobook_dir, ".last_completion")
        with open(abs_completion_file, 'w') as f:
            f.write(str(time.time()))
        if debug_mode:
            print(f"[DEBUG] Saved ABS completion timestamp to {abs_completion_file}")
    except Exception as e:
        if debug_mode:
            print(f"[DEBUG] Could not save ABS completion timestamp: {e}")

def should_refresh_posters(library_id, incremental_mode=False):
    """
    Check if posters for a library need refreshing based on age or missing metadata.
    Returns True if posters should be refreshed, False otherwise.
    
    Args:
        library_id: The library ID to check
        incremental_mode: If True, only check for missing metadata, not age
    """
    poster_dir = get_library_poster_dir(library_id)
    if not os.path.exists(poster_dir):
        return True
    
    # Check if any poster files exist
    poster_files = [f for f in os.listdir(poster_dir) if f.lower().endswith(('.webp', '.jpg', '.jpeg', '.png'))]
    if not poster_files:
        return True
    
    # Check for missing metadata files - if any poster is missing metadata, refresh is needed
    for poster_file in poster_files:
        if poster_file.startswith('poster_') and poster_file.endswith('.webp'):
            meta_file = poster_file.replace('.webp', '.json')
            meta_path = os.path.join(poster_dir, meta_file)
            if not os.path.exists(meta_path):
                if debug_mode:
                    print(f"[DEBUG] Missing metadata for {poster_file}, triggering refresh for library {library_id}")
                return True
    
    # In incremental mode, don't check age - only refresh if metadata is missing
    if incremental_mode:
        return False
    
    # Check the age of the most recent poster file
    most_recent_time = max(os.path.getmtime(os.path.join(poster_dir, f)) for f in poster_files)
    current_time = time.time()
    
    # Return True if posters are older than POSTER_REFRESH_INTERVAL
    return (current_time - most_recent_time) > POSTER_REFRESH_INTERVAL

def get_existing_poster_rating_keys(library_id):
    """
    Get a set of rating keys for existing posters in a library.
    
    Args:
        library_id: The library ID to check
        
    Returns:
        set: Set of rating keys for existing posters
    """
    poster_dir = get_library_poster_dir(library_id)
    if not os.path.exists(poster_dir):
        return set()
    
    existing_keys = set()
    for fname in os.listdir(poster_dir):
        if fname.startswith('poster_') and fname.endswith('.webp'):
            # Extract rating key from filename (poster_12345.webp -> 12345)
            rating_key = fname[7:-5]  # Remove 'poster_' prefix and '.webp' suffix
            if rating_key.isdigit():
                existing_keys.add(rating_key)
    
    return existing_keys

def cleanup_deleted_posters(library_id, current_rating_keys):
    """
    Remove posters for items that no longer exist in the Plex library.
    
    Args:
        library_id: The library ID to clean up
        current_rating_keys: Set of rating keys that currently exist in Plex
        
    Returns:
        int: Number of posters removed
    """
    poster_dir = get_library_poster_dir(library_id)
    if not os.path.exists(poster_dir):
        return 0
    
    removed_count = 0
    existing_keys = get_existing_poster_rating_keys(library_id)
    
    # Find keys that exist locally but not in Plex
    deleted_keys = existing_keys - current_rating_keys
    
    for rating_key in deleted_keys:
        poster_file = os.path.join(poster_dir, f"poster_{rating_key}.webp")
        meta_file = os.path.join(poster_dir, f"poster_{rating_key}.json")
        
        # Remove poster file
        if os.path.exists(poster_file):
            try:
                os.remove(poster_file)
                if debug_mode:
                    print(f"[DEBUG] Removed deleted poster: poster_{rating_key}.webp")
                removed_count += 1
            except Exception as e:
                if debug_mode:
                    print(f"[ERROR] Failed to remove poster {poster_file}: {e}")
        
        # Remove metadata file
        if os.path.exists(meta_file):
            try:
                os.remove(meta_file)
                if debug_mode:
                    print(f"[DEBUG] Removed deleted metadata: poster_{rating_key}.json")
            except Exception as e:
                if debug_mode:
                    print(f"[ERROR] Failed to remove metadata {meta_file}: {e}")
    
    if debug_mode and removed_count > 0:
        print(f"[INFO] Cleaned up {removed_count} deleted posters for library {library_id}")
    
    return removed_count

def process_library_posters_incremental(lib, plex_url, headers, background=False):
    """
    Process poster downloads for a single library in incremental mode.
    Only downloads new posters and removes deleted ones.
    
    Args:
        lib: Library dictionary with key and title
        plex_url: Plex server URL
        headers: Request headers with token
        background: Whether running in background mode
        
    Returns:
        tuple: (new_downloads, removed_count)
    """
    section_id = lib["key"]
    library_name = lib["title"]
    
    # Check if posters need refreshing (incremental mode)
    if not should_refresh_posters(section_id, incremental_mode=True):
        if debug_mode:
            print(f"[DEBUG] Skipping incremental poster refresh for {library_name} - no missing metadata")
        return 0, 0
    
    lib_dir = get_library_poster_dir(section_id)
    os.makedirs(lib_dir, exist_ok=True)
    
    try:
        # Fetch library items
        url = f"{plex_url}/library/sections/{section_id}/all"
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        root = ET.fromstring(response.content)
        
        # Collect current items from Plex
        current_items = []
        current_rating_keys = set()
        
        for el in root.findall(".//Video"):
            thumb = el.attrib.get("thumb")
            rating_key = el.attrib.get("ratingKey")
            title = el.attrib.get("title")
            year = el.attrib.get("year")
            if thumb and rating_key:
                current_items.append({"thumb": thumb, "ratingKey": rating_key, "title": title, "year": year})
                current_rating_keys.add(rating_key)
        
        for el in root.findall(".//Directory"):
            thumb = el.attrib.get("thumb")
            rating_key = el.attrib.get("ratingKey")
            title = el.attrib.get("title")
            if thumb and rating_key and not any(i["ratingKey"] == rating_key for i in current_items):
                current_items.append({"thumb": thumb, "ratingKey": rating_key, "title": title})
                current_rating_keys.add(rating_key)
        
        # Clean up deleted posters
        removed_count = cleanup_deleted_posters(section_id, current_rating_keys)
        
        # Get existing poster rating keys
        existing_keys = get_existing_poster_rating_keys(section_id)
        
        # Find new items that need posters
        new_items = []
        for item in current_items:
            if item["ratingKey"] not in existing_keys:
                new_items.append(item)
        
        if debug_mode:
            print(f"[DEBUG] Incremental refresh for {library_name}: {len(new_items)} new items, {removed_count} removed")
        
        if not new_items:
            return 0, removed_count
        
        # Update status to indicate processing has started
        if background:
            with poster_download_lock:
                # Initialize or update progress for this library with library name
                if section_id not in poster_download_progress:
                    poster_download_progress[section_id] = {}
                poster_download_progress[section_id].update({
                    'current': 0,
                    'total': len(new_items),
                    'successful': 0,
                    'status': 'processing_incremental',
                    'library_name': library_name,
                    'last_update': time.time()
                })
                
                # Update unified progress for Plex downloads
                if 'unified' in poster_download_progress and poster_download_progress['unified']['status'] == 'plex_downloading':
                    # Calculate overall progress across all libraries
                    total_libraries = poster_download_progress['unified'].get('total', 1)
                    current_library = poster_download_progress['unified'].get('current', 0)
                    poster_download_progress['unified']['message'] = f'Downloading posters for {library_name}...'
        
        # Download new posters with ThreadPoolExecutor
        successful_downloads = 0
        
        with ThreadPoolExecutor(max_workers=POSTER_DOWNLOAD_LIMITS['max_concurrent_downloads']) as executor:
            futures = []
            for i, item in enumerate(new_items):
                future = executor.submit(download_single_poster_with_metadata, item, lib_dir, i, headers)
                futures.append(future)
            
            # Wait for completion with progress tracking
            for i, future in enumerate(as_completed(futures)):
                if future.result():
                    successful_downloads += 1
                if background and i % 5 == 0:  # Update progress every 5 items
                    with poster_download_lock:
                        if section_id in poster_download_progress:
                            poster_download_progress[section_id].update({
                                'current': i + 1,
                                'total': len(new_items),
                                'successful': successful_downloads,
                                'status': 'processing_incremental',
                                'library_name': library_name,
                                'last_update': time.time()
                            })
                        
                        # Update unified progress for Plex downloads
                        if 'unified' in poster_download_progress and poster_download_progress['unified']['status'] == 'plex_downloading':
                            poster_download_progress['unified']['message'] = f'Downloading {library_name} ({i + 1}/{len(new_items)})'
        
        if debug_mode:
            print(f"[INFO] Incremental refresh for {library_name}: Downloaded {successful_downloads}/{len(new_items)} new posters, removed {removed_count} deleted posters")
        
        # Clear progress for this library when complete
        with poster_download_lock:
            if section_id in poster_download_progress:
                del poster_download_progress[section_id]
        
        return successful_downloads, removed_count
        
    except Exception as e:
        if debug_mode:
            print(f"Error in incremental poster refresh for section {section_id}: {e}")
        return 0, 0

def should_refresh_abs_posters():
    """
    Check if ABS audiobook posters need refreshing based on age.
    Returns True if posters should be refreshed, False otherwise.
    """
    audiobook_dir = os.path.join("static", "posters", "audiobooks")
    if not os.path.exists(audiobook_dir):
        if debug_mode:
            print("[DEBUG] ABS poster directory does not exist, refresh needed")
        return True
    
    # Check if any poster files exist
    poster_files = [f for f in os.listdir(audiobook_dir) if f.lower().endswith(('.webp', '.jpg', '.jpeg', '.png'))]
    if not poster_files:
        if debug_mode:
            print("[DEBUG] No ABS poster files found, refresh needed")
        return True
    
    # Check the age of the most recent poster file
    most_recent_time = max(os.path.getmtime(os.path.join(audiobook_dir, f)) for f in poster_files)
    current_time = time.time()
    age_hours = (current_time - most_recent_time) / 3600
    
    # Return True if posters are older than POSTER_REFRESH_INTERVAL
    needs_refresh = (current_time - most_recent_time) > POSTER_REFRESH_INTERVAL
    
    if debug_mode:
        print(f"[DEBUG] ABS posters age: {age_hours:.1f} hours, refresh needed: {needs_refresh}")
    
    return needs_refresh

def clear_library_cache():
    """Clear the library cache to force fresh data on next request"""
    global library_cache, library_cache_timestamp
    with library_cache_lock:
        library_cache = {}
        library_cache_timestamp = 0
    if debug_mode:
        print("[DEBUG] Library cache cleared")

def cleanup_library_cache():
    """Clean up library cache to prevent memory leaks"""
    global library_cache, library_cache_timestamp
    
    with library_cache_lock:
        # If cache is too large, clear it
        if len(library_cache) > 100:  # More than 100 libraries cached
            library_cache = {}
            if debug_mode:
                print("[DEBUG] Library cache cleared due to size limit")
        
        # Clear cache if it's older than 1 hour
        current_time = time.time()
        if library_cache_timestamp > 0 and (current_time - library_cache_timestamp) > 3600:
            library_cache = {}
            library_cache_timestamp = 0
            if debug_mode:
                print("[DEBUG] Library cache cleared due to age")

def fix_missing_metadata_files():
    """Check for and fix missing metadata files for existing posters"""
    try:
        if debug_mode:
            print("[DEBUG] Checking for missing metadata files...")
        
        # Get Plex credentials
        plex_token = os.getenv("PLEX_TOKEN")
        plex_url = os.getenv("PLEX_URL")
        
        if not plex_token or not plex_url:
            if debug_mode:
                print("[ERROR] Plex credentials not available for metadata fix")
            return False
        
        headers = {"X-Plex-Token": plex_token}
        fixed_count = 0
        
        # Check each library directory
        for lib_dir in ["posters/movies", "posters/shows"]:
            if not os.path.exists(lib_dir):
                continue
    
            if debug_mode:
                print(f"[DEBUG] Checking library directory: {lib_dir}")
            
            # Find all poster files
            poster_files = [f for f in os.listdir(lib_dir) if f.endswith('.webp')]
            
            for poster_file in poster_files:
                # Extract rating key from filename
                if poster_file.startswith('poster_') and poster_file.endswith('.webp'):
                    rating_key = poster_file[7:-5]  # Remove 'poster_' prefix and '.webp' suffix
                    meta_file = poster_file.replace('.webp', '.json')
                    meta_path = os.path.join(lib_dir, meta_file)
                    
                    # If metadata file is missing, try to recreate it
                    if not os.path.exists(meta_path):
                        if debug_mode:
                            print(f"[DEBUG] Missing metadata for poster: {poster_file}, ratingKey: {rating_key}")
                        
                        try:
                            # Try to fetch metadata from Plex
                            meta_url = f"{plex_url}/library/metadata/{rating_key}"
                            meta_resp = requests.get(meta_url, headers=headers, timeout=10)
                            
                            if meta_resp.status_code == 200:
                                meta_root = ET.fromstring(meta_resp.content)
                                
                                # Extract basic info
                                title_elem = meta_root.find(".//title")
                                year_elem = meta_root.find(".//year")
                                
                                title = title_elem.text if title_elem is not None else f"Unknown_{rating_key}"
                                year = year_elem.text if year_elem is not None else None
                                
                                # Extract GUIDs
                                guids = {"imdb": None, "tmdb": None, "tvdb": None}
                                for guid in meta_root.findall(".//Guid"):
                                    gid = guid.attrib.get("id", "")
                                    if gid.startswith("imdb://"):
                                        guids["imdb"] = gid.replace("imdb://", "")
                                    elif gid.startswith("tmdb://"):
                                        guids["tmdb"] = gid.replace("tmdb://", "")
                                    elif gid.startswith("tvdb://"):
                                        guids["tvdb"] = gid.replace("tvdb://", "")
                                
                                # Create metadata
                                meta = {
                                    "title": title,
                                    "ratingKey": rating_key,
                                    "year": year,
                                    "imdb": guids["imdb"],
                                    "tmdb": guids["tmdb"],
                                    "tvdb": guids["tvdb"],
                                    "poster": poster_file
                                }
                                
                                # Save metadata
                                with open(meta_path, "w", encoding="utf-8") as f:
                                    json.dump(meta, f, indent=2)
                                
                                fixed_count += 1
                                if debug_mode:
                                    print(f"[DEBUG] Fixed metadata for: {title} (ratingKey: {rating_key})")
                            
                        except Exception as e:
                            if debug_mode:
                                print(f"[ERROR] Failed to fix metadata for {poster_file}: {e}")
        
        if debug_mode:
            print(f"[DEBUG] Metadata fix complete. Fixed {fixed_count} missing metadata files.")
        
        return fixed_count > 0
        
    except Exception as e:
        if debug_mode:
            print(f"[ERROR] Error in fix_missing_metadata_files: {e}")
        return False

def load_library_notes():
    if debug_mode:
        print("[DEBUG] Loading library notes from file...")
    notes = load_json_file("library_notes.json", {})
    if debug_mode:
        print(f"[DEBUG] Loaded {len(notes)} library notes from file")
        if notes:
            print(f"[DEBUG] Library note keys: {list(notes.keys())}")
    
    # Only load from file - no API calls
    # Missing titles should be handled by recreate_library_notes() during setup/admin actions
    return notes

def save_library_notes(notes):
    print(f"[DEBUG] save_library_notes called with: {notes}")
    result = save_json_file("library_notes.json", notes)
    print(f"[DEBUG] save_json_file result: {result}")
    return result

def load_section7_content():
    """Load section 7 content from JSON file"""
    if debug_mode:
        print("[DEBUG] Loading section 7 content from file...")
    content = load_json_file("section7_content.json", {})
    if debug_mode:
        print(f"[DEBUG] Loaded section 7 content: {content}")
    
    # Set defaults if file is empty or missing fields
    if not content:
        content = {
            "personal_message": "Why did I do all this? I started out collecting all the Star Trek shows because they kept jumping around to different streaming services. At some point I joined r/datahoarder and now I have about 10TB of movies, shows, music, and books. And I wanted to share! So enjoy. 🖖",
            "payment_services": [
                {"title": "Venmo", "handle": "your-venmo"},
                {"title": "Cashapp", "handle": "your-cashapp"},
                {"title": "Zelle", "handle": "your-zelle"}
            ]
        }
    elif "payment_services" not in content:
        content["payment_services"] = [
            {"title": "Venmo", "handle": "your-venmo"},
            {"title": "Cashapp", "handle": "your-cashapp"},
            {"title": "Zelle", "handle": "your-zelle"}
        ]
    elif "personal_message" not in content:
        content["personal_message"] = "Why did I do all this? I started out collecting all the Star Trek shows because they kept jumping around to different streaming services. At some point I joined r/datahoarder and now I have about 10TB of movies, shows, music, and books. And I wanted to share! So enjoy. 🖖"
    
    return content

def save_section7_content(content):
    """Save section 7 content to JSON file"""
    print(f"[DEBUG] save_section7_content called with: {content}")
    result = save_json_file("section7_content.json", content)
    print(f"[DEBUG] save_json_file result: {result}")
    return result

def recreate_library_notes():
    """Update library notes on startup by fetching current library information from Plex, preserving existing descriptions"""
    try:
        plex_token = os.getenv("PLEX_TOKEN")
        plex_url = os.getenv("PLEX_URL")
        
        if not plex_token or not plex_url:
            if debug_mode:
                print("[DEBUG] Plex token or URL not configured, skipping library notes update")
            return
        
        if debug_mode:
            print("[INFO] Updating library notes from Plex API...")
        
        # Load existing library notes to preserve descriptions
        existing_notes = load_library_notes()
        
        # Get selected library IDs from environment
        selected_ids_str = os.getenv("LIBRARY_IDS", "")
        selected_ids = []
        if selected_ids_str:
            # Split by comma and clean up whitespace
            selected_ids = [id.strip() for id in selected_ids_str.split(",") if id.strip()]
        
        if debug_mode:
            print(f"[DEBUG] Selected library IDs from environment: {selected_ids}")
        
        headers = {"X-Plex-Token": plex_token}
        updated_count = 0
        
        # Only fetch selected libraries individually to avoid processing unselected ones
        for lib_id in selected_ids:
            url = f"{plex_url}/library/sections/{lib_id}"
            try:
                timeout = config.get_int("GENERAL_API_TIMEOUT", 5)
                response = requests.get(url, headers=headers, timeout=timeout)
                response.raise_for_status()
                root = ET.fromstring(response.text)
                
                directory = root.find(".//Directory")
                if directory is not None:
                    title = directory.attrib.get("title")
                    key = directory.attrib.get("key")
                    media_type = directory.attrib.get("type")
                    
                    if title and key:
                        # Check if this library exists in our notes
                        if key in existing_notes:
                            # Update existing entry, preserving description
                            existing_entry = existing_notes[key]
                            existing_entry["title"] = title
                            existing_entry["media_type"] = media_type
                            # Keep existing description if it exists
                            if debug_mode:
                                print(f"[DEBUG] Updated existing library: {title} (ID: {key}, Type: {media_type})")
                        else:
                            # Create new entry
                            existing_notes[key] = {
                                "title": title,
                                "media_type": media_type
                            }
                            if debug_mode:
                                print(f"[DEBUG] Added new library: {title} (ID: {key}, Type: {media_type})")
                        
                        updated_count += 1
                        
            except Exception as e:
                if debug_mode:
                    print(f"[WARN] Failed to fetch library {lib_id}: {e}")
                continue
        
        # Save the updated library notes
        save_library_notes(existing_notes)
        
        if debug_mode:
            print(f"[INFO] Successfully updated library notes for {updated_count} libraries")
            
    except Exception as e:
        if debug_mode:
            print(f"[WARN] Failed to update library notes: {e}")

def safe_set_key(env_path, key, value):
    set_key(env_path, key, value, quote_mode="never")

def process_uploaded_logo(file):
    """Process uploaded logo file and create favicon"""
    if not file or file.filename == '':
        return False
    
    # Check file extension
    allowed_extensions = {'.png', '.webp', '.jpg', '.jpeg'}
    file_ext = os.path.splitext(file.filename)[1].lower()
    if file_ext not in allowed_extensions:
        return False
    
    try:
        # Open image with PIL
        img = Image.open(file.stream)
        
        # Handle different image modes properly
        if img.mode == 'P':
            # Convert palette images to RGBA to preserve transparency
            img = img.convert('RGBA')
        elif img.mode == 'LA':
            # Convert grayscale with alpha to RGBA
            img = img.convert('RGBA')
        elif img.mode == 'L':
            # Convert grayscale to RGB (no transparency)
            img = img.convert('RGB')
        elif img.mode == 'RGB':
            # RGB is fine as-is
            pass
        elif img.mode == 'RGBA':
            # RGBA is fine as-is (preserves transparency)
            pass
        else:
            # Convert any other modes to RGB
            img = img.convert('RGB')
        
        # Save logo based on original format
        logo_path = os.path.join('static', 'clearlogo.webp')
        if file_ext in ['.png', '.webp']:
            # For PNG and WebP, preserve original format and transparency
            if file_ext == '.png':
                logo_path = os.path.join('static', 'clearlogo.png')
                # Preserve transparency for PNG
                if img.mode == 'RGBA':
                    img.save(logo_path, 'PNG')
                else:
                    img.save(logo_path, 'PNG')
            else:  # .webp
                # Preserve transparency for WebP
                if img.mode == 'RGBA':
                    img.save(logo_path, 'WEBP', lossless=True)
                else:
                    img.save(logo_path, 'WEBP', quality=95)
        else:
            # For JPG/JPEG, convert to WebP (no transparency support)
            if img.mode == 'RGBA':
                # Convert RGBA to RGB for JPEG compatibility
                rgb_img = Image.new('RGB', img.size, (255, 255, 255))
                rgb_img.paste(img, mask=img.split()[-1])  # Use alpha channel as mask
                rgb_img.save(logo_path, 'WEBP', quality=95)
            else:
                img.save(logo_path, 'WEBP', quality=95)
        
        # Create favicon (32x32) - preserve transparency if available
        favicon = img.resize((32, 32), Image.Resampling.LANCZOS)
        favicon_path = os.path.join('static', 'favicon.webp')
        if favicon.mode == 'RGBA':
            favicon.save(favicon_path, 'WEBP', lossless=True)
        else:
            favicon.save(favicon_path, 'WEBP', quality=95)
        
        return True
    except Exception as e:
        if debug_mode:
            print(f"Error processing logo: {e}")
        return False

def get_logo_filename():
    """Get the current logo filename (could be PNG or WebP)"""
    if os.path.exists(os.path.join('static', 'clearlogo.png')):
        return 'clearlogo.png'
    elif os.path.exists(os.path.join('static', 'clearlogo.webp')):
        return 'clearlogo.webp'
    else:
        return 'clearlogo.webp'  # default fallback

def get_wordmark_filename():
    """Get the current wordmark filename (could be PNG or WebP)"""
    if os.path.exists(os.path.join('static', 'wordmark.png')):
        return 'wordmark.png'
    elif os.path.exists(os.path.join('static', 'wordmark.webp')):
        return 'wordmark.webp'
    else:
        return 'wordmark.webp'  # default fallback

def process_uploaded_wordmark(file):
    """Process uploaded wordmark file"""
    if not file or file.filename == '':
        return False
    
    # Check file extension
    allowed_extensions = {'.png', '.webp', '.jpg', '.jpeg'}
    file_ext = os.path.splitext(file.filename)[1].lower()
    if file_ext not in allowed_extensions:
        return False
    
    try:
        # Open image with PIL
        img = Image.open(file.stream)
        
        # Handle different image modes properly
        if img.mode == 'P':
            # Convert palette images to RGBA to preserve transparency
            img = img.convert('RGBA')
        elif img.mode == 'LA':
            # Convert grayscale with alpha to RGBA
            img = img.convert('RGBA')
        elif img.mode == 'L':
            # Convert grayscale to RGB (no transparency)
            img = img.convert('RGB')
        elif img.mode == 'RGB':
            # RGB is fine as-is
            pass
        elif img.mode == 'RGBA':
            # RGBA is fine as-is (preserves transparency)
            pass
        else:
            # Convert any other modes to RGB
            img = img.convert('RGB')
        
        # Save wordmark based on original format
        wordmark_path = os.path.join('static', 'wordmark.webp')
        if file_ext in ['.png', '.webp']:
            # For PNG and WebP, preserve original format and transparency
            if file_ext == '.png':
                wordmark_path = os.path.join('static', 'wordmark.png')
                # Preserve transparency for PNG
                if img.mode == 'RGBA':
                    img.save(wordmark_path, 'PNG')
                else:
                    img.save(wordmark_path, 'PNG')
            else:  # .webp
                # Preserve transparency for WebP
                if img.mode == 'RGBA':
                    img.save(wordmark_path, 'WEBP', lossless=True)
                else:
                    img.save(wordmark_path, 'WEBP', quality=95)
        else:
            # For JPG/JPEG, convert to WebP (no transparency support)
            if img.mode == 'RGBA':
                # Convert RGBA to RGB for JPEG compatibility
                rgb_img = Image.new('RGB', img.size, (255, 255, 255))
                rgb_img.paste(img, mask=img.split()[-1])  # Use alpha channel as mask
                rgb_img.save(wordmark_path, 'WEBP', quality=95)
            else:
                img.save(wordmark_path, 'WEBP', quality=95)
        
        return True
    except Exception as e:
        if debug_mode:
            print(f"Error processing wordmark: {e}")
        return False


def send_discord_notification(email, service_type, event_type=None):
    """Send Discord notification for form submissions, respecting notification toggles"""
    # Notification toggles
    if event_type == "plex" and not config.get_bool("DISCORD_NOTIFY_PLEX", True):
        return
    if event_type == "abs" and not config.get_bool("DISCORD_NOTIFY_ABS", True):
        return
    
    webhook_url = config.get("DISCORD_WEBHOOK")
    if not config.validate_url(webhook_url, "DISCORD_WEBHOOK"):
        return
    
    username = config.get("DISCORD_USERNAME", "Onboarderr")
    avatar_url = config.get("DISCORD_AVATAR", url_for('static', filename=get_logo_filename(), _external=True))
    color = config.get("DISCORD_COLOR", "#000000")
    
    # Get Onboarderr URL for admin link
    onboarderr_url = config.get("ONBOARDERR_URL", "")
    
    # Build title and description with emojis and proper admin links
    if event_type == "plex":
        title = "📺 New Plex Access Request"
        description = f"**{email}** has requested access to **Plex**"
        if onboarderr_url:
            # Link to Plex requests admin section
            admin_link = f"{onboarderr_url}/services#plex-requests-section"
            description += f"\n\n[🔧 **Manage Plex Requests**]({admin_link})"
    elif event_type == "abs":
        title = "📚 New Audiobookshelf Access Request"
        description = f"**{email}** has requested access to **Audiobookshelf**"
        if onboarderr_url:
            # Link to Audiobookshelf requests admin section
            admin_link = f"{onboarderr_url}/services#audiobookshelf-requests-section"
            description += f"\n\n[🔧 **Manage Audiobookshelf Requests**]({admin_link})"
    elif event_type == "security":
        # Handle security reports
        title = "📊 Security Report"
        description = f"{email}"  # email parameter contains the report message
        if onboarderr_url:
            # Add generic admin link for security reports
            admin_link = f"{onboarderr_url}/services"
            description += f"\n\n[🔧 **View Admin Panel**]({admin_link})"
    else:
        # Fallback for other service types
        title = f"🔗 New {service_type} Access Request"
        description = f"**{email}** has requested access to **{service_type}**"
        if onboarderr_url:
            # Add generic admin link
            admin_link = f"{onboarderr_url}/services"
            description += f"\n\n[🔧 **Manage Users**]({admin_link})"
    
    # Create payload for all cases
    payload = {
        "username": username,
        "embeds": [{
            "title": title,
            "description": description,
            "color": int(color.lstrip('#'), 16) if color.startswith('#') else 0,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }]
    }
    if avatar_url:
        payload["avatar_url"] = avatar_url
    try:
        # Apply rate limiting for Discord API
        check_api_rate_limit('discord')
        
        timeout = config.get_int("DISCORD_API_TIMEOUT", 5)
        requests.post(webhook_url, json=payload, timeout=timeout)
    except Exception as e:
        if debug_mode:
            print(f"Failed to send Discord notification: {e}")

def send_security_discord_notification(event_type, ip, details):
    """Send Discord notification for security events, respecting notification toggles"""
    # Check if Discord notifications are enabled for this event type
    if event_type == "rate_limited" and not config.get_bool("DISCORD_NOTIFY_RATE_LIMITING", False):
        return
    if event_type in ["ip_whitelisted", "ip_whitelist_removed", "ip_banned", "ip_blacklist_removed"] and not config.get_bool("DISCORD_NOTIFY_IP_MANAGEMENT", False):
        return
    if event_type in ["login_success", "login_failed", "login_lockout"] and not config.get_bool("DISCORD_NOTIFY_LOGIN_ATTEMPTS", False):
        return
    if event_type == "form_rate_limited" and not config.get_bool("DISCORD_NOTIFY_FORM_RATE_LIMITING", False):
        return
    if event_type == "first_access" and not config.get_bool("DISCORD_NOTIFY_FIRST_ACCESS", False):
        return
    
    webhook_url = config.get("DISCORD_WEBHOOK")
    if not config.validate_url(webhook_url, "DISCORD_WEBHOOK"):
        return
    
    username = config.get("DISCORD_USERNAME", "Onboarderr Security")
    avatar_url = config.get("DISCORD_AVATAR", url_for('static', filename=get_logo_filename(), _external=True))
    color = config.get("DISCORD_COLOR", "#ff0000")  # Red for security events
    
    # Get Onboarderr URL for admin link
    onboarderr_url = config.get("ONBOARDERR_URL", "")
    
    # Build description with optional admin link
    description = f"**Security Event:** {event_type.replace('_', ' ').title()}\n**IP:** {ip}\n**Details:** {details}"
    if onboarderr_url:
        # Add linked text to admin page
        admin_link = f"{onboarderr_url}/services"
        description += f"\n\n[🔧 **View Admin Panel**]({admin_link})"
    
    payload = {
        "username": username,
        "embeds": [{
            "title": "🚨 Security Alert",
            "description": description,
            "color": int(color.lstrip('#'), 16) if color.startswith('#') else 0,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }]
    }
    if avatar_url:
        payload["avatar_url"] = avatar_url
    
    try:
        # Apply rate limiting for Discord API
        check_api_rate_limit('discord')
        
        timeout = config.get_int("DISCORD_API_TIMEOUT", 5)
        requests.post(webhook_url, json=payload, timeout=timeout)
    except Exception as e:
        if debug_mode:
            print(f"Failed to send security Discord notification: {e}")

def create_abs_user(username, password, user_type="user", permissions=None):
    """Create a user in Audiobookshelf using the API"""
    abs_url = config.get("AUDIOBOOKSHELF_URL")
    abs_token = config.get("AUDIOBOOKSHELF_TOKEN")
    
    if not config.validate_url(abs_url, "AUDIOBOOKSHELF_URL"):
        return {"success": False, "error": "Invalid Audiobookshelf URL"}
    
    if not config.validate_token(abs_token, "AUDIOBOOKSHELF_TOKEN"):
        return {"success": False, "error": "Invalid Audiobookshelf API token"}
    
    # Validate inputs
    if not username or not password:
        return {"success": False, "error": "Username and password are required"}
    
    if user_type not in ["user", "admin", "guest"]:
        return {"success": False, "error": "Invalid user type. Must be 'user', 'admin', or 'guest'"}
    
    # Default permissions based on user type
    if permissions is None:
        if user_type == "admin":
            permissions = {
                "download": True,
                "update": True,
                "delete": True,
                "upload": True,
                "accessAllLibraries": True,
                "accessAllTags": True,
                "accessExplicitContent": True
            }
        elif user_type == "user":
            permissions = {
                "download": True,
                "update": True,
                "delete": False,
                "upload": False,
                "accessAllLibraries": True,
                "accessAllTags": True,
                "accessExplicitContent": True
            }
        else:  # guest
            permissions = {
                "download": False,
                "update": False,
                "delete": False,
                "upload": False,
                "accessAllLibraries": True,
                "accessAllTags": True,
                "accessExplicitContent": False
            }
    
    # Prepare the user data
    user_data = {
        "username": username,
        "password": password,
        "type": user_type,
        "permissions": permissions,
        "librariesAccessible": [],
        "itemTagsAccessible": [],
        "isActive": True,
        "isLocked": False
    }
    
    try:
        headers = {
            "Authorization": f"Bearer {abs_token}",
            "Content-Type": "application/json"
        }
        
        timeout = config.get_int("ABS_API_TIMEOUT", 10)
        response = requests.post(
            f"{abs_url}/api/users",
            headers=headers,
            json=user_data,
            timeout=timeout
        )
        
        if response.status_code == 200:
            user_info = response.json()
            return {
                "success": True,
                "user_id": user_info.get("id"),
                "username": username,
                "email": "",  # Will be filled by caller
                "message": "User created successfully"
            }
        elif response.status_code == 500:
            # Check if it's a username already taken error
            try:
                error_data = response.json()
                if "username" in error_data.get("error", "").lower():
                    return {
                        "success": False,
                        "username": username,
                        "email": "",  # Will be filled by caller
                        "error": "Username already exists"
                    }
            except:
                pass
            return {
                "success": False,
                "username": username,
                "email": "",  # Will be filled by caller
                "error": f"Server error: {response.text}"
            }
        else:
            error_msg = "Unknown error"
            try:
                error_data = response.json()
                error_msg = error_data.get("error", error_data.get("message", "Unknown error"))
            except:
                error_msg = f"HTTP {response.status_code}: {response.text}"
            
            return {
                "success": False,
                "username": username,
                "email": "",  # Will be filled by caller
                "error": error_msg
            }
            
    except requests.exceptions.RequestException as e:
        return {
            "success": False,
            "username": username,
            "email": "",  # Will be filled by caller
            "error": f"Connection error: {str(e)}"
        }
    except Exception as e:
        return {
            "success": False,
            "username": username,
            "email": "",  # Will be filled by caller
            "error": f"Unexpected error: {str(e)}"
        }

@app.route("/onboarding", methods=["GET", "POST"])
def onboarding():
    if debug_mode:
        print("[DEBUG] Onboarding route accessed")
    if not session.get("authenticated"):
        if debug_mode:
            print("[DEBUG] User not authenticated, redirecting to login")
        # Use client-side redirect to preserve hash fragments
        return render_template_string("""
            <!DOCTYPE html>
            <html>
            <head><title>Redirecting...</title></head>
            <body>
                <script>
                    sessionStorage.setItem('intended_url_after_login', window.location.href);
                    window.location.href = '/login';
                </script>
            </body>
            </html>
        """)
    
    # Check for first-time IP access
    client_ip = get_client_ip()
    check_first_time_ip_access(client_ip)

    submitted = False
    library_notes = load_library_notes()
    selected_ids = [id.strip() for id in config.get("LIBRARY_IDS", "").split(",") if id.strip()]

    if request.method == "POST":
        # Get client IP for rate limiting
        client_ip = get_client_ip()
        
        # Check form submission rate limiting
        is_rate_limited, remaining_time = check_rate_limit(client_ip, "form_submission", "plex")
        if is_rate_limited:
            time_remaining = format_time_remaining(remaining_time)
            log_security_event("form_rate_limited", client_ip, f"Plex form submission rate limited, {time_remaining} remaining")
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"success": False, "error": f"Too many submissions. Please try again in {time_remaining}."})
            else:
                context = get_template_context()
                context.update({
                    "error": f"Too many submissions. Please try again in {time_remaining}.",
                    "section7_content": load_section7_content()
                })
                return render_template("onboarding.html", **context)
        
        email = request.form.get("email")
        selected_keys = request.form.getlist("libraries")
        explicit_content = request.form.get("explicit_content") == "yes"

        # Validate email
        if not config.validate_email(email):
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"success": False, "error": "Invalid email address."})
            else:
                context = get_template_context()
                context.update({
                    "error": "Invalid email address.",
                    "section7_content": load_section7_content()
                })
                return render_template("onboarding.html", **context)

        # Check for duplicate email
        submissions = load_json_file("plex_submissions.json", [])
        existing_emails = [submission.get("email", "").lower() for submission in submissions]
        if email.lower() in existing_emails:
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"success": False, "error": "This email has already been submitted."})
            else:
                context = get_template_context()
                context.update({
                    "error": "This email has already been submitted.",
                    "section7_content": load_section7_content()
                })
                return render_template("onboarding.html", **context)

        if email and selected_keys:
            all_libraries = get_libraries_from_local_files()  # Use local files for form submission
            key_to_title = {lib["key"]: lib["title"] for lib in all_libraries}
            selected_titles = [key_to_title.get(key, f"Unknown ({key})") for key in selected_keys]
            submission_entry = {
                "email": email,
                "libraries_keys": selected_keys,
                "libraries_titles": selected_titles,
                "explicit_content": explicit_content,
                "submitted_at": datetime.now(timezone.utc).isoformat() + "Z"
            }
            submissions = load_json_file("plex_submissions.json", [])
            submissions.append(submission_entry)
            save_json_file("plex_submissions.json", submissions)
            submitted = True
            
                    # Record successful form submission
        add_form_submission(client_ip, "plex")
        
        # No need to clear cache since we're using local files now
        
        send_discord_notification(email, "Plex", event_type="plex")
        # AJAX response
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": True})
        # AJAX error response
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": False, "error": "Missing required fields."})
        else:
            context = get_template_context()
            context.update({
                "error": "Missing required fields.",
                "section7_content": load_section7_content()
            })
            return render_template("onboarding.html", **context)

    # Initialize variables to prevent UnboundLocalError
    available_libraries = []
    carousel_libraries = []
    all_libraries = []
    
    try:
        # Get all libraries from local files only (no Plex API calls for onboarding)
        all_libraries = get_libraries_from_local_files()
        
        # Filter libraries for access requests (only selected ones from LIBRARY_IDS)
        # Convert both sides to strings to ensure proper comparison
        selected_ids_str = [str(id).strip() for id in selected_ids]
        available_libraries = [lib for lib in all_libraries if str(lib["key"]) in selected_ids_str]
        
        # Get libraries for carousel display (filtered by carousel settings)
        carousel_libraries = available_libraries.copy()
        library_carousels = config.get("LIBRARY_CAROUSELS", "")
        if library_carousels:
            # Only show libraries that have carousels enabled for carousel display
            carousel_ids = [str(id).strip() for id in library_carousels.split(",") if str(id).strip()]
            carousel_libraries = [lib for lib in available_libraries if str(lib["key"]) in carousel_ids]
        
        # Apply custom carousel tab order if specified
        library_carousel_order = config.get("LIBRARY_CAROUSEL_ORDER", "")
        if library_carousel_order and carousel_libraries:
            # Get the custom order of library IDs
            custom_order_ids = [str(id).strip() for id in library_carousel_order.split(",") if str(id).strip()]
            
            # Filter out non-existing library IDs and create ordered list
            ordered_libraries = []
            for lib_id in custom_order_ids:
                matching_lib = next((lib for lib in carousel_libraries if str(lib["key"]) == lib_id), None)
                if matching_lib:
                    ordered_libraries.append(matching_lib)
            
            # Add any remaining libraries that weren't in the custom order
            remaining_libs = [lib for lib in carousel_libraries if str(lib["key"]) not in custom_order_ids]
            ordered_libraries.extend(remaining_libs)
            
            # Update carousel_libraries with the custom order
            carousel_libraries = ordered_libraries
        
        # Order libraries for the "Select Libraries" section:
        # 1. Libraries with carousels (in carousel tab order)
        # 2. Libraries without carousels (in A-Z order)
        
        # Get carousel library IDs
        carousel_ids = set()
        if library_carousels:
            carousel_ids = {str(id).strip() for id in library_carousels.split(",") if str(id).strip()}
        
        # Create a mapping of library keys to their carousel status from all_libraries
        library_carousel_status = {}
        for lib in all_libraries:
            library_carousel_status[str(lib["key"])] = str(lib["key"]) in carousel_ids
        
        # Separate available libraries with and without carousels
        libraries_with_carousels = []
        libraries_without_carousels = []
        
        for lib in available_libraries:
            if library_carousel_status.get(str(lib["key"]), False):
                libraries_with_carousels.append(lib)
            else:
                libraries_without_carousels.append(lib)
        
        # Apply carousel tab order to libraries with carousels
        if library_carousel_order and libraries_with_carousels:
            custom_order_ids = [str(id).strip() for id in library_carousel_order.split(",") if str(id).strip()]
            
            # Create ordered list based on custom order
            ordered_carousel_libraries = []
            for lib_id in custom_order_ids:
                matching_lib = next((lib for lib in libraries_with_carousels if str(lib["key"]) == lib_id), None)
                if matching_lib:
                    ordered_carousel_libraries.append(matching_lib)
            
            # Add any remaining carousel libraries that weren't in the custom order
            remaining_carousel_libs = [lib for lib in libraries_with_carousels if str(lib["key"]) not in custom_order_ids]
            ordered_carousel_libraries.extend(remaining_carousel_libs)
            
            libraries_with_carousels = ordered_carousel_libraries
        elif libraries_with_carousels:
            # If no custom order specified, sort carousel libraries alphabetically
            libraries_with_carousels.sort(key=lambda lib: lib["title"].lower())
        
        # Sort libraries without carousels alphabetically by title
        libraries_without_carousels.sort(key=lambda lib: lib["title"].lower())
        
        # Combine the lists: carousel libraries first, then non-carousel libraries
        libraries = libraries_with_carousels + libraries_without_carousels
        
        if debug_mode:
            print(f"[DEBUG] Library ordering for onboarding:")
            print(f"[DEBUG] Carousel IDs: {carousel_ids}")
            print(f"[DEBUG] Library carousel order: {library_carousel_order}")
            print(f"[DEBUG] Available libraries: {[(lib['key'], lib['title']) for lib in available_libraries]}")
            print(f"[DEBUG] Libraries with carousels ({len(libraries_with_carousels)}): {[(lib['key'], lib['title']) for lib in libraries_with_carousels]}")
            print(f"[DEBUG] Libraries without carousels ({len(libraries_without_carousels)}): {[(lib['key'], lib['title']) for lib in libraries_without_carousels]}")
            print(f"[DEBUG] Final library order: {[(lib['key'], lib['title']) for lib in libraries]}")
    except Exception as e:
        if debug_mode:
            print(f"Failed to get libraries from local files: {e}")
        libraries = []
        all_libraries = []
        carousel_libraries = []
        available_libraries = []

    # Build static poster URLs for each library (limit to 10 per library)
    library_posters = {}
    poster_imdb_ids = {}
    for lib in carousel_libraries:
        section_id = lib["key"]
        name = lib["title"]
        poster_dir = get_library_poster_dir(section_id)
        posters = []
        imdb_ids = []
        
        try:
            if os.path.exists(poster_dir):
                # Get all image files efficiently
                all_files = [f for f in os.listdir(poster_dir) if f.lower().endswith(('.webp', '.jpg', '.jpeg', '.png'))]
                
                # Sort by modification time to get most recent first
                all_files.sort(key=lambda f: os.path.getmtime(os.path.join(poster_dir, f)), reverse=True)
                
                # Limit to 10 random posters per library for initial load
                if len(all_files) > 10:
                    limited_files = random.sample(all_files, 10)
                else:
                    limited_files = all_files
                
                for fname in limited_files:
                    posters.append(f"/static/posters/{section_id}/{fname}")
                    
                    # Load metadata efficiently
                    json_path = os.path.join(poster_dir, fname.rsplit('.', 1)[0] + '.json')
                    imdb_id = None
                    try:
                        if os.path.exists(json_path):
                            with open(json_path, 'r', encoding='utf-8') as f:
                                meta = json.load(f)
                                imdb_id = meta.get('imdb')
                    except (IOError, json.JSONDecodeError):
                        # Skip corrupted metadata files
                        pass
                    
                    imdb_ids.append(imdb_id)
        except OSError as e:
            if debug_mode:
                print(f"Error loading posters for library {name}: {e}")
            # Continue with empty posters list
        
        library_posters[name] = posters
        poster_imdb_ids[name] = imdb_ids

    pulsarr_enabled = bool(config.get("PULSARR"))
    overseerr_enabled = bool(config.get("OVERSEERR"))
    jellyseerr_enabled = bool(config.get("JELLYSEERR"))
    overseerr_url = config.get("OVERSEERR", "")
    jellyseerr_url = config.get("JELLYSEERR", "")
    tautulli_enabled = bool(config.get("TAUTULLI"))
    
    # Get default library setting
    default_library = config.get("DEFAULT_LIBRARY", "all")
    
    # Get all libraries to map numbers to names (use local data)
    # Note: We already have all_libraries from earlier in the function, so reuse it
    library_map = {lib["key"]: lib["title"] for lib in all_libraries}
    
    # Check if any library has media_type of "artist" (music)
    # Only check currently available libraries that are actually shown in the UI
    has_music_library = any(lib.get("media_type") == "artist" for lib in carousel_libraries)
    
    if debug_mode:
        print(f"[DEBUG] Music library check: {has_music_library}")
        print(f"[DEBUG] Total libraries from Plex API: {len(all_libraries)}")
        print(f"[DEBUG] Libraries for access requests: {len(libraries)}")
        print(f"[DEBUG] Libraries for carousel display: {len(carousel_libraries)}")
        print(f"[DEBUG] All libraries from Plex API:")
        for lib in all_libraries:
            print(f"[DEBUG]   - {lib['title']} (ID: {lib['key']}, type: {lib.get('media_type', 'unknown')})")
        print(f"[DEBUG] Libraries for access requests:")
        for lib in libraries:
            print(f"[DEBUG]   - {lib['title']} (ID: {lib['key']}, type: {lib.get('media_type', 'unknown')})")
        print(f"[DEBUG] Libraries for carousel display:")
        for lib in carousel_libraries:
            print(f"[DEBUG]   - {lib['title']} (ID: {lib['key']}, type: {lib.get('media_type', 'unknown')})")
            if lib.get("media_type") == "artist":
                print(f"[DEBUG] Found music library in carousel: {lib['title']} (ID: {lib['key']})")
        # Also check library_notes.json for comparison
        library_notes = load_library_notes()
        music_in_notes = [lib_id for lib_id, note in library_notes.items() 
                         if note.get('media_type') == 'artist']
        if music_in_notes:
            print(f"[DEBUG] Music libraries in library_notes.json: {music_in_notes}")
            for lib_id in music_in_notes:
                if lib_id not in [lib['key'] for lib in all_libraries]:
                    print(f"[DEBUG] Music library {lib_id} exists in notes but not in current Plex API")
    
    # Determine which library should be default
    default_library_name = "random-all"  # Default to random-all
    if default_library != "all":
        try:
            # Parse comma-separated library numbers
            library_numbers = [num.strip() for num in default_library.split(",")]
            # Use the first valid library number
            for lib_num in library_numbers:
                if lib_num in library_map:
                    default_library_name = library_map[lib_num]
                    break
        except Exception as e:
            if debug_mode:
                print(f"Error parsing DEFAULT_LIBRARY: {e}")

    # Get template context with quick_access_services
    context = get_template_context()
    
    # Add page-specific variables
    context.update({
        "libraries": libraries,  # Use ordered libraries for access requests
        "carousel_libraries": carousel_libraries,  # Use filtered libraries for carousel display
        "submitted": submitted,
        "pulsarr_enabled": pulsarr_enabled,
        "overseerr_enabled": overseerr_enabled,
        "jellyseerr_enabled": jellyseerr_enabled,
        "overseerr_url": overseerr_url,
        "jellyseerr_url": jellyseerr_url,
        "tautulli_enabled": tautulli_enabled,
        "library_posters": library_posters,
        "poster_imdb_ids": poster_imdb_ids,
        "default_library": default_library_name,
        "has_music_library": has_music_library,
        "section7_content": load_section7_content(),
    })
    
    return render_template("onboarding.html", **context)

@app.route("/audiobookshelf", methods=["GET", "POST"])
def audiobookshelf():
    if config.get("ABS_ENABLED", "yes") != "yes":
        return ("Not Found", 404)
    if not session.get("authenticated"):
        # Use client-side redirect to preserve hash fragments
        return render_template_string("""
            <!DOCTYPE html>
            <html>
            <head><title>Redirecting...</title></head>
            <body>
                <script>
                    sessionStorage.setItem('intended_url_after_login', window.location.href);
                    window.location.href = '/login';
                </script>
            </body>
            </html>
        """)
    
    # Check for first-time IP access
    client_ip = get_client_ip()
    check_first_time_ip_access(client_ip)

    submitted = False

    if request.method == "POST":
        # Get client IP for rate limiting
        client_ip = get_client_ip()
        
        # Check form submission rate limiting
        is_rate_limited, remaining_time = check_rate_limit(client_ip, "form_submission", "audiobookshelf")
        if is_rate_limited:
            time_remaining = format_time_remaining(remaining_time)
            log_security_event("form_rate_limited", client_ip, f"Audiobookshelf form submission rate limited, {time_remaining} remaining")
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"success": False, "error": f"Too many submissions. Please try again in {time_remaining}."})
            else:
                return render_template("audiobookshelf.html", error=f"Too many submissions. Please try again in {time_remaining}.")
        
        email = request.form.get("email")
        username = request.form.get("username")
        password = request.form.get("password")

        # Validate email
        if not config.validate_email(email):
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"success": False, "error": "Invalid email address."})
            else:
                return render_template("audiobookshelf.html", error="Invalid email address.")

        # Validate password length (minimum 8 characters)
        if len(password) < 8:
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"success": False, "error": "Password must be at least 8 characters long."})
            else:
                return render_template("audiobookshelf.html", error="Password must be at least 8 characters long.")

        # Check for duplicate email
        submissions = load_json_file("audiobookshelf_submissions.json", [])
        existing_emails = [submission.get("email", "").lower() for submission in submissions]
        if email.lower() in existing_emails:
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"success": False, "error": "This email has already been submitted."})
            else:
                return render_template("audiobookshelf.html", error="This email has already been submitted.")

        if email and username and password:
            submission_entry = {
                "email": email,
                "username": username,
                "password": password,
                "submitted_at": datetime.now(timezone.utc).isoformat() + "Z"
            }
            submissions = load_json_file("audiobookshelf_submissions.json", [])
            submissions.append(submission_entry)
            save_json_file("audiobookshelf_submissions.json", submissions)
            submitted = True
            
            # Record successful form submission
            add_form_submission(client_ip, "audiobookshelf")
            
            send_discord_notification(email, "Audiobookshelf", event_type="abs")
            # AJAX response
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"success": True})
        # AJAX error response
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": False, "error": "Missing required fields."})

    # List all covers in static/posters/audiobooks/
    abs_covers = []
    audiobook_dir = os.path.join("static", "posters", "audiobooks")
    if os.path.exists(audiobook_dir):
        for fname in sorted(os.listdir(audiobook_dir)):
            if fname.lower().endswith(('.webp', '.jpg', '.jpeg', '.png')):
                abs_covers.append(f"/static/posters/audiobooks/{fname}")

    tautulli_enabled = bool(config.get("TAUTULLI"))
    
    # Get template context with quick_access_services
    context = get_template_context()
    
    # Add page-specific variables
    context.update({
        "submitted": submitted,
        "abs_covers": abs_covers,
        "tautulli_enabled": tautulli_enabled,
    })
    
    return render_template("audiobookshelf.html", **context)

# Add this helper at the top (after imports)
def is_setup_complete():
    return config.get("SETUP_COMPLETE", "0") == "1"

# Update login route to check setup status


@app.route("/login", methods=["GET", "POST"])
@csrf.exempt
def login():
    if not is_setup_complete():
        return redirect(url_for("setup"))
    
    # Get client IP for rate limiting
    client_ip = get_client_ip()
    
    # Check for first-time IP access
    check_first_time_ip_access(client_ip)
    
    if request.method == "POST":
        # Check rate limiting only for POST requests (actual login attempts)
        is_rate_limited, remaining_time = check_rate_limit(client_ip, "login")
        if is_rate_limited:
            time_remaining = format_time_remaining(remaining_time)
            log_security_event("rate_limited", client_ip, f"Login attempt rate limited, {time_remaining} remaining")
            return render_template("login.html", error=f"Too many failed attempts. Please try again in {time_remaining}.")
        
        entered_password = request.form.get("password")
        # Get passwords from centralized config
        
        # Get hashed passwords and salts
        admin_password_hash = config.get("ADMIN_PASSWORD_HASH")
        admin_password_salt = config.get("ADMIN_PASSWORD_SALT")
        site_password_hash = config.get("SITE_PASSWORD_HASH")
        site_password_salt = config.get("SITE_PASSWORD_SALT")
        
        # For backward compatibility, check plain text passwords if hashes don't exist
        admin_password_plain = config.get("ADMIN_PASSWORD")
        site_password_plain = config.get("SITE_PASSWORD")
        
        # Check admin password
        admin_authenticated = False
        if admin_password_hash and admin_password_salt:
            admin_authenticated = verify_password(entered_password, admin_password_salt, admin_password_hash)
        elif admin_password_plain:
            # Fallback to plain text for backward compatibility
            admin_authenticated = (entered_password == admin_password_plain)
        
        # Check site password
        site_authenticated = False
        if site_password_hash and site_password_salt:
            site_authenticated = verify_password(entered_password, site_password_salt, site_password_hash)
        elif site_password_plain:
            # Fallback to plain text for backward compatibility
            site_authenticated = (entered_password == site_password_plain)

        if admin_authenticated:
            session["authenticated"] = True
            session["admin_authenticated"] = True
            check_first_time_login_success(client_ip)
            
            # Get intended URL from form data (sent by client-side JavaScript)
            intended_url_after_login = request.form.get("intended_url_after_login")
            redirect_url = intended_url_after_login if intended_url_after_login else url_for("services")
            
            # If redirecting to services with a hash fragment, ensure it's preserved
            if intended_url_after_login and intended_url_after_login.startswith(url_for("services")) and "#" in intended_url_after_login:
                # Extract the hash fragment
                hash_fragment = intended_url_after_login.split("#", 1)[1]
                redirect_url = f"{url_for('services')}#{hash_fragment}"
                print(f"DEBUG: Preserving hash fragment '{hash_fragment}' for services redirect")
            
            return redirect(redirect_url)
        elif site_authenticated:
            session["authenticated"] = True
            session["admin_authenticated"] = False
            check_first_time_login_success(client_ip)
            
            # Get intended URL from form data (sent by client-side JavaScript)
            intended_url_after_login = request.form.get("intended_url_after_login")
            redirect_url = intended_url_after_login if intended_url_after_login else url_for("onboarding")
            return redirect(redirect_url)
        else:
            # Record failed attempt
            add_failed_attempt(client_ip, "login")
            
            # Check if this is an AJAX request by looking for X-Requested-With header
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                # AJAX request, return JSON response
                return jsonify({"success": False, "error": "Incorrect password"}), 401
            else:
                # Regular form submission, return template with error
                return render_template("login.html", error="Incorrect password")

    return render_template("login.html")

@app.route("/logout")
def logout():
    """Clear session and redirect to login"""
    session.clear()
    return redirect(url_for("login"))

@app.route("/services", methods=["GET", "POST"])
def services():
    if not session.get("admin_authenticated"):
        # Use client-side redirect to preserve hash fragments
        print(f"DEBUG: Unauthenticated access to services, storing URL: {request.url}")
        return render_template_string("""
            <!DOCTYPE html>
            <html>
            <head><title>Redirecting...</title></head>
            <body>
                <script>
                    // Store the full URL including hash fragment
                    console.log('Storing intended URL:', window.location.href);
                    sessionStorage.setItem('intended_url_after_login', window.location.href);
                    window.location.href = '/login';
                </script>
            </body>
        </html>
        """)

    # Handle admin settings form POST
    if request.method == "POST" and (
        "server_name" in request.form or
        "plex_token" in request.form or
        "plex_url" in request.form or
        "audiobooks_id" in request.form or
        "abs_enabled" in request.form or
        "discord_webhook" in request.form or
        "discord_notify_plex" in request.form or
        "discord_notify_abs" in request.form or
        "onboarderr_url" in request.form or
        "library_ids" in request.form or
        "audiobookshelf_url" in request.form or
        "accent_color" in request.form or
        "quick_access_enabled" in request.form or
        "logo_file" in request.files or
        "wordmark_file" in request.files or
        "ip_management" in request.form
    ):
        env_path = os.path.join(os.getcwd(), ".env")
        
        # Handle file uploads
        logo_file = request.files.get('logo_file')
        wordmark_file = request.files.get('wordmark_file')
        
        if logo_file and logo_file.filename:
            if not process_uploaded_logo(logo_file):
                # Get all the necessary data for the template
                context = get_template_context()
                
                context["error_message"] = "Failed to process logo file. Please ensure it's a valid image file (.png, .webp, .jpg, .jpeg)."
                return render_template("services.html", **context)
        
        if wordmark_file and wordmark_file.filename:
            if not process_uploaded_wordmark(wordmark_file):
                # Similar error handling for wordmark
                context = get_template_context()
                context["error_message"] = "Failed to process wordmark file. Please ensure it's a valid image file (.png, .webp, .jpg, .jpeg)."
                return render_template("services.html", **context)
        
        # Update .env with any non-empty fields (only if they changed)
        for field in ["server_name", "plex_url", "audiobooks_id"]:
            value = request.form.get(field, "").strip()
            current_value = config.get(field.upper(), "")
            if value != current_value:
                safe_set_key(env_path, field.upper(), value)
        
        # Handle Plex token with hashing
        plex_token = request.form.get("plex_token", "").strip()
        if plex_token:
            save_api_key_with_hash(env_path, "PLEX_TOKEN", plex_token)

        # Handle Audiobookshelf fields
        audiobooks_id = request.form.get("audiobooks_id", "").strip()
        audiobookshelf_url = request.form.get("audiobookshelf_url", "").strip()
        audiobookshelf_token = request.form.get("audiobookshelf_token", "").strip()

        abs_enabled = request.form.get("abs_enabled")
        current_abs = config.get("ABS_ENABLED", "no")

        # Handle ABS enabled/disabled radio button selection first
        if abs_enabled in ["yes", "no"]:
            safe_set_key(env_path, "ABS_ENABLED", abs_enabled)
            
            # If ABS is disabled, clear all ABS fields
            if abs_enabled == "no":
                safe_set_key(env_path, "AUDIOBOOKS_ID", "")
                safe_set_key(env_path, "AUDIOBOOKSHELF_URL", "")
                save_api_key_with_hash(env_path, "AUDIOBOOKSHELF_TOKEN", "")
            # If ABS is enabled, save the provided fields
            else:
                if audiobooks_id:
                    safe_set_key(env_path, "AUDIOBOOKS_ID", audiobooks_id)
                if audiobookshelf_url:
                    safe_set_key(env_path, "AUDIOBOOKSHELF_URL", audiobookshelf_url)
                if audiobookshelf_token:
                    save_api_key_with_hash(env_path, "AUDIOBOOKSHELF_TOKEN", audiobookshelf_token)
        else:
            # Fallback to field-based logic if no radio button selection
            if not audiobooks_id and not audiobookshelf_url and not audiobookshelf_token:
                # If all Audiobookshelf fields are empty, set ABS_ENABLED to 'no' and clear other ABS fields
                safe_set_key(env_path, "ABS_ENABLED", "no")
                safe_set_key(env_path, "AUDIOBOOKS_ID", "")
                safe_set_key(env_path, "AUDIOBOOKSHELF_URL", "")
                save_api_key_with_hash(env_path, "AUDIOBOOKSHELF_TOKEN", "")
            else:
                # If any Audiobookshelf field is filled, set ABS_ENABLED to 'yes'
                safe_set_key(env_path, "ABS_ENABLED", "yes")
                if audiobooks_id:
                    safe_set_key(env_path, "AUDIOBOOKS_ID", audiobooks_id)
                if audiobookshelf_url:
                    safe_set_key(env_path, "AUDIOBOOKSHELF_URL", audiobookshelf_url)
                if audiobookshelf_token:
                    save_api_key_with_hash(env_path, "AUDIOBOOKSHELF_TOKEN", audiobookshelf_token)
        # Library IDs (checkboxes)
        library_ids = request.form.getlist("library_ids")
        current_library_ids = config.get("LIBRARY_IDS", "")
        
        # Ensure library_ids are properly formatted (no commas within individual IDs)
        cleaned_library_ids = []
        for lib_id in library_ids:
            # Remove any commas from individual library IDs
            cleaned_id = lib_id.replace(",", "").strip()
            if cleaned_id:
                cleaned_library_ids.append(cleaned_id)
        
        if cleaned_library_ids and ",".join(cleaned_library_ids) != current_library_ids:
            safe_set_key(env_path, "LIBRARY_IDS", ",".join(cleaned_library_ids))
            if debug_mode:
                print(f"[DEBUG] Services form - Updated LIBRARY_IDS to: {','.join(cleaned_library_ids)}")
        
        # Library descriptions (optional) - always process descriptions regardless of library_ids
        # Load existing library notes to preserve other data
        existing_notes = load_library_notes()
        
        # Debug: Print all form data to see what's being submitted
        print(f"[DEBUG] Services form submission - All form keys: {list(request.form.keys())}")
        
        # Process descriptions for all libraries that have description fields in the form
        # This ensures we don't lose descriptions when libraries are deselected
        for key, value in request.form.items():
            if key.startswith("library_desc_"):
                # Handle both visible inputs (library_desc_X) and hidden inputs (library_desc_hidden_X)
                if key.startswith("library_desc_hidden_"):
                    lib_id = key.replace("library_desc_hidden_", "")
                else:
                    lib_id = key.replace("library_desc_", "")
                # Clean the library ID to remove any commas
                lib_id = lib_id.replace(",", "").strip()
                desc = value.strip()
                
                print(f"[DEBUG] Processing library description - Key: {key}, Lib ID: {lib_id}, Description: '{desc}'")
                
                # Skip if library ID is empty after cleaning
                if not lib_id:
                    print(f"[DEBUG] Skipping empty library ID")
                    continue
                
                # Initialize library entry if it doesn't exist
                if lib_id not in existing_notes:
                    existing_notes[lib_id] = {}
                    print(f"[DEBUG] Created new library entry for {lib_id}")
                
                if desc:
                    # Add or update description
                    existing_notes[lib_id]["description"] = desc
                    print(f"[DEBUG] Updated description for library {lib_id}: '{desc}'")
                else:
                    # Remove description if field is empty
                    if "description" in existing_notes[lib_id]:
                        del existing_notes[lib_id]["description"]
                        print(f"[DEBUG] Removed description for library {lib_id}")
        
        # Save the updated library notes
        print(f"[DEBUG] Saving library notes: {existing_notes}")
        save_library_notes(existing_notes)
        # Discord settings
        discord_webhook = request.form.get("discord_webhook", "").strip()
        current_webhook = os.getenv("DISCORD_WEBHOOK", "")
        if discord_webhook != current_webhook:
            safe_set_key(env_path, "DISCORD_WEBHOOK", discord_webhook)
        
        discord_username = request.form.get("discord_username", "").strip()
        current_username = os.getenv("DISCORD_USERNAME", "")
        if discord_username != current_username:
            safe_set_key(env_path, "DISCORD_USERNAME", discord_username)
        
        discord_avatar = request.form.get("discord_avatar", "").strip()
        current_avatar = os.getenv("DISCORD_AVATAR", "")
        if discord_avatar != current_avatar:
            safe_set_key(env_path, "DISCORD_AVATAR", discord_avatar)
        
        discord_color = request.form.get("discord_color", "").strip()
        current_color = os.getenv("DISCORD_COLOR", "")
        if discord_color != current_color:
            safe_set_key(env_path, "DISCORD_COLOR", discord_color)
        
        onboarderr_url = request.form.get("onboarderr_url", "").strip()
        current_onboarderr_url = os.getenv("ONBOARDERR_URL", "")
        if onboarderr_url != current_onboarderr_url:
            safe_set_key(env_path, "ONBOARDERR_URL", onboarderr_url)
        
        # Update service URLs if changed
        service_defs = get_service_definitions()
        for name, env, logo in service_defs:
            url = request.form.get(env, None)
            if url is not None:
                url = url.strip()
                current_url = os.getenv(env, "")
                if url != current_url:
                    safe_set_key(env_path, env, url)

        # Read new notification toggles
        discord_notify_plex = request.form.get("discord_notify_plex")
        # If checkbox is unchecked, it won't be in form data, so treat as "0"
        if discord_notify_plex is None:
            discord_notify_plex = "0"
        current_discord_notify_plex = os.getenv("DISCORD_NOTIFY_PLEX", "1")
        if discord_notify_plex in ["1", "0"] and discord_notify_plex != current_discord_notify_plex:
            safe_set_key(env_path, "DISCORD_NOTIFY_PLEX", discord_notify_plex)

        discord_notify_abs = request.form.get("discord_notify_abs")
        # If checkbox is unchecked, it won't be in form data, so treat as "0"
        if discord_notify_abs is None:
            discord_notify_abs = "0"
        current_discord_notify_abs = os.getenv("DISCORD_NOTIFY_ABS", "1")
        if discord_notify_abs in ["1", "0"] and discord_notify_abs != current_discord_notify_abs:
            safe_set_key(env_path, "DISCORD_NOTIFY_ABS", discord_notify_abs)

        # Handle new security event notification settings
        discord_notify_rate_limiting = request.form.get("discord_notify_rate_limiting")
        if discord_notify_rate_limiting is None:
            discord_notify_rate_limiting = "0"
        current_discord_notify_rate_limiting = os.getenv("DISCORD_NOTIFY_RATE_LIMITING", "0")
        if discord_notify_rate_limiting in ["1", "0"] and discord_notify_rate_limiting != current_discord_notify_rate_limiting:
            safe_set_key(env_path, "DISCORD_NOTIFY_RATE_LIMITING", discord_notify_rate_limiting)

        discord_notify_ip_management = request.form.get("discord_notify_ip_management")
        if discord_notify_ip_management is None:
            discord_notify_ip_management = "0"
        current_discord_notify_ip_management = os.getenv("DISCORD_NOTIFY_IP_MANAGEMENT", "0")
        if discord_notify_ip_management in ["1", "0"] and discord_notify_ip_management != current_discord_notify_ip_management:
            safe_set_key(env_path, "DISCORD_NOTIFY_IP_MANAGEMENT", discord_notify_ip_management)

        discord_notify_login_attempts = request.form.get("discord_notify_login_attempts")
        if discord_notify_login_attempts is None:
            discord_notify_login_attempts = "0"
        current_discord_notify_login_attempts = os.getenv("DISCORD_NOTIFY_LOGIN_ATTEMPTS", "0")
        if discord_notify_login_attempts in ["1", "0"] and discord_notify_login_attempts != current_discord_notify_login_attempts:
            safe_set_key(env_path, "DISCORD_NOTIFY_LOGIN_ATTEMPTS", discord_notify_login_attempts)

        discord_notify_form_rate_limiting = request.form.get("discord_notify_form_rate_limiting")
        if discord_notify_form_rate_limiting is None:
            discord_notify_form_rate_limiting = "0"
        current_discord_notify_form_rate_limiting = os.getenv("DISCORD_NOTIFY_FORM_RATE_LIMITING", "0")
        if discord_notify_form_rate_limiting in ["1", "0"] and discord_notify_form_rate_limiting != current_discord_notify_form_rate_limiting:
            safe_set_key(env_path, "DISCORD_NOTIFY_FORM_RATE_LIMITING", discord_notify_form_rate_limiting)

        discord_notify_first_access = request.form.get("discord_notify_first_access")
        if discord_notify_first_access is None:
            discord_notify_first_access = "0"
        current_discord_notify_first_access = os.getenv("DISCORD_NOTIFY_FIRST_ACCESS", "0")
        if discord_notify_first_access in ["1", "0"] and discord_notify_first_access != current_discord_notify_first_access:
            safe_set_key(env_path, "DISCORD_NOTIFY_FIRST_ACCESS", discord_notify_first_access)

        # Handle Quick Access setting
        quick_access_enabled = request.form.get("quick_access_enabled", "yes")
        current_quick_access = os.getenv("QUICK_ACCESS_ENABLED", "yes")
        if quick_access_enabled in ["yes", "no"] and quick_access_enabled != current_quick_access:
            safe_set_key(env_path, "QUICK_ACCESS_ENABLED", quick_access_enabled)
        
        # Handle individual Quick Access service toggles
        qa_plex_enabled = "yes" if request.form.get("qa_plex_enabled") else "no"
        qa_audiobookshelf_enabled = "yes" if request.form.get("qa_audiobookshelf_enabled") else "no"
        qa_tautulli_enabled = "yes" if request.form.get("qa_tautulli_enabled") else "no"
        qa_overseerr_enabled = "yes" if request.form.get("qa_overseerr_enabled") else "no"
        qa_jellyseerr_enabled = "yes" if request.form.get("qa_jellyseerr_enabled") else "no"
        
        safe_set_key(env_path, "QA_PLEX_ENABLED", qa_plex_enabled)
        safe_set_key(env_path, "QA_AUDIOBOOKSHELF_ENABLED", qa_audiobookshelf_enabled)
        safe_set_key(env_path, "QA_TAUTULLI_ENABLED", qa_tautulli_enabled)
        safe_set_key(env_path, "QA_OVERSEERR_ENABLED", qa_overseerr_enabled)
        safe_set_key(env_path, "QA_JELLYSEERR_ENABLED", qa_jellyseerr_enabled)

        # Handle Library Carousel settings
        library_carousels = request.form.getlist("library_carousels")
        current_carousels = os.getenv("LIBRARY_CAROUSELS", "")
        
        # Get current library IDs for validation
        current_library_ids = [id.strip() for id in os.getenv("LIBRARY_IDS", "").split(",") if id.strip()]
        
        if debug_mode:
            print(f"[DEBUG] Services form - Raw library_carousels from form: {library_carousels}")
            print(f"[DEBUG] Services form - Current library_ids: {current_library_ids}")
        
        # Validate that all carousel libraries are in the current library IDs
        if library_carousels:
            # Convert both to sets for comparison
            carousel_set = set(library_carousels)
            library_set = set(current_library_ids)
            
            # Find any carousel libraries that aren't in current libraries
            invalid_carousels = carousel_set - library_set
            if invalid_carousels and debug_mode:
                print(f"[DEBUG] Services form - Invalid carousel libraries found: {invalid_carousels}")
                print(f"[DEBUG] Services form - These libraries are not in the current library IDs")
            
            # Only keep carousel libraries that are actually in the current libraries
            valid_carousels = list(carousel_set & library_set)
            if debug_mode:
                print(f"[DEBUG] Services form - Valid carousel libraries: {valid_carousels}")
            
            new_carousels = ",".join(valid_carousels)
            if new_carousels != current_carousels:
                safe_set_key(env_path, "LIBRARY_CAROUSELS", new_carousels)
                # Reload environment variables to reflect the change immediately
                load_dotenv(override=True)
        
        # Handle Library Carousel Tab Order
        library_carousel_order = request.form.get("library_carousel_order", "").strip()
        current_carousel_order = os.getenv("LIBRARY_CAROUSEL_ORDER", "")
        
        if debug_mode:
            print(f"[DEBUG] Services form - Raw carousel order from form: '{library_carousel_order}'")
            print(f"[DEBUG] Services form - Current carousel order from env: '{current_carousel_order}'")
        
        if library_carousel_order:
            # Validate that all libraries in the order are in the current libraries
            order_ids = [id.strip() for id in library_carousel_order.split(",") if id.strip()]
            if debug_mode:
                print(f"[DEBUG] Services form - Carousel order from form: {order_ids}")
            
            # Filter to only include libraries that are actually in the current libraries
            valid_order_ids = [id for id in order_ids if id in current_library_ids]
            if debug_mode:
                print(f"[DEBUG] Services form - Valid carousel order: {valid_order_ids}")
            
            new_order = ",".join(valid_order_ids)
            if new_order != current_carousel_order:
                safe_set_key(env_path, "LIBRARY_CAROUSEL_ORDER", new_order)
                # Reload environment variables to reflect the change immediately
                load_dotenv(override=True)

        # Handle password fields
        site_password = request.form.get("site_password", "").strip()
        admin_password = request.form.get("admin_password", "").strip()
        if site_password:
            # Hash the site password
            site_salt, site_hash = hash_password(site_password)
            safe_set_key(env_path, "SITE_PASSWORD_HASH", site_hash)
            safe_set_key(env_path, "SITE_PASSWORD_SALT", site_salt)
            # Keep plain text for backward compatibility
            safe_set_key(env_path, "SITE_PASSWORD", site_password)
        if admin_password:
            # Hash the admin password
            admin_salt, admin_hash = hash_password(admin_password)
            safe_set_key(env_path, "ADMIN_PASSWORD_HASH", admin_hash)
            safe_set_key(env_path, "ADMIN_PASSWORD_SALT", admin_salt)
            # Keep plain text for backward compatibility
            safe_set_key(env_path, "ADMIN_PASSWORD", admin_password)

        # Handle accent color
        accent_color = request.form.get("accent_color_text", "").strip()
        current_accent_color = os.getenv("ACCENT_COLOR", "")
        if accent_color and accent_color != current_accent_color:
            safe_set_key(env_path, "ACCENT_COLOR", accent_color)
            # Reload environment variables to apply the new accent color immediately
            load_dotenv(override=True)

        # Handle IP management enabled setting
        ip_management_enabled = request.form.get("ip_management_enabled", "no")
        current_ip_management = os.getenv("IP_MANAGEMENT_ENABLED", "no")
        if ip_management_enabled in ["yes", "no"] and ip_management_enabled != current_ip_management:
            safe_set_key(env_path, "IP_MANAGEMENT_ENABLED", ip_management_enabled)
            # Reload environment variables to reflect the change immediately
            load_dotenv(override=True)

        # Handle rate limiting settings
        rate_limit_settings_enabled = request.form.get("rate_limit_settings_enabled", "yes")
        current_rate_limit_settings = os.getenv("RATE_LIMIT_SETTINGS_ENABLED", "yes")
        if rate_limit_settings_enabled in ["yes", "no"] and rate_limit_settings_enabled != current_rate_limit_settings:
            safe_set_key(env_path, "RATE_LIMIT_SETTINGS_ENABLED", rate_limit_settings_enabled)
            # Reload environment variables to reflect the change immediately
            load_dotenv(override=True)

        # Handle rate limiting values
        max_login_attempts = request.form.get("max_login_attempts")
        if max_login_attempts is not None:
            try:
                max_login_attempts = int(max_login_attempts)
                if 0 <= max_login_attempts <= 10:
                    current_max_login = int(os.getenv("RATE_LIMIT_MAX_LOGIN_ATTEMPTS", os.getenv("RATE_LIMIT_LOGIN_ATTEMPTS", "5")))
                    if max_login_attempts != current_max_login:
                        safe_set_key(env_path, "RATE_LIMIT_MAX_LOGIN_ATTEMPTS", str(max_login_attempts))
                        load_dotenv(override=True)
            except ValueError:
                pass

        max_form_submissions = request.form.get("max_form_submissions")
        if max_form_submissions is not None:
            try:
                max_form_submissions = int(max_form_submissions)
                if 0 <= max_form_submissions <= 10:
                    current_max_form = int(os.getenv("RATE_LIMIT_MAX_FORM_SUBMISSIONS", os.getenv("RATE_LIMIT_FORM_SUBMISSIONS", "1")))
                    if max_form_submissions != current_max_form:
                        safe_set_key(env_path, "RATE_LIMIT_MAX_FORM_SUBMISSIONS", str(max_form_submissions))
                        load_dotenv(override=True)
            except ValueError:
                pass

        # Handle IP management
        if "ip_management" in request.form:
            action = request.form.get("ip_action")
            ip_address = request.form.get("ip_address", "").strip()
            
            if ip_address and action:
                # Validate IP address or IP range format
                if not is_valid_ip_or_range(ip_address):
                    context = get_template_context()
                    context["error_message"] = f"Invalid IP address or IP range format: {ip_address}. Use single IP (e.g., 192.168.1.1) or IP range (e.g., 192.168.1.0/24)"
                    return render_template("services.html", **context)
                
                try:
                    if action == "whitelist":
                        add_ip_to_whitelist(ip_address)
                    elif action == "remove_whitelist":
                        remove_ip_from_whitelist(ip_address)
                    elif action == "blacklist":
                        add_ip_to_blacklist(ip_address)
                    elif action == "remove_blacklist":
                        remove_ip_from_blacklist(ip_address)
                except ValueError as e:
                    context = get_template_context()
                    context["error_message"] = str(e)
                    return render_template("services.html", **context)

        # Handle section 7 content (personal message and payment services)
        personal_message = request.form.get("personal_message", "").strip()
        payment_services = []
        for i in range(3):
            title = request.form.get(f"payment_service_{i}_title", "").strip()
            handle = request.form.get(f"payment_service_{i}_handle", "").strip()
            if title or handle:  # Save even if only one field is filled
                payment_services.append({
                    "title": title,
                    "handle": handle
                })
            else:
                # Add empty service to maintain 3 slots
                payment_services.append({
                    "title": "",
                    "handle": ""
                })
        
        section7_content = {
            "personal_message": personal_message,
            "payment_services": payment_services
        }
        save_section7_content(section7_content)

        # Note: Poster downloads will be handled by setup_complete route to ensure proper flow
        # This prevents the user from staying on /services with loading animation

        # Track what settings changed for adaptive restart
        changed_settings = set()
        
        # Check which settings actually changed by comparing with current values
        current_config = {
            "server_name": config.get("SERVER_NAME", ""),
            "plex_url": config.get("PLEX_URL", ""),
            "audiobooks_id": config.get("AUDIOBOOKS_ID", ""),
            "accent_color_text": config.get("ACCENT_COLOR_TEXT", ""),
            "quick_access_enabled": config.get("QUICK_ACCESS_ENABLED", "no"),
            "discord_webhook": config.get("DISCORD_WEBHOOK", ""),
            "discord_username": config.get("DISCORD_USERNAME", ""),
            "discord_avatar": config.get("DISCORD_AVATAR", ""),
            "discord_color": config.get("DISCORD_COLOR", ""),
            "discord_notify_plex": config.get("DISCORD_NOTIFY_PLEX", "0"),
            "discord_notify_abs": config.get("DISCORD_NOTIFY_ABS", "0"),
            "discord_notify_rate_limiting": config.get("DISCORD_NOTIFY_RATE_LIMITING", "0"),
            "discord_notify_ip_management": config.get("DISCORD_NOTIFY_IP_MANAGEMENT", "0"),
            "discord_notify_login_attempts": config.get("DISCORD_NOTIFY_LOGIN_ATTEMPTS", "0"),
            "discord_notify_form_rate_limiting": config.get("DISCORD_NOTIFY_FORM_RATE_LIMITING", "0"),
            "library_carousels": config.get("LIBRARY_CAROUSELS", ""),
            "library_carousel_order": config.get("LIBRARY_CAROUSEL_ORDER", ""),
            "qa_plex_enabled": config.get("QA_PLEX_ENABLED", "no"),
            "qa_audiobookshelf_enabled": config.get("QA_AUDIOBOOKSHELF_ENABLED", "no"),
            "qa_tautulli_enabled": config.get("QA_TAUTULLI_ENABLED", "no"),
            "qa_overseerr_enabled": config.get("QA_OVERSEERR_ENABLED", "no"),
            "qa_jellyseerr_enabled": config.get("QA_JELLYSEERR_ENABLED", "no"),
            "ip_management_enabled": config.get("IP_MANAGEMENT_ENABLED", "no"),
            "rate_limit_settings_enabled": config.get("RATE_LIMIT_SETTINGS_ENABLED", "no"),
            "max_login_attempts": config.get("MAX_LOGIN_ATTEMPTS", "5"),
            "max_form_submissions": config.get("MAX_FORM_SUBMISSIONS", "10"),
            "library_ids": config.get("LIBRARY_IDS", ""),
            "abs_enabled": config.get("ABS_ENABLED", "no"),
            "audiobookshelf_url": config.get("AUDIOBOOKSHELF_URL", ""),
        }
        
        # Check for actual changes in form fields
        for field in ["server_name", "plex_url", "audiobooks_id", "accent_color_text", 
                     "quick_access_enabled", "discord_webhook", "discord_username", 
                     "discord_avatar", "discord_color", "discord_notify_plex", 
                     "discord_notify_abs", "discord_notify_rate_limiting",
                     "discord_notify_ip_management", "discord_notify_login_attempts",
                     "discord_notify_form_rate_limiting", "library_carousels", "library_carousel_order",
                     "qa_plex_enabled", "qa_audiobookshelf_enabled", "qa_tautulli_enabled",
                     "qa_overseerr_enabled", "qa_jellyseerr_enabled", "ip_management_enabled",
                     "rate_limit_settings_enabled", "max_login_attempts", "max_form_submissions"]:
            if field in request.form:
                new_value = request.form.get(field, "").strip()
                if field in ["discord_notify_plex", "discord_notify_abs", "discord_notify_rate_limiting",
                           "discord_notify_ip_management", "discord_notify_login_attempts",
                           "discord_notify_form_rate_limiting", "quick_access_enabled",
                           "qa_plex_enabled", "qa_audiobookshelf_enabled", "qa_tautulli_enabled",
                           "qa_overseerr_enabled", "qa_jellyseerr_enabled", "ip_management_enabled",
                           "rate_limit_settings_enabled"]:
                    # Handle checkbox fields
                    new_value = "yes" if new_value else "no"
                
                if new_value != current_config.get(field, ""):
                    changed_settings.add(field)
                    if is_debug_mode():
                        print(f"[DEBUG] Setting '{field}' changed: '{current_config.get(field, '')}' -> '{new_value}'")
        
        # Check for poster-dependent settings
        if "plex_token" in request.form and request.form.get("plex_token", "").strip():
            changed_settings.add("plex_token")
            if is_debug_mode():
                print("[DEBUG] Plex token changed")
        
        if "library_ids" in request.form:
            new_library_ids = ",".join(cleaned_library_ids)
            if new_library_ids != current_config.get("library_ids", ""):
                changed_settings.add("library_ids")
                if is_debug_mode():
                    print(f"[DEBUG] Library IDs changed: '{current_config.get('library_ids', '')}' -> '{new_library_ids}'")
        
        if "audiobooks_id" in request.form:
            new_audiobooks_id = request.form.get("audiobooks_id", "").strip()
            if new_audiobooks_id != current_config.get("audiobooks_id", ""):
                changed_settings.add("audiobooks_id")
                if is_debug_mode():
                    print(f"[DEBUG] Audiobooks ID changed: '{current_config.get('audiobooks_id', '')}' -> '{new_audiobooks_id}'")
        
        if "audiobookshelf_url" in request.form:
            new_abs_url = request.form.get("audiobookshelf_url", "").strip()
            if new_abs_url != current_config.get("audiobookshelf_url", ""):
                changed_settings.add("audiobookshelf_url")
                if is_debug_mode():
                    print(f"[DEBUG] ABS URL changed: '{current_config.get('audiobookshelf_url', '')}' -> '{new_abs_url}'")
        
        if "audiobookshelf_token" in request.form:
            new_abs_token = request.form.get("audiobookshelf_token", "").strip()
            # Only mark as changed if the token field is not empty and different from current
            # Since we can't directly compare hashed tokens, we'll only mark as changed if:
            # 1. The new token is not empty AND
            # 2. Either there's no current token hash OR the new token is different from what we can verify
            current_abs_token_hash = os.getenv("AUDIOBOOKSHELF_TOKEN_HASH", "")
            if new_abs_token and (not current_abs_token_hash or not verify_api_key(new_abs_token, current_abs_token_hash)):
                changed_settings.add("audiobookshelf_token")
                if is_debug_mode():
                    print("[DEBUG] ABS token changed")
            elif is_debug_mode():
                print("[DEBUG] ABS token unchanged or empty")
        
        if "abs_enabled" in request.form:
            new_abs_enabled = request.form.get("abs_enabled")
            if new_abs_enabled != current_config.get("abs_enabled", "no"):
                changed_settings.add("abs_enabled")
                if is_debug_mode():
                    print(f"[DEBUG] ABS enabled changed: '{current_config.get('abs_enabled', 'no')}' -> '{new_abs_enabled}'")
        
        if is_debug_mode():
            print(f"[DEBUG] Final changed settings: {changed_settings}")
            print(f"[DEBUG] ABS token in changed settings: {'audiobookshelf_token' in changed_settings}")
        
        # Calculate restart delay
        restart_delay = get_restart_delay_for_changes(changed_settings)
        
        # Note: Poster downloads will be handled by setup_complete route to ensure proper flow
        # This prevents the user from staying on /services with loading animation
        
        # Redirect to setup_complete with adaptive restart info
        return redirect(url_for("setup_complete", from_services="true", 
                              restart_delay=str(restart_delay),
                              changed_settings=",".join(changed_settings)))

    # Handle Plex/Audiobookshelf request deletion
    if request.method == "POST":
        delete_index = int(request.form.get("delete_index", -1))
        if delete_index >= 0:
            try:
                submissions = load_json_file("plex_submissions.json", [])
                if 0 <= delete_index < len(submissions):
                    del submissions[delete_index]
                    save_json_file("plex_submissions.json", submissions)
            except Exception as e:
                if debug_mode:
                    print(f"Error deleting submission: {e}")
        audiobookshelf_delete_index = request.form.get("audiobookshelf_delete_index")
        if audiobookshelf_delete_index is not None:
            try:
                audiobookshelf_delete_index = int(audiobookshelf_delete_index)
                audiobookshelf_submissions = load_json_file("audiobookshelf_submissions.json", [])
                if 0 <= audiobookshelf_delete_index < len(audiobookshelf_submissions):
                    del audiobookshelf_submissions[audiobookshelf_delete_index]
                    save_json_file("audiobookshelf_submissions.json", audiobookshelf_submissions)
            except Exception as e:
                if debug_mode:
                    print(f"Error deleting audiobookshelf submission: {e}")

        # Handle ABS user creation
        if "create_abs_users" in request.form:
            try:
                # Load current submissions
                audiobookshelf_submissions = load_json_file("audiobookshelf_submissions.json", [])
                
                # Get form data
                selected_indices = request.form.getlist("create_users")
                user_type = request.form.get("user_type", "user")
                selected_permissions = request.form.getlist("permissions")
                
                # Build permissions object
                permissions = {
                    "download": "download" in selected_permissions,
                    "update": "update" in selected_permissions,
                    "delete": "delete" in selected_permissions,
                    "upload": "upload" in selected_permissions,
                    "accessAllLibraries": "accessAllLibraries" in selected_permissions,
                    "accessAllTags": "accessAllTags" in selected_permissions,
                    "accessExplicitContent": "accessExplicitContent" in selected_permissions
                }
                
                # Create users
                creation_results = []
                for index_str in selected_indices:
                    try:
                        index = int(index_str)
                        if 0 <= index < len(audiobookshelf_submissions):
                            submission = audiobookshelf_submissions[index]
                            result = create_abs_user(
                                username=submission["username"],
                                password=submission["password"],
                                user_type=user_type,
                                permissions=permissions
                            )
                            result["email"] = submission["email"]
                            creation_results.append(result)
                            
                            # If successful, remove from submissions
                            if result["success"]:
                                del audiobookshelf_submissions[index]
                                # Update the file
                                save_json_file("audiobookshelf_submissions.json", audiobookshelf_submissions)
                    except Exception as e:
                        if debug_mode:
                            print(f"Error creating ABS user for index {index_str}: {e}")
                        creation_results.append({
                            "success": False,
                            "username": "Unknown",
                            "email": "Unknown",
                            "error": f"Error processing submission: {str(e)}"
                        })
                
                # Load all necessary data for template
                context = get_template_context()
                
                context["abs_user_creation_results"] = creation_results
                return render_template("services.html", **context)
                
            except Exception as e:
                if debug_mode:
                    print(f"Error in ABS user creation: {e}")
                # Continue to normal template rendering with error

    # Get template context
    context = get_template_context()
    
    # Add IP management data to context
    context['ip_lists'] = get_ip_lists()
    
    # Add section 7 content to context
    context['section7_content'] = load_section7_content()
    
    # Handle Plex user invitation (parallel to ABS user creation)
    if request.method == "POST" and "invite_plex_users" in request.form:
        try:
            plex_submissions = load_json_file("plex_submissions.json", [])
        except FileNotFoundError:
            plex_submissions = []
        selected_indices = request.form.getlist("invite_users")
        invite_results = []
        # Invite each selected user
        for index_str in selected_indices:
            try:
                index = int(index_str)
                if 0 <= index < len(plex_submissions):
                    submission = plex_submissions[index]
                    email = submission["email"]
                    libraries_titles = submission.get("libraries_titles", [])
                    result = invite_plex_user(email, libraries_titles)
                    invite_results.append(result)
                    # If successful, remove from submissions
                    if result["success"]:
                        del plex_submissions[index]
                        save_json_file("plex_submissions.json", plex_submissions)
            except Exception as e:
                invite_results.append({"success": False, "email": "Unknown", "error": f"Error processing submission: {str(e)}"})
        # Load all necessary data for template
        context = get_template_context()
        context["submissions"] = plex_submissions
        context["plex_invite_results"] = invite_results
        return render_template("services.html", **context)

    context["abs_user_creation_results"] = None  # Will be populated if user creation was attempted
    
    if debug_mode:
        print(f"[DEBUG] Services GET request - LIBRARY_CAROUSEL_ORDER: '{context.get('LIBRARY_CAROUSEL_ORDER', '')}'")
        print(f"[DEBUG] Services GET request - LIBRARY_IDS: '{context.get('LIBRARY_IDS', '')}'")
        print(f"[DEBUG] Services GET request - LIBRARY_CAROUSELS: '{context.get('LIBRARY_CAROUSELS', '')}'")
    
    return render_template("services.html", **context)

@app.route("/fetch-libraries", methods=["POST"])
@limiter.exempt
@csrf.exempt
def fetch_libraries():
    data = request.get_json()
    plex_token = data.get("plex_token")
    plex_url = data.get("plex_url")
    
    if not plex_token or not plex_url:
        return jsonify({"error": "Plex token and URL are required"})
    
    try:
        headers = {"X-Plex-Token": plex_token}
        url = f"{plex_url}/library/sections"
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        root = ET.fromstring(response.text)
        libraries = []
        for directory in root.findall(".//Directory"):
            title = directory.attrib.get("title")
            key = directory.attrib.get("key")
            media_type = directory.attrib.get("type")  # Get the media type
            if title and key:
                libraries.append({
                    "title": title, 
                    "key": key, 
                    "media_type": media_type
                })
        
        # For configuration purposes, show all libraries so admin can select which ones should be available
        # The filtering will be handled by the frontend based on current LIBRARY_IDS
        
        return jsonify({"libraries": libraries})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/ajax/delete-plex-request", methods=["POST"])
def ajax_delete_plex_request():
    if not session.get("admin_authenticated"):
        return jsonify({"success": False, "error": "Unauthorized"})
    
    try:
        data = request.get_json()
        delete_index = data.get("delete_index")
        
        if delete_index is None:
            return jsonify({"success": False, "error": "Missing delete_index"})
        
        delete_index = int(delete_index)
        submissions = load_json_file("plex_submissions.json", [])
        
        if 0 <= delete_index < len(submissions):
            del submissions[delete_index]
            save_json_file("plex_submissions.json", submissions)
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": "Invalid index"})
    except Exception as e:
        if debug_mode:
            print(f"Error deleting Plex submission: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route("/ajax/delete-abs-request", methods=["POST"])
def ajax_delete_abs_request():
    if not session.get("admin_authenticated"):
        return jsonify({"success": False, "error": "Unauthorized"})
    
    try:
        data = request.get_json()
        delete_index = data.get("delete_index")
        
        if delete_index is None:
            return jsonify({"success": False, "error": "Missing delete_index"})
        
        delete_index = int(delete_index)
        audiobookshelf_submissions = load_json_file("audiobookshelf_submissions.json", [])
        
        if 0 <= delete_index < len(audiobookshelf_submissions):
            del audiobookshelf_submissions[delete_index]
            save_json_file("audiobookshelf_submissions.json", audiobookshelf_submissions)
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": "Invalid index"})
    except Exception as e:
        if debug_mode:
            print(f"Error deleting Audiobookshelf submission: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route("/ajax/ip-management", methods=["POST"])
def ajax_ip_management():
    """Handle IP management operations"""
    # Allow access during setup or if admin authenticated
    if not is_setup_complete() or session.get("admin_authenticated"):
        pass
    else:
        return jsonify({"success": False, "error": "Unauthorized"})
    
    try:
        data = request.get_json()
        action = data.get("action")
        ip_address = data.get("ip_address", "").strip()
        
        if not action or not ip_address:
            return jsonify({"success": False, "error": "Missing action or IP address"})
        
        # Validate IP address or IP range format
        if not is_valid_ip_or_range(ip_address):
            return jsonify({"success": False, "error": "Invalid IP address or IP range format. Use single IP (e.g., 192.168.1.1) or IP range (e.g., 192.168.1.0/24)"})
        
        try:
            if action == "whitelist":
                add_ip_to_whitelist(ip_address)
                return jsonify({"success": True})
            elif action == "blacklist":
                add_ip_to_blacklist(ip_address)
                return jsonify({"success": True})
            elif action == "remove_whitelist":
                remove_ip_from_whitelist(ip_address)
                return jsonify({"success": True})
            elif action == "remove_blacklist":
                remove_ip_from_blacklist(ip_address)
                return jsonify({"success": True})
            else:
                return jsonify({"success": False, "error": "Invalid action"})
        except ValueError as e:
            return jsonify({"success": False, "error": str(e)})
            
    except Exception as e:
        if debug_mode:
            print(f"Error in IP management: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route("/ajax/get-ip-lists", methods=["GET"])
def ajax_get_ip_lists():
    """Get current IP lists"""
    # Allow access during setup or if admin authenticated
    if not is_setup_complete() or session.get("admin_authenticated"):
        pass
    else:
        return jsonify({"success": False, "error": "Unauthorized"})
    
    try:
        ip_lists = get_ip_lists()
        return jsonify({
            "success": True,
            "whitelisted": list(ip_lists["whitelisted"]),
            "banned": list(ip_lists["banned"])
        })
    except Exception as e:
        if debug_mode:
            print(f"Error getting IP lists: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route("/ajax/check-rate-limit", methods=["GET"])
def ajax_check_rate_limit():
    """Check if current IP is rate limited for login"""
    try:
        client_ip = get_client_ip()
        
        # Check if IP is whitelisted or banned
        if is_ip_whitelisted(client_ip):
            return jsonify({"rate_limited": False})
        
        if is_ip_banned(client_ip):
            return jsonify({"rate_limited": True, "time_remaining": 86400})  # 24 hours
        
        # Check login rate limit
        rate_limited, time_remaining = check_rate_limit(client_ip, "login")
        if rate_limited:
            return jsonify({
                "rate_limited": True,
                "time_remaining": int(time_remaining)  # Ensure it's an integer for JavaScript
            })
        
        return jsonify({"rate_limited": False})
        
    except Exception as e:
        if debug_mode:
            print(f"Error checking rate limit: {e}")
        return jsonify({"rate_limited": False})

@app.route("/ajax/rate-limit-settings", methods=["POST"])
def ajax_rate_limit_settings():
    """Update rate limiting settings"""
    # Allow access during setup or if admin authenticated
    if not is_setup_complete() or session.get("admin_authenticated"):
        pass
    else:
        return jsonify({"success": False, "error": "Unauthorized"})
    
    try:
        data = request.get_json()
        enabled = data.get("enabled", "yes")
        max_login_attempts = data.get("max_login_attempts", 5)
        max_form_submissions = data.get("max_form_submissions", 1)
        
        # Validate inputs
        if enabled not in ["yes", "no"]:
            return jsonify({"success": False, "error": "Invalid enabled value"})
        
        if not isinstance(max_login_attempts, int) or max_login_attempts < 0 or max_login_attempts > 10:
            return jsonify({"success": False, "error": "Max login attempts must be between 0 and 10"})
        
        if not isinstance(max_form_submissions, int) or max_form_submissions < 0 or max_form_submissions > 10:
            return jsonify({"success": False, "error": "Max form submissions must be between 0 and 10"})
        
        # Update .env file
        env_path = os.path.join(os.getcwd(), ".env")
        safe_set_key(env_path, "RATE_LIMIT_SETTINGS_ENABLED", enabled)
        safe_set_key(env_path, "RATE_LIMIT_MAX_LOGIN_ATTEMPTS", str(max_login_attempts))
        safe_set_key(env_path, "RATE_LIMIT_MAX_FORM_SUBMISSIONS", str(max_form_submissions))
        
        # Reload environment variables
        load_dotenv(override=True)
        
        return jsonify({"success": True})
        
    except Exception as e:
        if debug_mode:
            print(f"Error updating rate limit settings: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route("/ajax/get-rate-limit-settings", methods=["GET"])
def ajax_get_rate_limit_settings():
    """Get current rate limiting settings"""
    # Allow access during setup or if admin authenticated
    if not is_setup_complete() or session.get("admin_authenticated"):
        pass
    else:
        return jsonify({"success": False, "error": "Unauthorized"})
    
    try:
        return jsonify({
            "success": True,
            "enabled": os.getenv("RATE_LIMIT_SETTINGS_ENABLED", "yes"),
            "max_login_attempts": int(os.getenv("RATE_LIMIT_MAX_LOGIN_ATTEMPTS", os.getenv("RATE_LIMIT_LOGIN_ATTEMPTS", "5"))),
            "max_form_submissions": int(os.getenv("RATE_LIMIT_MAX_FORM_SUBMISSIONS", os.getenv("RATE_LIMIT_FORM_SUBMISSIONS", "1")))
        })
    except Exception as e:
        if debug_mode:
            print(f"Error getting rate limit settings: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route("/ajax/invite-plex-users", methods=["POST"])
def ajax_invite_plex_users():
    if not session.get("admin_authenticated"):
        return jsonify({"success": False, "error": "Unauthorized"})
    
    try:
        data = request.get_json()
        selected_indices = data.get("selected_indices", [])
        
        if not selected_indices:
            return jsonify({"success": False, "error": "No users selected"})
        
        plex_submissions = load_json_file("plex_submissions.json", [])
        invite_results = []
        
        # Sort indices in descending order to avoid index shifting issues
        selected_indices.sort(reverse=True)
        
        for index in selected_indices:
            try:
                if 0 <= index < len(plex_submissions):
                    submission = plex_submissions[index]
                    email = submission["email"]
                    libraries_titles = submission.get("libraries_titles", [])
                    result = invite_plex_user(email, libraries_titles)
                    result["email"] = email
                    invite_results.append(result)
                    
                    # If successful, remove from submissions
                    if result["success"]:
                        del plex_submissions[index]
                else:
                    invite_results.append({
                        "success": False, 
                        "email": "Unknown", 
                        "error": "Invalid index"
                    })
            except Exception as e:
                invite_results.append({
                    "success": False, 
                    "email": "Unknown", 
                    "error": f"Error processing submission: {str(e)}"
                })
        
        # Save updated submissions
        save_json_file("plex_submissions.json", plex_submissions)
        
        return jsonify({
            "success": True,
            "results": invite_results
        })
        
    except Exception as e:
        if debug_mode:
            print(f"Error in Plex user invitation: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route("/ajax/create-abs-users", methods=["POST"])
def ajax_create_abs_users():
    if not session.get("admin_authenticated"):
        return jsonify({"success": False, "error": "Unauthorized"})
    
    try:
        data = request.get_json()
        selected_indices = data.get("selected_indices", [])
        user_type = data.get("user_type", "user")
        selected_permissions = data.get("permissions", [])
        
        if not selected_indices:
            return jsonify({"success": False, "error": "No users selected"})
        
        # Build permissions object
        permissions = {
            "download": "download" in selected_permissions,
            "update": "update" in selected_permissions,
            "delete": "delete" in selected_permissions,
            "upload": "upload" in selected_permissions,
            "accessAllLibraries": "accessAllLibraries" in selected_permissions,
            "accessAllTags": "accessAllTags" in selected_permissions,
            "accessExplicitContent": "accessExplicitContent" in selected_permissions
        }
        
        audiobookshelf_submissions = load_json_file("audiobookshelf_submissions.json", [])
        creation_results = []
        
        # Sort indices in descending order to avoid index shifting issues
        selected_indices.sort(reverse=True)
        
        for index in selected_indices:
            try:
                if 0 <= index < len(audiobookshelf_submissions):
                    submission = audiobookshelf_submissions[index]
                    result = create_abs_user(
                        username=submission["username"],
                        password=submission["password"],
                        user_type=user_type,
                        permissions=permissions
                    )
                    result["email"] = submission["email"]
                    creation_results.append(result)
                    
                    # If successful, remove from submissions
                    if result["success"]:
                        del audiobookshelf_submissions[index]
                else:
                    creation_results.append({
                        "success": False,
                        "username": "Unknown",
                        "email": "Unknown",
                        "error": "Invalid index"
                    })
            except Exception as e:
                creation_results.append({
                    "success": False,
                    "username": "Unknown",
                    "email": "Unknown",
                    "error": f"Error processing submission: {str(e)}"
                })
        
        # Save updated submissions
        save_json_file("audiobookshelf_submissions.json", audiobookshelf_submissions)
        
        return jsonify({
            "success": True,
            "results": creation_results
        })
        
    except Exception as e:
        if debug_mode:
            print(f"Error in ABS user creation: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route("/ajax/poster-progress", methods=["GET"])
def ajax_poster_progress():
    """Get poster download progress for admin interface"""
    if not session.get("admin_authenticated"):
        return jsonify({"success": False, "error": "Unauthorized"})
    
    try:
        progress = get_poster_download_progress()
        return jsonify({
            "success": True,
            "progress": progress,
            "worker_running": poster_download_running
        })
    except Exception as e:
        if debug_mode:
            print(f"Error getting poster progress: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route("/refresh-library-titles", methods=["POST"])
def refresh_library_titles():
    if not session.get("admin_authenticated"):
        return jsonify({"success": False, "error": "Unauthorized"})
    
    try:
        # Get current library notes
        library_notes = load_library_notes()
        
        # Get selected library IDs
        library_ids = os.getenv("LIBRARY_IDS", "")
        if not library_ids:
            return jsonify({"success": False, "error": "No libraries selected"})
        
        selected_ids = [i.strip() for i in library_ids.split(",") if i.strip()]
        
        # Fetch current titles from Plex
        plex_token = os.getenv("PLEX_TOKEN")
        plex_url = os.getenv("PLEX_URL")
        
        if not plex_token or not plex_url:
            return jsonify({"success": False, "error": "Plex token or URL not configured"})
        
        headers = {"X-Plex-Token": plex_token}
        url = f"{plex_url}/library/sections"
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()
        root = ET.fromstring(response.text)
        id_to_title = {d.attrib.get("key"): d.attrib.get("title") for d in root.findall(".//Directory")}
        
        # Update library notes with current titles
        updated = False
        for lib_id in selected_ids:
            title = id_to_title.get(lib_id)
            if title:
                if lib_id not in library_notes:
                    library_notes[lib_id] = {}
                library_notes[lib_id]['title'] = title
                updated = True
        
        if updated:
            save_library_notes(library_notes)
            if debug_mode:
                print(f"[INFO] Refreshed {len([lib_id for lib_id in selected_ids if library_notes.get(lib_id, {}).get('title')])} library titles")
        
        return jsonify({"success": True})
        
    except Exception as e:
        if debug_mode:
            print(f"[ERROR] Failed to refresh library titles: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route("/ajax/get-library-notes", methods=["GET"])
def ajax_get_library_notes():
    """Get updated library notes for AJAX updates"""
    if not session.get("admin_authenticated"):
        return jsonify({"success": False, "error": "Unauthorized"})
    
    try:
        library_notes = load_library_notes()
        return jsonify({"success": True, "library_notes": library_notes})
    except Exception as e:
        if debug_mode:
            print(f"[ERROR] Failed to get library notes: {e}")
        return jsonify({"success": False, "error": str(e)})

# --- Use os.path.join for all file paths ---
def download_and_cache_posters():
    """Download and cache posters for libraries"""
    # Get Plex credentials directly from environment
    plex_token = os.getenv("PLEX_TOKEN")
    plex_url = os.getenv("PLEX_URL")
    
    if not plex_token or not plex_url:
        if debug_mode:
            print(f"[ERROR] Plex credentials not available for poster download")
        return
    
    # Only download audiobook posters from ABS (no more Plex fallback)
    if os.getenv("ABS_ENABLED", "yes") == "yes":
        if debug_mode:
            print("[INFO] ABS enabled, downloading audiobook posters from ABS")
        download_abs_audiobook_posters()
    else:
        if debug_mode:
            print("[INFO] ABS disabled, skipping audiobook poster download")

def get_abs_headers():
    """Get headers for ABS API requests"""
    headers = {}
    abs_token = os.getenv("AUDIOBOOKSHELF_TOKEN")
    if abs_token:
        headers["Authorization"] = f"Bearer {abs_token}"
        if debug_mode:
            print("[DEBUG] Using ABS token for authentication")
    else:
        if debug_mode:
            print("[WARN] No ABS token provided, trying without authentication")
    return headers

def fetch_abs_libraries(abs_url, headers):
    """Fetch audiobook libraries from ABS API with improved error handling"""
    if debug_mode:
        print(f"[DEBUG] Fetching ABS libraries from: {abs_url}/api/libraries")
    
    # Apply rate limiting for ABS API
    check_api_rate_limit('abs')
    
    def api_call():
        timeout = config.get_int("ABS_API_TIMEOUT", 10)
        response = requests.get(f"{abs_url}/api/libraries", headers=headers, timeout=timeout)
        response.raise_for_status()  # This will raise HTTPError for bad status codes
        return response
    
    try:
        response = safe_api_call(api_call, operation_name="fetch_abs_libraries")
        response_data = response.json()
        libraries = response_data.get("libraries", [])
        
        if debug_mode:
            print(f"[DEBUG] Successfully fetched {len(libraries)} ABS libraries")
            for lib in libraries:
                if isinstance(lib, dict):
                    lib_id = lib.get("id", "Unknown")
                    lib_name = lib.get("name", "Unknown")
                    lib_type = lib.get("mediaType", "Unknown")
                    print(f"[DEBUG] Found ABS library: {lib_name} (ID: {lib_id}, Type: {lib_type})")
        return libraries
        
    except requests.exceptions.HTTPError as e:
        log_error("abs_api_error", f"ABS API returned error: {e.response.status_code}", 
                 {"status_code": e.response.status_code, "url": f"{abs_url}/api/libraries"})
        if debug_mode:
            print(f"[ERROR] Failed to connect to ABS API: HTTP {e.response.status_code}")
            print(f"[ERROR] Response content: {e.response.text[:200]}...")
        return None
    except requests.exceptions.Timeout:
        log_error("abs_api_timeout", "ABS API request timed out", {"url": f"{abs_url}/api/libraries"})
        if debug_mode:
            print(f"[ERROR] ABS API request timed out")
        return None
    except requests.exceptions.ConnectionError:
        log_error("abs_api_connection", "Failed to connect to ABS API", {"url": f"{abs_url}/api/libraries"})
        if debug_mode:
            print(f"[ERROR] Failed to connect to ABS API")
        return None
    except Exception as e:
        log_error("abs_api_unknown", f"Unexpected error fetching ABS libraries: {e}", {"url": f"{abs_url}/api/libraries"})
        if debug_mode:
            print(f"[ERROR] Error parsing ABS response: {e}")
        return None

def fetch_abs_books(abs_url, library_id, headers):
    """Fetch books from a specific ABS library with improved error handling"""
    if debug_mode:
        print(f"[DEBUG] Fetching books from ABS library {library_id}")
    
    # Apply rate limiting for ABS API
    check_api_rate_limit('abs')
    
    def api_call():
        timeout = config.get_int("ABS_API_TIMEOUT", 10)
        response = requests.get(f"{abs_url}/api/libraries/{library_id}/items", headers=headers, timeout=timeout)
        response.raise_for_status()
        return response
    
    try:
        response = safe_api_call(api_call, operation_name=f"fetch_abs_books_{library_id}")
        books_data = response.json()
        books = books_data.get("results", [])
        
        if debug_mode:
            print(f"[DEBUG] Successfully fetched {len(books)} books from ABS library {library_id}")
        return books
        
    except requests.exceptions.HTTPError as e:
        log_error("abs_books_api_error", f"ABS books API returned error: {e.response.status_code}", 
                 {"status_code": e.response.status_code, "library_id": library_id, "url": f"{abs_url}/api/libraries/{library_id}/items"})
        if debug_mode:
            print(f"[ERROR] Failed to get books from ABS library {library_id}: HTTP {e.response.status_code}")
        return None
    except requests.exceptions.Timeout:
        log_error("abs_books_api_timeout", "ABS books API request timed out", {"library_id": library_id})
        if debug_mode:
            print(f"[ERROR] ABS books API request timed out for library {library_id}")
        return None
    except requests.exceptions.ConnectionError:
        log_error("abs_books_api_connection", "Failed to connect to ABS books API", {"library_id": library_id})
        if debug_mode:
            print(f"[ERROR] Failed to connect to ABS books API for library {library_id}")
        return None
    except Exception as e:
        log_error("abs_books_api_unknown", f"Unexpected error fetching ABS books: {e}", {"library_id": library_id})
        if debug_mode:
            print(f"[ERROR] Error parsing books response for ABS library {library_id}: {e}")
        return None

def download_abs_book_poster(abs_url, book, library_id, audiobook_dir, poster_count, headers):
    """Download poster and metadata for a single ABS book"""
    media = book.get("media", {})
    cover_path = media.get("coverPath")
    metadata = media.get("metadata", {})
    title = metadata.get("title", "Unknown")
    author = metadata.get("authorName", "")
    item_id = book.get("id")
    
    if debug_mode:
        print(f"[DEBUG] Processing ABS book: {title} by {author} (ID: {item_id})")
    
    if not cover_path:
        if debug_mode:
            print(f"[DEBUG] No cover path for ABS book: {title}")
        return poster_count
    
    cover_url = f"{abs_url}/api/items/{item_id}/cover"
    if debug_mode:
        print(f"[DEBUG] Downloading cover for ABS book: {title} from {cover_url}")
    
    # Apply rate limiting for ABS API
    check_api_rate_limit('abs')
    
    cover_response = requests.get(cover_url, headers=headers, timeout=10)
    
    if cover_response.status_code != 200:
        if debug_mode:
            print(f"[ERROR] Failed to download cover for ABS book {title}: HTTP {cover_response.status_code}")
        return poster_count
    
    # Use the existing naming convention to maintain compatibility
    out_path = os.path.join(audiobook_dir, f"audiobook{poster_count+1}.webp")
    meta_path = os.path.join(audiobook_dir, f"audiobook{poster_count+1}.json")
    
    # Save the poster image
    with open(out_path, "wb") as f:
        f.write(cover_response.content)
    
    # Save the metadata
    meta_data = {
        "title": title,
        "author": author,
        "id": item_id,
        "library_id": library_id
    }
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta_data, f, ensure_ascii=False, indent=2)
    
    if debug_mode:
        print(f"[DEBUG] Successfully downloaded poster and metadata for ABS book: {title}")
    
    return poster_count + 1

def download_abs_audiobook_posters(check_local_first=False):
    """Download audiobook posters from ABS API"""
    global abs_download_in_progress, abs_download_completed
    
    abs_url = os.getenv("AUDIOBOOKSHELF_URL")
    if not abs_url:
        if debug_mode:
            print("[WARN] ABS enabled but AUDIOBOOKSHELF_URL not set")
        # Clear flags if no URL
        abs_download_in_progress = False
        abs_download_completed = True
        return
    
    if debug_mode:
        print(f"[INFO] Starting ABS audiobook poster download from: {abs_url}")
    
    # Check if posters need refreshing (skip if check_local_first is enabled)
    if not check_local_first and not should_refresh_abs_posters():
        if debug_mode:
            print("[DEBUG] Skipping ABS poster download - posters are recent")
        # Clear flags if no refresh needed
        abs_download_in_progress = False
        abs_download_completed = True
        return
    
    audiobook_dir = os.path.join("static", "posters", "audiobooks")
    os.makedirs(audiobook_dir, exist_ok=True)
    
    if debug_mode:
        print(f"[DEBUG] Using audiobook directory: {audiobook_dir}")
    
    try:
        headers = get_abs_headers()
        libraries = fetch_abs_libraries(abs_url, headers)
        
        if not libraries:
            if debug_mode:
                print("[WARN] No ABS libraries found or failed to fetch libraries")
            # Clear flags if no libraries
            abs_download_in_progress = False
            abs_download_completed = True
            return
        
        poster_count = 0
        book_libraries = [lib for lib in libraries if isinstance(lib, dict) and lib.get("mediaType") == "book"]
        
        if debug_mode:
            print(f"[DEBUG] Found {len(book_libraries)} book libraries in ABS")
        
        # Update progress to show ABS download is starting
        with poster_download_lock:
            poster_download_progress['abs'] = {
                'current': 0,
                'total': len(book_libraries),
                'library_name': 'Audiobookshelf',
                'type': 'abs'
            }
            
            # Update unified progress to show ABS is in progress
            if 'unified' in poster_download_progress:
                poster_download_progress['unified']['status'] = 'abs_downloading'
                poster_download_progress['unified']['message'] = 'Downloading Audiobookshelf posters...'
                poster_download_progress['unified']['current'] = 0
                poster_download_progress['unified']['total'] = len(book_libraries)
                poster_download_progress['unified']['last_update'] = time.time()
            
            # Update setup status to show ABS is in progress
            if 'abs_setup' in poster_download_progress:
                poster_download_progress['abs_setup']['status'] = 'in_progress'
                poster_download_progress['abs_setup']['total'] = len(book_libraries)
                poster_download_progress['abs_setup']['current'] = 0
            
            # Clear plex_setup status now that ABS downloads are starting
            if 'plex_setup' in poster_download_progress:
                if debug_mode:
                    print("[DEBUG] Clearing plex_setup status as ABS downloads are starting")
                del poster_download_progress['plex_setup']
        
        for i, library in enumerate(book_libraries):
            library_id = library.get("id")
            library_name = library.get("name", f"Library {library_id}")
            
            if debug_mode:
                print(f"[DEBUG] Processing ABS library: {library_name} (ID: {library_id})")
            
            # Update progress
            with poster_download_lock:
                if 'abs' in poster_download_progress:
                    poster_download_progress['abs']['current'] = i + 1
                    poster_download_progress['abs']['library_name'] = f'Audiobookshelf - {library_name}'
                
                # Update unified progress
                if 'unified' in poster_download_progress:
                    poster_download_progress['unified']['current'] = i + 1
                    poster_download_progress['unified']['message'] = f'Downloading posters for {library_name}...'
                
                # Update setup status
                if 'abs_setup' in poster_download_progress:
                    poster_download_progress['abs_setup']['current'] = i + 1
                    poster_download_progress['abs_setup']['message'] = f'Downloading posters for {library_name}...'
            
            books = fetch_abs_books(abs_url, library_id, headers)
            
            if books:
                if debug_mode:
                    print(f"[DEBUG] Processing {len(books)} books from ABS library {library_name}")
                
                for book in books:
                    poster_count = download_abs_book_poster(
                        abs_url, book, library_id, audiobook_dir, poster_count, headers
                    )
            else:
                if debug_mode:
                    print(f"[WARN] No books found in ABS library {library_name}")
        
        if debug_mode:
            print(f"[INFO] Completed ABS audiobook poster download: {poster_count} posters downloaded")
            
    except Exception as e:
        if debug_mode:
            print(f"[ERROR] Error downloading ABS audiobook posters: {e}")
            import traceback
            traceback.print_exc()
    finally:
        # Clear ABS progress when done
        with poster_download_lock:
            if 'abs' in poster_download_progress:
                del poster_download_progress['abs']
            
            # Update setup status to show completion or failure, then clear it
            if 'abs_setup' in poster_download_progress:
                if 'Exception' in str(locals().get('e', '')):
                    poster_download_progress['abs_setup']['status'] = 'failed'
                    poster_download_progress['abs_setup']['message'] = f'ABS download failed: {str(locals().get("e", ""))}'
                else:
                    poster_download_progress['abs_setup']['status'] = 'completed'
                    poster_download_progress['abs_setup']['message'] = f'ABS downloads completed ({poster_count} posters)'
                poster_download_progress['abs_setup']['end_time'] = time.time()
                # Clear the abs_setup status after a brief delay to allow the UI to show completion
                if debug_mode:
                    print("[DEBUG] ABS setup downloads completed, will clear status shortly")
        
        # Set completion flags
        abs_download_in_progress = False
        abs_download_completed = True
        abs_download_queued = False  # Reset queued flag when download completes
        
        # Save completion timestamp to prevent unnecessary re-downloads
        try:
            abs_completion_file = os.path.join("static", "posters", "audiobooks", ".last_completion")
            os.makedirs(os.path.dirname(abs_completion_file), exist_ok=True)
            with open(abs_completion_file, 'w') as f:
                f.write(str(time.time()))
            if debug_mode:
                print(f"[DEBUG] Saved ABS completion timestamp to {abs_completion_file}")
        except Exception as e:
            if debug_mode:
                print(f"[DEBUG] Could not save ABS completion timestamp: {e}")
        
        # Update unified status to show completion
        with poster_download_lock:
            if 'unified' in poster_download_progress:
                poster_download_progress['unified'].update({
                    'status': 'completed',
                    'message': f'All downloads completed! ({poster_count} ABS posters)',
                    'last_update': time.time(),
                    'end_time': time.time()
                })
        
        if debug_mode:
            print(f"[DEBUG] ABS poster download completed, flags cleared (abs_download_queued={abs_download_queued}, abs_download_completed={abs_download_completed})")
        
        # Clear the abs_setup status after a brief delay to allow the UI to show completion
        def clear_abs_setup_status():
            time.sleep(3)  # Wait 3 seconds for UI to show completion
            with poster_download_lock:
                if 'abs_setup' in poster_download_progress:
                    del poster_download_progress['abs_setup']
                    if debug_mode:
                        print("[DEBUG] Cleared abs_setup status from poster_download_progress")
        
        # Start the clearing thread
        import threading
        clear_thread = threading.Thread(target=clear_abs_setup_status, daemon=True)
        clear_thread.start()

def force_abs_poster_refresh():
    """Force refresh of ABS posters by clearing the download completion flag"""
    global abs_download_completed, abs_download_queued
    abs_download_completed = False
    abs_download_queued = False
    if debug_mode:
        print("[DEBUG] Forced ABS poster refresh - cleared completion and queued flags")

def download_single_poster_with_metadata(item, lib_dir, index, headers):
    """Download a single poster with metadata, with rate limiting and thread safety"""
    # Use a unique filename based on ratingKey to prevent race conditions
    rating_key = item.get('ratingKey', str(index))
    safe_filename = f"poster_{rating_key}"
    out_path = os.path.join(lib_dir, f"{safe_filename}.webp")
    meta_path = os.path.join(lib_dir, f"{safe_filename}.json")
    
    # Skip if already cached and recent (less than 24 hours old)
    if os.path.exists(out_path) and os.path.exists(meta_path):
        file_age = time.time() - os.path.getmtime(out_path)
        if file_age < 43200:  # 12 hours
            return True
    
    # Check download size limit before downloading
    max_size_bytes = POSTER_DOWNLOAD_LIMITS['max_download_size_mb'] * 1024 * 1024
    
    # Check available disk space before downloading
    try:
        import shutil
        total, used, free = shutil.disk_usage(lib_dir)
        free_mb = free / (1024 * 1024)
        if free_mb < 100:  # Less than 100MB free
            if debug_mode:
                print(f"[WARN] Low disk space ({free_mb:.1f}MB free), skipping poster download")
            return False
    except Exception as e:
        if debug_mode:
            print(f"[WARN] Could not check disk space: {e}")
    
    # If poster exists but metadata is missing, we need to recreate the metadata
    poster_exists = os.path.exists(out_path)
    meta_exists = os.path.exists(meta_path)
    
    try:
        # Get Plex credentials directly from environment
        plex_token = os.getenv("PLEX_TOKEN")
        plex_url = os.getenv("PLEX_URL")
        
        if not plex_token or not plex_url:
            if debug_mode:
                print(f"[ERROR] Plex credentials not available for poster download")
            return False
        
        # Download poster only if it doesn't exist
        if not poster_exists:
            # Apply rate limiting for Plex API
            check_api_rate_limit('plex')
            
            img_url = f"{plex_url}{item['thumb']}?X-Plex-Token={plex_token}"
            r = requests.get(img_url, headers=headers, timeout=10, stream=True)
            if r.status_code == 200:
                # Check content length for size limit
                content_length = r.headers.get('content-length')
                if content_length and int(content_length) > max_size_bytes:
                    if debug_mode:
                        print(f"[WARN] Poster too large ({content_length} bytes) for {item.get('title', 'Unknown')}")
                    return False
                
                # Stream download to check size and save
                content = b""
                for chunk in r.iter_content(chunk_size=8192):
                    content += chunk
                    if len(content) > max_size_bytes:
                        if debug_mode:
                            print(f"[WARN] Poster download exceeded size limit for {item.get('title', 'Unknown')}")
                        return False
                
                with open(out_path, "wb") as f:
                    f.write(content)
                if debug_mode:
                    log_info("poster_download", f"Downloaded poster for {item.get('title', 'Unknown')}", {"rating_key": rating_key, "size": len(content)})
            else:
                if debug_mode:
                    log_error("poster_download", f"Failed to download poster for {item.get('title', 'Unknown')}", {"rating_key": rating_key, "status_code": r.status_code})
                return False
            
            # Rate limiting - small delay between requests
            time.sleep(0.1)
        
        # Always try to fetch metadata (either for new items or items with missing metadata)
        guids = {"imdb": None, "tmdb": None, "tvdb": None}
        try:
            # Apply rate limiting for Plex API
            check_api_rate_limit('plex')
            
            meta_url = f"{plex_url}/library/metadata/{item['ratingKey']}"
            meta_resp = requests.get(meta_url, headers=headers, timeout=10)
            if meta_resp.status_code == 200:
                meta_root = ET.fromstring(meta_resp.content)
                for guid in meta_root.findall(".//Guid"):
                    gid = guid.attrib.get("id", "")
                    if gid.startswith("imdb://"):
                        guids["imdb"] = gid.replace("imdb://", "")
                    elif gid.startswith("tmdb://"):
                        guids["tmdb"] = gid.replace("tmdb://", "")
                    elif gid.startswith("tvdb://"):
                        guids["tvdb"] = gid.replace("tvdb://", "")
                if debug_mode:
                    print(f"[DEBUG] Fetched metadata for {item.get('title', 'Unknown')} (ratingKey: {rating_key})")
            else:
                if debug_mode:
                    print(f"[ERROR] Failed to fetch metadata for {item.get('title', 'Unknown')}: HTTP {meta_resp.status_code}")
        except Exception as e:
            if debug_mode:
                print(f"[ERROR] Error fetching GUIDs for {item['ratingKey']}: {e}")
        
        # Save metadata with thread-safe writing
        meta = {
            "title": item["title"],
            "ratingKey": item["ratingKey"],
            "year": item.get("year"),
            "thumb": item.get("thumb", ""),  # Add thumb field for comparison
            "imdb": guids["imdb"],
            "tmdb": guids["tmdb"],
            "tvdb": guids["tvdb"],
            "poster": f"{safe_filename}.webp"
        }
        
        # Write to temporary file first, then rename to prevent corruption
        temp_meta_path = meta_path + ".tmp"
        with open(temp_meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
        
        # Atomic rename (this is atomic on most filesystems)
        if os.path.exists(meta_path):
            os.remove(meta_path)
        os.rename(temp_meta_path, meta_path)
        
        if debug_mode:
            print(f"[DEBUG] Successfully saved metadata for {item.get('title', 'Unknown')} (ratingKey: {rating_key})")
        
        return True
    except Exception as e:
        if debug_mode:
            print(f"[ERROR] Error downloading poster/metadata for {item.get('title', 'Unknown')}: {e}")
        # Clean up partial files on error
        if not poster_exists and os.path.exists(out_path):
            try:
                os.remove(out_path)
            except:
                pass
        if os.path.exists(meta_path + ".tmp"):
            try:
                os.remove(meta_path + ".tmp")
            except:
                pass
        return False

def process_library_posters(lib, plex_url, headers, limit=None, background=False):
    """Process poster downloads for a single library"""
    section_id = lib["key"]
    library_name = lib["title"]
    
    # Check if posters need refreshing
    if not should_refresh_posters(section_id):
        if debug_mode:
            log_debug("library_posters", f"Skipping poster download for {library_name} - posters are recent", {"section_id": section_id})
        return 0
    
    lib_dir = get_library_poster_dir(section_id)
    os.makedirs(lib_dir, exist_ok=True)
    
    try:
        # Fetch library items
        url = f"{plex_url}/library/sections/{section_id}/all"
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        root = ET.fromstring(response.content)
        
        # Collect items
        items = []
        for el in root.findall(".//Video"):
            thumb = el.attrib.get("thumb")
            rating_key = el.attrib.get("ratingKey")
            title = el.attrib.get("title")
            year = el.attrib.get("year")
            if thumb and rating_key:
                items.append({"thumb": thumb, "ratingKey": rating_key, "title": title, "year": year})
        
        for el in root.findall(".//Directory"):
            thumb = el.attrib.get("thumb")
            rating_key = el.attrib.get("ratingKey")
            title = el.attrib.get("title")
            if thumb and rating_key and not any(i["ratingKey"] == rating_key for i in items):
                items.append({"thumb": thumb, "ratingKey": rating_key, "title": title})
        
        # Shuffle and limit
        random.shuffle(items)
        if limit is not None:
            items = items[:limit]
        
        if debug_mode:
            log_info("library_posters", f"Processing {len(items)} items for library {lib['title']}", {"section_id": section_id, "items_count": len(items)})
        
        # Process items with ThreadPoolExecutor for parallel downloads
        successful_downloads = 0
        
        # Update status to indicate processing has started
        if background:
            with poster_download_lock:
                # Initialize or update progress for this library with library name
                if section_id not in poster_download_progress:
                    poster_download_progress[section_id] = {}
                poster_download_progress[section_id].update({
                    'current': 0,
                    'total': len(items),
                    'successful': 0,
                    'status': 'processing',
                    'library_name': library_name,
                    'last_update': time.time()
                })
                
                # Update setup status to show Plex is in progress
                if 'plex_setup' in poster_download_progress:
                    poster_download_progress['plex_setup']['status'] = 'in_progress'
                    poster_download_progress['plex_setup']['current'] = 0
                    poster_download_progress['plex_setup']['total'] = len(items)
                    poster_download_progress['plex_setup']['message'] = f'Downloading posters for {library_name}...'
        
        with ThreadPoolExecutor(max_workers=POSTER_DOWNLOAD_LIMITS['max_concurrent_downloads']) as executor:
            futures = []
            for i, item in enumerate(items):
                future = executor.submit(download_single_poster_with_metadata, item, lib_dir, i, headers)
                futures.append(future)
            
            # Wait for completion with progress tracking
            for i, future in enumerate(as_completed(futures)):
                if future.result():
                    successful_downloads += 1
                if background and i % 5 == 0:  # Update progress every 5 items
                    with poster_download_lock:
                        if section_id in poster_download_progress:
                            poster_download_progress[section_id].update({
                                'current': i + 1,
                                'total': len(items),
                                'successful': successful_downloads,
                                'status': 'processing',
                                'library_name': library_name,
                                'last_update': time.time()
                            })
                        
                        # Update setup status
                        if 'plex_setup' in poster_download_progress:
                            poster_download_progress['plex_setup']['current'] = i + 1
                            poster_download_progress['plex_setup']['message'] = f'Downloading posters for {library_name} ({i + 1}/{len(items)})'
            
            if debug_mode:
                log_info("library_posters", f"Downloaded {successful_downloads}/{len(items)} posters for library {lib['title']}", {"section_id": section_id, "successful": successful_downloads, "total": len(items)})
            
            # Clear progress for this library when complete
            with poster_download_lock:
                if section_id in poster_download_progress:
                    del poster_download_progress[section_id]
            
            return successful_downloads
            
    except Exception as e:
        if debug_mode:
            print(f"Error fetching posters for section {section_id}: {e}")
        return 0

def download_and_cache_posters_for_libraries(libraries, limit=None, background=False, incremental_mode=False, check_local_first=False):
    """Optimized poster downloading with background processing and rate limiting"""
    if not libraries:
        return
    
    # Check queue size to prevent memory overflow
    if poster_download_queue.qsize() >= POSTER_DOWNLOAD_LIMITS['max_downloads_per_hour']:
        if debug_mode:
            log_warning("poster_download", f"Download queue is full ({poster_download_queue.qsize()} items), skipping new downloads")
        return
    
    if debug_mode:
        log_debug("poster_download", f"download_and_cache_posters_for_libraries called with {len(libraries)} libraries", {"background": background, "incremental": incremental_mode, "check_local_first": check_local_first})
    
    # Get Plex credentials directly from environment to ensure latest values
    plex_token = os.getenv("PLEX_TOKEN")
    plex_url = os.getenv("PLEX_URL")
    
    if not plex_token or not plex_url:
        if debug_mode:
            log_error("poster_download", "Plex credentials not available", {"token_set": bool(plex_token), "url_set": bool(plex_url)})
        return
    
    # If check_local_first is enabled, use incremental mode to only download missing posters
    if check_local_first:
        if debug_mode:
            log_debug("poster_download", "check_local_first enabled, using incremental mode to check local files first")
        incremental_mode = True
    
    headers = {"X-Plex-Token": plex_token}
    
    if background:
        # Queue for background processing with incremental mode flag
        poster_download_queue.put(('libraries', libraries, limit, incremental_mode))
        if debug_mode:
            log_debug("poster_download", f"Queued {len(libraries)} libraries for background processing", {"incremental": incremental_mode, "queue_size": poster_download_queue.qsize()})
        return True
    else:
        # Process immediately
        total_downloaded = 0
        total_removed = 0
        for lib in libraries:
            if incremental_mode:
                downloaded, removed = process_library_posters_incremental(lib, plex_url, headers, background)
                total_downloaded += downloaded
                total_removed += removed
            else:
                downloaded = process_library_posters(lib, plex_url, headers, limit, background)
                total_downloaded += downloaded
        
        if debug_mode and incremental_mode:
            log_info("poster_download", f"Incremental refresh complete: {total_downloaded} new posters downloaded, {total_removed} deleted posters removed")
        
        return total_downloaded

def background_poster_worker():
    """Background worker for poster downloads with improved error handling and recovery"""
    global poster_download_running, abs_download_in_progress, abs_download_completed, abs_download_queued
    poster_download_running = True
    
    log_debug("worker", "Background poster worker started", {"worker_type": "poster_download"})
    
    # Cleanup counter for periodic memory cleanup
    cleanup_counter = 0
    
    while poster_download_running:
        try:
            # Periodic memory cleanup every 50 operations
            cleanup_counter += 1
            if cleanup_counter >= 50:
                cleanup_poster_progress()
                cleanup_counter = 0
            
            # Wait for work with timeout
            work_item = poster_download_queue.get(timeout=1)
            if work_item is None:  # Shutdown signal
                break
            
            # Handle different work item formats
            if len(work_item) == 3:
                work_type, data, limit = work_item
                incremental_mode = False
                check_local_first = False
                smart_data = None
            elif len(work_item) == 4:
                work_type, data, limit, incremental_mode = work_item
                check_local_first = False
                smart_data = None
            elif len(work_item) == 5:
                work_type, data, limit, incremental_mode, check_local_first = work_item
                smart_data = None
            elif len(work_item) == 6:
                work_type, data, limit, incremental_mode, check_local_first, smart_data = work_item
            else:
                log_debug("worker", f"Invalid work item format: {work_item}", {"work_item_length": len(work_item)})
                continue
            
            log_debug("worker", f"Processing work item: {work_type}", {"work_type": work_type, "data_size": len(data) if isinstance(data, list) else "N/A"})
            
            if work_type == 'libraries':
                log_debug("worker", f"Starting library poster download for {len(data)} libraries", {"libraries_count": len(data)})
                
                # Use retry mechanism for library downloads
                def download_libraries():
                    return download_and_cache_posters_for_libraries(data, limit, background=False, incremental_mode=incremental_mode, check_local_first=False)
                
                try:
                    retry_operation(download_libraries, max_retries=3, delay=5.0, 
                                  operation_name=f"library_poster_download_{len(data)}_libraries")
                    log_debug("worker", f"Completed library poster download for {len(data)} libraries", {"libraries_count": len(data)})
                    
                    # Update unified status to show Plex downloads completed
                    with poster_download_lock:
                        if 'unified' in poster_download_progress and poster_download_progress['unified']['status'] == 'plex_downloading':
                            poster_download_progress['unified'].update({
                                'status': 'plex_completed',
                                'message': 'Plex downloads completed, waiting for ABS...',
                                'last_update': time.time()
                            })
                            if debug_mode:
                                print("[DEBUG] Updated unified status to plex_completed")
                except Exception as e:
                    log_error("worker", f"Failed to download library posters after retries", {"libraries_count": len(data)}, e)
                    
            elif work_type == 'smart_plex':
                log_debug("worker", f"Starting smart Plex poster download for {len(data)} libraries", {"libraries_count": len(data)})
                
                # Process smart Plex downloads using the smart check results
                smart_results = smart_data if smart_data else []
                
                try:
                    # Process each library with its smart results
                    for i, lib in enumerate(data):
                        if i < len(smart_results):
                            smart_result = smart_results[i]
                            
                            # Update progress for this library
                            with poster_download_lock:
                                if 'unified' in poster_download_progress:
                                    poster_download_progress['unified'].update({
                                        'current': i + 1,
                                        'total': len(data),
                                        'message': f'Downloading posters for {lib["title"]}...',
                                        'last_update': time.time()
                                    })
                                
                                # Also update individual library progress for frontend compatibility
                                lib_id = lib["key"]
                                if lib_id not in poster_download_progress:
                                    poster_download_progress[lib_id] = {}
                                poster_download_progress[lib_id].update({
                                    'current': 0,
                                    'total': len(smart_result.get('new_items', [])) + len(smart_result.get('changed_items', [])),
                                    'library_name': lib["title"],
                                    'status': 'processing',
                                    'last_update': time.time()
                                })
                            
                            # Process new and changed items for this library
                            if smart_result['new_items'] or smart_result['changed_items']:
                                process_smart_library_download(lib, smart_result)
                        
                        # Small delay to prevent overwhelming the server
                        time.sleep(0.1)
                    
                    log_debug("worker", f"Completed smart Plex poster download for {len(data)} libraries", {"libraries_count": len(data)})
                    
                    # Update unified status to show Plex downloads completed
                    with poster_download_lock:
                        if 'unified' in poster_download_progress and poster_download_progress['unified']['status'] == 'plex_downloading':
                            poster_download_progress['unified'].update({
                                'status': 'plex_completed',
                                'message': 'Plex downloads completed, waiting for ABS...',
                                'last_update': time.time()
                            })
                            if debug_mode:
                                print("[DEBUG] Updated unified status to plex_completed")
                except Exception as e:
                    log_error("worker", f"Failed to download smart Plex posters", {"libraries_count": len(data)}, e)
                    
            elif work_type == 'abs':
                abs_download_in_progress = True
                abs_download_completed = False
                abs_download_queued = False  # Reset queued flag since we're now processing
                
                log_debug("worker", "Starting ABS audiobook poster download", {"work_type": "abs_download", "check_local_first": check_local_first})
                
                # Use retry mechanism for ABS downloads
                def download_abs():
                    return download_abs_audiobook_posters(check_local_first=check_local_first)
                
                try:
                    retry_operation(download_abs, max_retries=3, delay=10.0, 
                                  operation_name="abs_audiobook_poster_download")
                    abs_download_in_progress = False
                    abs_download_completed = True
                    log_debug("worker", "Completed ABS poster download", {"work_type": "abs_download"})
                except Exception as e:
                    abs_download_in_progress = False
                    abs_download_completed = False
                    log_error("worker", "Failed to download ABS posters after retries", {"work_type": "abs_download"}, e)
                    
            elif work_type == 'smart_abs':
                abs_download_in_progress = True
                abs_download_completed = False
                abs_download_queued = False
                
                log_debug("worker", "Starting smart ABS audiobook poster download", {"work_type": "smart_abs_download"})
                
                # Get smart ABS results
                smart_result = smart_data if smart_data else None
                
                try:
                    # Update unified status to show ABS downloads starting
                    with poster_download_lock:
                        if 'unified' in poster_download_progress:
                            poster_download_progress['unified'].update({
                                'status': 'abs_downloading',
                                'message': 'Downloading Audiobookshelf posters...',
                                'current': 0,
                                'total': len(smart_result['new_items']) + len(smart_result['changed_items']) if smart_result else 0,
                                'last_update': time.time()
                            })
                    
                    # Process smart ABS downloads
                    if smart_result and (smart_result['new_items'] or smart_result['changed_items']):
                        process_smart_abs_download(smart_result)
                    
                    abs_download_in_progress = False
                    abs_download_completed = True
                    
                    # Save completion timestamp to prevent unnecessary re-downloads
                    try:
                        abs_completion_file = os.path.join("static", "posters", "audiobooks", ".last_completion")
                        os.makedirs(os.path.dirname(abs_completion_file), exist_ok=True)
                        with open(abs_completion_file, 'w') as f:
                            f.write(str(time.time()))
                        if debug_mode:
                            print(f"[DEBUG] Saved ABS completion timestamp to {abs_completion_file}")
                    except Exception as e:
                        if debug_mode:
                            print(f"[DEBUG] Could not save ABS completion timestamp: {e}")
                    
                    # Update unified status to show completion
                    with poster_download_lock:
                        if 'unified' in poster_download_progress:
                            poster_download_progress['unified'].update({
                                'status': 'completed',
                                'message': 'All downloads completed!',
                                'end_time': time.time()
                            })
                    
                    log_debug("worker", "Completed smart ABS poster download", {"work_type": "smart_abs_download"})
                except Exception as e:
                    abs_download_in_progress = False
                    abs_download_completed = False
                    log_error("worker", "Failed to download smart ABS posters", {"work_type": "smart_abs_download"}, e)
            
            # Clear regular progress when work is complete, but preserve setup status
            with poster_download_lock:
                # Keep setup-specific status entries including unified status
                setup_keys = ['plex_setup', 'abs_setup', 'setup_error', 'unified']
                regular_progress = {k: v for k, v in poster_download_progress.items() if k not in setup_keys}
                poster_download_progress.clear()
                # Restore setup status
                for key in setup_keys:
                    if key in regular_progress:
                        poster_download_progress[key] = regular_progress[key]
                
                # If Plex setup is completed but ABS is enabled and not started yet, keep plex_setup status
                if ('plex_setup' in poster_download_progress and 
                    poster_download_progress['plex_setup']['status'] == 'completed' and
                    os.getenv("ABS_ENABLED", "yes") == "yes" and
                    'abs_setup' not in poster_download_progress):
                    # Keep plex_setup status until ABS downloads start
                    if debug_mode:
                        log_debug("worker", "Keeping plex_setup status until ABS downloads start")
            
            poster_download_queue.task_done()
            
        except queue.Empty:
            continue
        except Exception as e:
            log_error("worker", "Unexpected error in background poster worker", {"work_type": work_type if 'work_type' in locals() else "unknown"}, e)
            # Continue processing other work items instead of crashing
    
    log_debug("worker", "Background poster worker stopped", {"worker_type": "poster_download"})

def start_background_poster_worker():
    """Start the background poster download worker"""
    global poster_download_running, abs_download_completed, abs_download_queued
    if not poster_download_running:
        poster_download_running = True
        worker_thread = threading.Thread(target=background_poster_worker, daemon=True)
        worker_thread.start()
        if debug_mode:
            print("[INFO] Started background poster download worker")
    else:
        if debug_mode:
            print("[DEBUG] Background poster worker already running, skipping start")
        # Small delay to ensure worker is ready
        time.sleep(0.5)
        # Reset ABS download status when starting new worker
        abs_download_completed = False
        abs_download_queued = False

def get_poster_download_progress():
    """Get current poster download progress"""
    with poster_download_lock:
        return poster_download_progress.copy()

def is_poster_download_in_progress():
    """Check if poster downloads are currently in progress"""
    with poster_download_lock:
        return len(poster_download_progress) > 0

def should_wait_for_posters():
    """Determine if we should wait for poster downloads to complete"""
    global abs_download_in_progress, abs_download_queued, poster_download_running, poster_download_queue
    
    # Check unified download status first (for setup_complete route)
    with poster_download_lock:
        if 'unified' in poster_download_progress:
            unified_status = poster_download_progress['unified']['status']
            if unified_status in ['plex_downloading', 'abs_downloading', 'starting', 'plex_completed', 'checking']:
                if debug_mode:
                    print(f"[DEBUG] Unified downloads in progress (status: {unified_status}), waiting...")
                return True
            elif unified_status in ['no_downloads_needed', 'server_offline', 'completed']:
                if debug_mode:
                    print(f"[DEBUG] Unified downloads finished (status: {unified_status}), not waiting...")
                return False
    
    # Check if poster downloads are in progress (for regular background downloads)
    if is_poster_download_in_progress():
        if debug_mode:
            progress = get_poster_download_progress()
            print(f"[DEBUG] Poster downloads in progress: {list(progress.keys())}")
        return True
    
    # Check if ABS downloads are in progress - this is the key fix
    if abs_download_in_progress:
        if debug_mode:
            print("[DEBUG] ABS poster downloads in progress, waiting...")
        return True
    
    # Check if ABS download is queued but not yet started
    if abs_download_queued:
        if debug_mode:
            print("[DEBUG] ABS poster downloads queued, waiting...")
        return True
    
    # Check if there are items in the download queue (but exclude periodic refresh jobs)
    try:
        queue_size = poster_download_queue.qsize()
        if queue_size > 0:
            # Don't wait for periodic refresh jobs - they can run in the background
            # Only wait for essential setup downloads
            if debug_mode:
                print(f"[DEBUG] Found {queue_size} items in poster download queue, but not waiting for periodic refresh")
            return False  # Changed from True to False - don't wait for queue items
    except Exception as e:
        if debug_mode:
            print(f"[DEBUG] Error checking queue size: {e}")
    
    # Check if worker is actively processing (but don't wait for periodic refresh)
    if poster_download_running and not poster_download_queue.empty():
        if debug_mode:
            print("[DEBUG] Worker is running but queue not empty, but not waiting for periodic refresh")
        return False  # Changed from True to False - don't wait for queue processing
    
    return False

def wait_for_poster_completion(timeout_seconds=300):
    """Wait for poster downloads to complete with timeout"""
    start_time = time.time()
    
    if debug_mode:
        print(f"[DEBUG] Waiting for poster completion with {timeout_seconds}s timeout...")
    
    while should_wait_for_posters():
        if time.time() - start_time > timeout_seconds:
            if debug_mode:
                print(f"[WARN] Poster download timeout reached after {timeout_seconds} seconds")
            return False
        
        # Log progress every 10 seconds
        elapsed = time.time() - start_time
        if debug_mode and int(elapsed) % 10 == 0:
            print(f"[DEBUG] Still waiting for posters... ({elapsed:.1f}s elapsed)")
        
        time.sleep(1)
    
    if debug_mode:
        print(f"[DEBUG] Poster completion wait finished after {time.time() - start_time:.1f}s")
    
    return True

def get_restart_delay_for_changes(changed_settings):
    """Calculate restart delay based on what settings changed"""
    # Immediate restart settings (5 seconds) - no poster downloads needed
    immediate_settings = {
        'server_name', 'accent_color_text', 'quick_access_enabled',
        'qa_plex_enabled', 'qa_audiobookshelf_enabled', 'qa_tautulli_enabled',
        'qa_overseerr_enabled', 'qa_jellyseerr_enabled', 'ip_management_enabled',
        'discord_webhook', 'discord_username', 'discord_avatar', 'discord_color',
        'discord_notify_plex', 'discord_notify_abs', 'discord_notify_rate_limiting',
        'discord_notify_ip_management', 'discord_notify_login_attempts',
        'discord_notify_form_rate_limiting', 'library_carousels', 'library_carousel_order'
    }
    
    # Poster-dependent settings (adaptive delay) - need to wait for poster downloads
    poster_dependent_settings = {
        'plex_token', 'library_ids', 'audiobooks_id', 'audiobookshelf_url',
        'audiobookshelf_token', 'abs_enabled'
    }
    
    # Check if any poster-dependent settings changed
    if any(setting in changed_settings for setting in poster_dependent_settings):
        return "adaptive"
    
    # Check if any immediate settings changed
    if any(setting in changed_settings for setting in immediate_settings):
        return IMMEDIATE_RESTART_DELAY
    
    # Default to immediate delay for any other changes
    return IMMEDIATE_RESTART_DELAY

def is_restart_ready():
    """Check if system is ready for restart"""
    # If no poster downloads are in progress, we're ready
    if not should_wait_for_posters():
        return True
    
    # If we've been waiting too long, proceed anyway
    return False



def get_adaptive_restart_delay():
    """Calculate adaptive restart delay based on current operations"""
    if debug_mode:
        print("[DEBUG] Calculating adaptive restart delay...")
    
    if should_wait_for_posters():
        if debug_mode:
            print("[DEBUG] Poster downloads in progress, waiting for completion...")
        # Wait for posters with timeout
        if wait_for_poster_completion(POSTER_DOWNLOAD_TIMEOUT):
            if debug_mode:
                print("[DEBUG] Poster downloads completed successfully, quick restart")
            return 5  # Quick restart after posters complete
        else:
            if debug_mode:
                print("[DEBUG] Poster download timeout reached, short delay")
            return 10  # Short delay if timeout reached
    else:
        if debug_mode:
            print("[DEBUG] No poster downloads in progress, immediate restart")
        return IMMEDIATE_RESTART_DELAY

def strip_articles(title):
    """Strip articles (A, An, The) from the beginning of a title for sorting purposes."""
    if not title:
        return title
    
    # Remove leading whitespace and convert to lowercase for comparison
    title_clean = title.strip()
    title_lower = title_clean.lower()
    
    # Check for articles at the beginning
    if title_lower.startswith('the '):
        return title_clean[4:].strip()  # Remove "The " and any trailing whitespace
    elif title_lower.startswith('a '):
        return title_clean[2:].strip()  # Remove "A " and any trailing whitespace
    elif title_lower.startswith('an '):
        return title_clean[3:].strip()  # Remove "An " and any trailing whitespace
    
    return title_clean

def group_titles_by_letter(titles):
    groups = defaultdict(list)
    for title in titles:
        # Strip articles for sorting purposes
        sort_title = strip_articles(title)
        
        # Check if sort_title starts with a digit
        if sort_title and sort_title[0].isdigit():
            groups['0-9'].append(title)
        else:
            # Find the first ASCII letter in the sort_title
            match = re.search(r'[A-Za-z]', sort_title)
            if match:
                letter = match.group(0).upper()
                groups[letter].append(title)
            elif any(c.isdigit() for c in sort_title):
                groups['0-9'].append(title)
            else:
                groups['Other'].append(title)
    # Sort groups alphabetically, but put 'Other' at the end
    sorted_keys = sorted([k for k in groups if k != 'Other'], key=lambda x: (x != '0-9', x))
    if 'Other' in groups:
        sorted_keys.append('Other')
    return OrderedDict((k, sorted(groups[k], key=lambda t: strip_articles(t).casefold())) for k in sorted_keys)

def group_posters_by_letter(posters):
    groups = defaultdict(list)
    for poster in posters:
        title = poster.get("title", "")
        # Strip articles for sorting purposes
        sort_title = strip_articles(title)
        
        match = re.search(r'[A-Za-z]', sort_title)
        if match:
            letter = match.group(0).upper()
            groups[letter].append(poster)
        elif any(c.isdigit() for c in sort_title):
            groups['0-9'].append(poster)
        else:
            groups['Other'].append(poster)
    sorted_keys = sorted([k for k in groups if k != 'Other'], key=lambda x: (x != '0-9', x))
    if 'Other' in groups:
        sorted_keys.append('Other')
    return OrderedDict((k, sorted(groups[k], key=lambda p: strip_articles(p.get("title", "")).casefold())) for k in sorted_keys)

def group_books_by_letter(books):
    groups = defaultdict(list)
    for book in books:
        title = book.get("title", "")
        # Strip articles for sorting purposes
        sort_title = strip_articles(title)
        
        match = re.search(r'[A-Za-z]', sort_title)
        if match:
            letter = match.group(0).upper()
            groups[letter].append(book)
        elif any(c.isdigit() for c in sort_title):
            groups['0-9'].append(book)
        else:
            groups['Other'].append(book)
    sorted_keys = sorted([k for k in groups if k != 'Other'], key=lambda x: (x != '0-9', x))
    if 'Other' in groups:
        sorted_keys.append('Other')
    return OrderedDict((k, sorted(groups[k], key=lambda b: strip_articles(b.get("title", "")).casefold())) for k in sorted_keys)

def fetch_titles_for_library(section_id):
    """Fetch library titles from cached poster metadata or Plex API as fallback"""
    titles = []
    if not section_id:
        return titles
    
    # Use cached poster metadata instead of live Plex queries
    poster_dir = get_library_poster_dir(section_id)
    if os.path.exists(poster_dir):
        # Get all JSON files
        json_files = [f for f in os.listdir(poster_dir) if f.endswith(".json")]
        
        for fname in json_files:
            meta_path = os.path.join(poster_dir, fname)
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                
                title = meta.get("title")
                if title and title not in titles:
                    titles.append(title)
            except Exception as e:
                if debug_mode:
                    print(f"Error loading cached metadata from {meta_path}: {e}")
                continue
    
    # If no cached data available, fall back to Plex API (but this should be rare)
    if not titles:
        if debug_mode:
            print(f"[DEBUG] No cached data for section {section_id}, falling back to Plex API")
        
        # Get Plex credentials directly from environment
        plex_token = os.getenv("PLEX_TOKEN")
        plex_url = os.getenv("PLEX_URL")
        
        if not plex_token or not plex_url:
            if debug_mode:
                print("[ERROR] Plex credentials not available for fetching titles")
            return titles
        
        headers = {"X-Plex-Token": plex_token}
        url = f"{plex_url}/library/sections/{section_id}/all"
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            root = ET.fromstring(response.content)
            for el in root.findall(".//Video"):
                title = el.attrib.get("title")
                if title:
                    titles.append(title)
            for el in root.findall(".//Directory"):
                title = el.attrib.get("title")
                if title and title not in titles:
                    titles.append(title)
        except Exception as e:
            if debug_mode:
                print(f"Error fetching titles for section {section_id}: {e}")
    
    return titles

def fetch_audiobooks_from_cache():
    """Fetch audiobooks from cached ABS data only (no Plex fallback)"""
    books = {}
    abs_enabled = os.getenv("ABS_ENABLED", "yes") == "yes"
    
    if not abs_enabled:
        return books
    
    # Load cached audiobook data from static/posters/audiobooks
    audiobook_dir = os.path.join("static", "posters", "audiobooks")
    if os.path.exists(audiobook_dir):
        # Get all JSON files
        json_files = [f for f in os.listdir(audiobook_dir) if f.endswith(".json")]
        
        for fname in json_files:
            meta_path = os.path.join(audiobook_dir, fname)
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                
                title = meta.get("title")
                author = meta.get("author", "Unknown Author")
                
                if title and author:
                    if author not in books:
                        books[author] = []
                    books[author].append(title)
            except Exception as e:
                if debug_mode:
                    print(f"[WARN] Error loading cached audiobook metadata from {meta_path}: {e}")
                continue
    
    return books

def fetch_abs_books_from_cache():
    """Fetch ABS books from cached data only (no Plex fallback)"""
    abs_books = []
    abs_enabled = os.getenv("ABS_ENABLED", "yes") == "yes"
    if not abs_enabled:
        return abs_books
    
    # Load cached audiobook data from static/posters/audiobooks
    audiobook_dir = os.path.join("static", "posters", "audiobooks")
    if os.path.exists(audiobook_dir):
        # Get all JSON files
        json_files = [f for f in os.listdir(audiobook_dir) if f.endswith(".json")]
        
        for fname in json_files:
            meta_path = os.path.join(audiobook_dir, fname)
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                
                title = meta.get("title")
                author = meta.get("author")
                
                # Extract the number from the filename (e.g., "audiobook99.json" -> "99")
                # and construct the corresponding webp filename
                if fname.startswith("audiobook") and fname.endswith(".json"):
                    number = fname[9:-5]  # Remove "audiobook" prefix and ".json" suffix
                    cover_file = f"audiobook{number}.webp"
                    cover_path = os.path.join(audiobook_dir, cover_file)
                    
                    # Only include if the cover file actually exists
                    if os.path.exists(cover_path):
                        cover_url = f"/static/posters/audiobooks/{cover_file}"
                    else:
                        cover_url = None
                else:
                    cover_url = None
                
                if title:
                    abs_books.append({
                        "title": title,
                        "author": author,
                        "cover": cover_url,
                    })
            except Exception as e:
                    if debug_mode:
                        print(f"[ABS] Error loading cached audiobook metadata from {meta_path}: {e}")
                    continue
        
        return abs_books

@app.route("/audiobook-covers")
def get_random_audiobook_covers():
    if os.getenv("ABS_ENABLED", "yes") != "yes":
        return ("Not Found", 404)
    
    # Check which audiobook poster files actually exist
    audiobook_dir = os.path.join("static", "posters", "audiobooks")
    existing_paths = []
    for i in range(25):
        poster_path = os.path.join(audiobook_dir, f"audiobook{i+1}.webp")
        if os.path.exists(poster_path):
            existing_paths.append(f"/static/posters/audiobooks/audiobook{i+1}.webp")
    
    random.shuffle(existing_paths)
    return jsonify(existing_paths)

@app.route("/audiobook-covers-with-links")
def get_random_audiobook_covers_with_links():
    if os.getenv("ABS_ENABLED", "yes") != "yes":
        return ("Not Found", 404)
    
    # Check which audiobook poster files actually exist
    audiobook_dir = os.path.join("static", "posters", "audiobooks")
    existing_paths = []
    goodreads_links = []
    titles = []
    
    for i in range(25):
        poster_path = os.path.join(audiobook_dir, f"audiobook{i+1}.webp")
        if os.path.exists(poster_path):
            poster_url = f"/static/posters/audiobooks/audiobook{i+1}.webp"
            existing_paths.append(poster_url)
            
            # Try to get actual title and author from metadata if available
            json_path = os.path.join(audiobook_dir, f"audiobook{i+1}.json")
            search_query = ""
            title = ""
            
            try:
                if os.path.exists(json_path):
                    with open(json_path, 'r', encoding='utf-8') as f:
                        meta = json.load(f)
                        title = meta.get('title', '')
                        author = meta.get('author', '')
                        
                        if title and author:
                            search_query = f"{author} {title}"
                        elif title:
                            search_query = title
                        else:
                            # Fallback to generic filename if no metadata
                            title = f"audiobook{i+1}".replace('_', ' ').replace('-', ' ').title()
                            search_query = title
                else:
                    # Fallback to generic filename if no JSON file
                    title = f"audiobook{i+1}".replace('_', ' ').replace('-', ' ').title()
                    search_query = title
            except (IOError, json.JSONDecodeError):
                # Fallback to generic filename if JSON read fails
                title = f"audiobook{i+1}".replace('_', ' ').replace('-', ' ').title()
                search_query = title
            
            # Create Goodreads search URL with proper URL encoding
            import urllib.parse
            encoded_query = urllib.parse.quote(search_query)
            goodreads_url = f"https://www.goodreads.com/search?q={encoded_query}"
            goodreads_links.append(goodreads_url)
            titles.append(title)
    
    # Shuffle all arrays in the same order
    combined = list(zip(existing_paths, goodreads_links, titles))
    random.shuffle(combined)
    existing_paths, goodreads_links, titles = zip(*combined) if combined else ([], [], [])
    
    return jsonify({
        "posters": existing_paths,
        "goodreads_links": goodreads_links,
        "titles": titles
    })

def is_setup_complete():
    # Always reload from .env to get the latest setup status
    from dotenv import load_dotenv
    load_dotenv(override=True)
    return os.getenv("SETUP_COMPLETE") == "1"

@app.before_request
def check_setup():
    allowed_endpoints = {"setup", "setup_complete", "fetch_libraries", "static", "ajax_check_rate_limit", "ajax_ip_management", "ajax_get_ip_lists", "ajax_rate_limit_settings", "ajax_get_rate_limit_settings"}
    if not is_setup_complete():
        # Allow setup page, setup_complete page, fetch-libraries API, static files, rate limit check, and IP management
        if request.endpoint not in allowed_endpoints and not request.path.startswith("/static"):
            return redirect(url_for("setup"))

def restart_container_delayed():
    """Restart the container with proper poster download completion handling"""
    if debug_mode:
        print("[INFO] Preparing for restart...")
    
    # Wait for poster downloads to complete before restarting
    max_wait_time = 600  # 10 minutes timeout
    start_time = time.time()
    
    while should_wait_for_posters() and (time.time() - start_time) < max_wait_time:
        if debug_mode:
            print("[DEBUG] Waiting for poster downloads to complete before restart...")
        time.sleep(2)
    
    if should_wait_for_posters():
        if debug_mode:
            print("[WARN] Poster downloads did not complete within timeout, restarting anyway")
    else:
        if debug_mode:
            print("[INFO] Poster downloads completed, proceeding with restart")
    
    time.sleep(2)  # Give browser time to receive the response
    
    # Instead of killing the process, just reload the configuration
    # This allows background threads to continue running
    if debug_mode:
        print("[INFO] Reloading configuration instead of full restart to preserve background downloads")
    
    # Reload environment variables
    reload_config()
    
    # Clear any cached data that might need refreshing
    clear_library_cache()
    
    if debug_mode:
        print("[INFO] Configuration reloaded successfully")

@app.route("/trigger_restart", methods=["POST"])
@csrf.exempt
def trigger_restart():
    threading.Thread(target=restart_container_delayed, daemon=True).start()
    return jsonify({"status": "restarting"})

@app.route("/check-restart-readiness", methods=["GET"])
@limiter.exempt  # Exempt from rate limiting
@csrf.exempt
def check_restart_readiness():
    """Check if the system is ready for restart"""
    try:
        should_wait = should_wait_for_posters()
        ready = not should_wait  # Ready if we don't need to wait for posters
        
        poster_status = {
            "in_progress": is_poster_download_in_progress(),
            "worker_running": poster_download_running,
            "queue_size": poster_download_queue.qsize() if hasattr(poster_download_queue, 'qsize') else 0,
            "progress": get_poster_download_progress()
        }
        
        # Add unified download status
        setup_download_status = {}
        current_phase = "idle"
        with poster_download_lock:
            if 'unified' in poster_download_progress:
                unified_status = poster_download_progress['unified']
                setup_download_status['unified'] = unified_status
                
                # Determine current phase based on unified status
                if unified_status['status'] == 'checking':
                    current_phase = "checking"
                elif unified_status['status'] == 'no_downloads_needed':
                    current_phase = "no_downloads_needed"
                elif unified_status['status'] == 'server_offline':
                    current_phase = "server_offline"
                elif unified_status['status'] == 'plex_downloading':
                    current_phase = "plex"
                elif unified_status['status'] == 'plex_completed':
                    current_phase = "plex_completed"
                elif unified_status['status'] == 'abs_downloading':
                    current_phase = "abs"
                elif unified_status['status'] == 'completed':
                    current_phase = "completed"
                elif unified_status['status'] == 'error':
                    current_phase = "error"
        
        # Add ABS-specific status
        abs_enabled = os.getenv("ABS_ENABLED", "yes") == "yes"
        abs_needs_refresh = should_refresh_abs_posters() if abs_enabled else False
        
        if debug_mode:
            print(f"[DEBUG] Restart readiness check: ready={ready}, should_wait={should_wait}")
            print(f"[DEBUG] Poster status: {poster_status}")
            print(f"[DEBUG] Setup download status: {setup_download_status}")
            print(f"[DEBUG] Current phase: {current_phase}")
            print(f"[DEBUG] ABS enabled: {abs_enabled}, ABS needs refresh: {abs_needs_refresh}")
            print(f"[DEBUG] ABS download in progress: {abs_download_in_progress}, ABS download completed: {abs_download_completed}")
        
        return jsonify({
            "ready": ready,
            "poster_status": poster_status,
            "setup_download_status": setup_download_status,
            "current_phase": current_phase,
            "should_wait_for_posters": should_wait,
            "abs_enabled": abs_enabled,
            "abs_needs_refresh": abs_needs_refresh,
            "abs_download_in_progress": abs_download_in_progress,
            "abs_download_completed": abs_download_completed
        })
    except Exception as e:
        if debug_mode:
            print(f"[ERROR] Error checking restart readiness: {e}")
        return jsonify({"ready": True, "error": str(e)})

# Update index route to check setup status
@app.route("/", methods=["GET", "POST"])
def index():
    if not is_setup_complete():
        return redirect(url_for("setup"))
    if request.method == "POST":
        entered_password = request.form.get("password")
        # Always reload from .env
        from dotenv import load_dotenv
        load_dotenv(override=True)
        
        # Get hashed passwords and salts
        admin_password_hash = os.getenv("ADMIN_PASSWORD_HASH")
        admin_password_salt = os.getenv("ADMIN_PASSWORD_SALT")
        site_password_hash = os.getenv("SITE_PASSWORD_HASH")
        site_password_salt = os.getenv("SITE_PASSWORD_SALT")
        
        # For backward compatibility, check plain text passwords if hashes don't exist
        admin_password_plain = os.getenv("ADMIN_PASSWORD")
        site_password_plain = os.getenv("SITE_PASSWORD")
        
        # Check admin password
        admin_authenticated = False
        if admin_password_hash and admin_password_salt:
            admin_authenticated = verify_password(entered_password, admin_password_salt, admin_password_hash)
        elif admin_password_plain:
            # Fallback to plain text for backward compatibility
            admin_authenticated = (entered_password == admin_password_plain)
        
        # Check site password
        site_authenticated = False
        if site_password_hash and site_password_salt:
            site_authenticated = verify_password(entered_password, site_password_salt, site_password_hash)
        elif site_password_plain:
            # Fallback to plain text for backward compatibility
            site_authenticated = (entered_password == site_password_plain)

        if admin_authenticated:
            session["authenticated"] = True
            session["admin_authenticated"] = True
            return redirect(url_for("services"))
        elif site_authenticated:
            session["authenticated"] = True
            session["admin_authenticated"] = False
            return redirect(url_for("onboarding"))
        else:
            return render_template("login.html", error="Incorrect password")

    return render_template("login.html")



@app.route("/setup", methods=["GET", "POST"])
@limiter.exempt
def setup():
    # If GET and SETUP_COMPLETE=0, show prompt for SITE_PASSWORD, ADMIN_PASSWORD, DRIVES
    if request.method == "GET" and not is_setup_complete():
        site_password = os.getenv("SITE_PASSWORD", "changeme")
        admin_password = os.getenv("ADMIN_PASSWORD", "changeme2")
        drives = os.getenv("DRIVES", "")
        prompt = False
        if site_password == "changeme" or admin_password == "changeme2" or not drives:
            prompt = True
        service_keys = [
            'PLEX', 'LIDARR', 'RADARR', 'SONARR', 'TAUTULLI', 'QBITTORRENT', 'IMMICH',
            'PROWLARR', 'BAZARR', 'PULSARR', 'AUDIOBOOKSHELF', 'OVERSEERR', 'JELLYSEERR'
        ]
        service_urls = {key: os.getenv(key, "") for key in service_keys}
        # Get template context including rate limiting variables
        template_context = get_template_context()
        template_context.update({
            "prompt_passwords": prompt,
            "site_password": site_password,
            "admin_password": admin_password,
            "drives": drives,
            "server_name": os.getenv("SERVER_NAME", ""),
            "service_urls": service_urls,
            "ip_lists": get_ip_lists(),
            "section7_content": load_section7_content()
        })
        return render_template("setup.html", **template_context)
    if is_setup_complete():
        return redirect(url_for("login"))
    error_message = None
    if request.method == "POST" and (
        "server_name" in request.form or
        "plex_token" in request.form or
        "plex_url" in request.form or
        "audiobooks_id" in request.form or
        "abs_enabled" in request.form or
        "discord_webhook" in request.form or
        "discord_notify_plex" in request.form or
        "discord_notify_abs" in request.form or
        "onboarderr_url" in request.form or
        "library_ids" in request.form or
        "audiobookshelf_url" in request.form or
        "accent_color_text" in request.form or
        "logo_file" in request.files or
        "wordmark_file" in request.files or
        "site_password" in request.form or
        "admin_password" in request.form or
        "drives" in request.form
    ):
        from dotenv import set_key
        env_path = os.path.join(os.getcwd(), ".env")
        form = request.form
        
        # Handle file uploads
        logo_file = request.files.get('logo_file')
        wordmark_file = request.files.get('wordmark_file')
        
        if logo_file and logo_file.filename:
            if not process_uploaded_logo(logo_file):
                error_message = "Failed to process logo file. Please ensure it's a valid image file (.png, .webp, .jpg, .jpeg)."
        
        if wordmark_file and wordmark_file.filename:
            if not process_uploaded_wordmark(wordmark_file):
                error_message = "Failed to process wordmark file. Please ensure it's a valid image file (.png, .webp, .jpg, .jpeg)."

        # Save SITE_PASSWORD, ADMIN_PASSWORD, DRIVES from the form
        site_password = form.get("site_password_box") or form.get("site_password")
        admin_password = form.get("admin_password_box") or form.get("admin_password")
        drives = form.get("drives_box") or form.get("drives")
        
        # Get other required fields for validation
        server_name = form.get("server_name", "").strip()
        plex_token = form.get("plex_token", "").strip()
        plex_url = form.get("plex_url", "").strip()
        library_ids = request.form.getlist("library_ids")
        
        # Validate required fields
        missing_fields = []
        if not site_password:
            missing_fields.append("Guest Password")
        if not admin_password:
            missing_fields.append("Admin Password")
        if not drives:
            missing_fields.append("Storage Drives")
        if not server_name:
            missing_fields.append("Server Name")
        if not plex_token:
            missing_fields.append("Plex Token")
        if not plex_url:
            missing_fields.append("Plex URL")
        if not library_ids:
            missing_fields.append("At least one Library")
        
        # Validate Audiobookshelf settings if enabled
        abs_enabled = form.get("abs_enabled", "")
        if abs_enabled == "yes":
            audiobooks_id = form.get("audiobooks_id", "").strip()
            audiobookshelf_url = form.get("audiobookshelf_url", "").strip()
            audiobookshelf_token = form.get("audiobookshelf_token", "").strip()
            
            if not audiobooks_id:
                missing_fields.append("Audiobook Library ID")
            if not audiobookshelf_url:
                missing_fields.append("Audiobookshelf URL")
            if not audiobookshelf_token:
                missing_fields.append("Audiobookshelf API Token")
        elif not abs_enabled:
            missing_fields.append("Enable Audiobookshelf?")
        
        if missing_fields:
            error_message = f"Some entries are missing: {', '.join(missing_fields)}"
            service_keys = [
                'PLEX', 'LIDARR', 'RADARR', 'SONARR', 'TAUTULLI', 'QBITTORRENT', 'IMMICH',
                'PROWLARR', 'BAZARR', 'PULSARR', 'AUDIOBOOKSHELF', 'OVERSEERR', 'JELLYSEERR'
            ]
            service_urls = {key: os.getenv(key, "") for key in service_keys}
            # Get template context including rate limiting variables
            template_context = get_template_context()
            template_context.update({
                "error_message": error_message,
                "prompt_passwords": True,
                "site_password": site_password,
                "admin_password": admin_password,
                "drives": drives,
                "server_name": os.getenv("SERVER_NAME", ""),
                "service_urls": service_urls,
                "ip_lists": get_ip_lists(),
                "section7_content": load_section7_content()
            })
            return render_template("setup.html", **template_context)
        
        if site_password == admin_password:
            error_message = "Guest Password and Admin Password must be different."
            service_keys = [
                'PLEX', 'LIDARR', 'RADARR', 'SONARR', 'TAUTULLI', 'QBITTORRENT', 'IMMICH',
                'PROWLARR', 'BAZARR', 'PULSARR', 'AUDIOBOOKSHELF', 'OVERSEERR', 'JELLYSEERR'
            ]
            service_urls = {key: os.getenv(key, "") for key in service_keys}
            # Get template context including rate limiting variables
            template_context = get_template_context()
            template_context.update({
                "error_message": error_message,
                "prompt_passwords": True,
                "site_password": site_password,
                "admin_password": admin_password,
                "drives": drives,
                "server_name": os.getenv("SERVER_NAME", ""),
                "service_urls": service_urls,
                "ip_lists": get_ip_lists(),
                "section7_content": load_section7_content()
            })
            return render_template("setup.html", **template_context)
        
        # Hash passwords before saving
        site_salt, site_hash = hash_password(site_password)
        admin_salt, admin_hash = hash_password(admin_password)
        
        # Save hashed passwords and salts
        safe_set_key(env_path, "SITE_PASSWORD_HASH", site_hash)
        safe_set_key(env_path, "SITE_PASSWORD_SALT", site_salt)
        safe_set_key(env_path, "ADMIN_PASSWORD_HASH", admin_hash)
        safe_set_key(env_path, "ADMIN_PASSWORD_SALT", admin_salt)
        
        # Keep plain text passwords for backward compatibility during transition
        safe_set_key(env_path, "SITE_PASSWORD", site_password)
        safe_set_key(env_path, "ADMIN_PASSWORD", admin_password)
        safe_set_key(env_path, "DRIVES", drives)

        # Get other form data
        audiobooks_id = form.get("audiobooks_id", "").strip()
        audiobookshelf_url = form.get("audiobookshelf_url", "").strip()
        discord_webhook = form.get("discord_webhook", "").strip()
        discord_username = form.get("discord_username", "").strip()
        discord_avatar = form.get("discord_avatar", "").strip()
        discord_color = form.get("discord_color", "").strip()
        onboarderr_url = form.get("onboarderr_url", "").strip()



        safe_set_key(env_path, "SERVER_NAME", form.get("server_name", ""))
        
        # Handle accent color with proper validation (same as services route)
        accent_color = form.get("accent_color_text", "").strip()
        current_accent_color = os.getenv("ACCENT_COLOR", "")
        if accent_color and accent_color != current_accent_color:
            safe_set_key(env_path, "ACCENT_COLOR", accent_color)
        
        # Handle API keys with hashing
        plex_token = form.get("plex_token", "").strip()
        if plex_token:
            save_api_key_with_hash(env_path, "PLEX_TOKEN", plex_token)
        
        safe_set_key(env_path, "PLEX_URL", form.get("plex_url", ""))
        safe_set_key(env_path, "ABS_ENABLED", abs_enabled)
        if abs_enabled == "yes":
            safe_set_key(env_path, "AUDIOBOOKS_ID", audiobooks_id)
            safe_set_key(env_path, "AUDIOBOOKSHELF_URL", audiobookshelf_url)
            audiobookshelf_token = form.get("audiobookshelf_token", "").strip()
            if audiobookshelf_token:
                save_api_key_with_hash(env_path, "AUDIOBOOKSHELF_TOKEN", audiobookshelf_token)
        # Save Discord settings
        safe_set_key(env_path, "DISCORD_WEBHOOK", discord_webhook)
        if discord_webhook:
            if discord_username:
                safe_set_key(env_path, "DISCORD_USERNAME", discord_username)
            if discord_avatar:
                safe_set_key(env_path, "DISCORD_AVATAR", discord_avatar)
            if discord_color:
                safe_set_key(env_path, "DISCORD_COLOR", discord_color)
            if onboarderr_url:
                safe_set_key(env_path, "ONBOARDERR_URL", onboarderr_url)
        
        # Save Discord notification settings
        discord_notify_plex = form.get("discord_notify_plex")
        if discord_notify_plex is None:
            discord_notify_plex = "0"
        safe_set_key(env_path, "DISCORD_NOTIFY_PLEX", discord_notify_plex)
        
        discord_notify_abs = form.get("discord_notify_abs")
        if discord_notify_abs is None:
            discord_notify_abs = "0"
        safe_set_key(env_path, "DISCORD_NOTIFY_ABS", discord_notify_abs)
        
        # Save new security event notification settings
        discord_notify_rate_limiting = form.get("discord_notify_rate_limiting")
        if discord_notify_rate_limiting is None:
            discord_notify_rate_limiting = "0"
        safe_set_key(env_path, "DISCORD_NOTIFY_RATE_LIMITING", discord_notify_rate_limiting)
        
        discord_notify_ip_management = form.get("discord_notify_ip_management")
        if discord_notify_ip_management is None:
            discord_notify_ip_management = "0"
        safe_set_key(env_path, "DISCORD_NOTIFY_IP_MANAGEMENT", discord_notify_ip_management)
        
        discord_notify_login_attempts = form.get("discord_notify_login_attempts")
        if discord_notify_login_attempts is None:
            discord_notify_login_attempts = "0"
        safe_set_key(env_path, "DISCORD_NOTIFY_LOGIN_ATTEMPTS", discord_notify_login_attempts)
        
        discord_notify_form_rate_limiting = form.get("discord_notify_form_rate_limiting")
        if discord_notify_form_rate_limiting is None:
            discord_notify_form_rate_limiting = "0"
        safe_set_key(env_path, "DISCORD_NOTIFY_FORM_RATE_LIMITING", discord_notify_form_rate_limiting)

        discord_notify_first_access = form.get("discord_notify_first_access")
        if discord_notify_first_access is None:
            discord_notify_first_access = "0"
        safe_set_key(env_path, "DISCORD_NOTIFY_FIRST_ACCESS", discord_notify_first_access)
        
        # Save Quick Access setting
        quick_access_enabled = form.get("quick_access_enabled", "yes")
        safe_set_key(env_path, "QUICK_ACCESS_ENABLED", quick_access_enabled)
        
        # Save individual Quick Access service toggles
        qa_plex_enabled = "yes" if form.get("qa_plex_enabled") else "no"
        qa_audiobookshelf_enabled = "yes" if form.get("qa_audiobookshelf_enabled") else "no"
        qa_tautulli_enabled = "yes" if form.get("qa_tautulli_enabled") else "no"
        qa_overseerr_enabled = "yes" if form.get("qa_overseerr_enabled") else "no"
        qa_jellyseerr_enabled = "yes" if form.get("qa_jellyseerr_enabled") else "no"
        
        safe_set_key(env_path, "QA_PLEX_ENABLED", qa_plex_enabled)
        safe_set_key(env_path, "QA_AUDIOBOOKSHELF_ENABLED", qa_audiobookshelf_enabled)
        safe_set_key(env_path, "QA_TAUTULLI_ENABLED", qa_tautulli_enabled)
        safe_set_key(env_path, "QA_OVERSEERR_ENABLED", qa_overseerr_enabled)
        safe_set_key(env_path, "QA_JELLYSEERR_ENABLED", qa_jellyseerr_enabled)
        # Save selected library IDs and names
        library_ids = request.form.getlist("library_ids")
        
        # Clean library IDs (remove whitespace, no need to remove commas since we're using individual inputs)
        cleaned_library_ids = []
        for lib_id in library_ids:
            cleaned_id = lib_id.strip()
            if cleaned_id:
                cleaned_library_ids.append(cleaned_id)
        
        library_notes = {}
        if debug_mode:
            print(f"[DEBUG] Setup form - library_ids from form: {library_ids}")
            print(f"[DEBUG] Setup form - cleaned_library_ids: {cleaned_library_ids}")
            print(f"[DEBUG] Setup form - all form data keys: {list(request.form.keys())}")
        if cleaned_library_ids:
            plex_token = form.get("plex_token", "")
            plex_url = form.get("plex_url", "")
            headers = {"X-Plex-Token": plex_token}
            url = f"{plex_url}/library/sections"
            try:
                response = requests.get(url, headers=headers, timeout=5)
                response.raise_for_status()
                import xml.etree.ElementTree as ET
                root = ET.fromstring(response.text)
                id_to_title = {d.attrib.get("key"): d.attrib.get("title") for d in root.findall(".//Directory")}
                selected_titles = [id_to_title.get(i, f"Unknown ({i})") for i in cleaned_library_ids]
                safe_set_key(env_path, "LIBRARY_IDS", ",".join(cleaned_library_ids))
                safe_set_key(env_path, "LIBRARY_NAMES", ",".join([t or "" for t in selected_titles]))
                if debug_mode:
                    print(f"[DEBUG] Setup form - Saved LIBRARY_IDS: {','.join(cleaned_library_ids)}")
                    print(f"[DEBUG] Setup form - Saved LIBRARY_NAMES: {','.join([t or '' for t in selected_titles])}")
                # Save library notes with title and description
                for lib_id in cleaned_library_ids:
                    desc = form.get(f"library_desc_{lib_id}", "")
                    if debug_mode:
                        print(f"[DEBUG] Setup form - Processing library {lib_id}, description from form: '{desc}'")
                    library_notes[lib_id] = {
                        "title": id_to_title.get(lib_id, f"Unknown ({lib_id})"),
                        "description": desc
                    }
                save_library_notes(library_notes)
                
                # Handle Library Carousel settings
                library_carousels = request.form.getlist("library_carousels")
                if debug_mode:
                    print(f"[DEBUG] Setup form - Raw library_carousels from form: {library_carousels}")
                    print(f"[DEBUG] Setup form - Selected library_ids: {cleaned_library_ids}")
                
                # Validate that all carousel libraries are in the selected library IDs
                if library_carousels:
                    # Convert both to sets for comparison
                    carousel_set = set(library_carousels)
                    selected_set = set(cleaned_library_ids)
                    
                    # Find any carousel libraries that aren't in selected libraries
                    invalid_carousels = carousel_set - selected_set
                    if invalid_carousels and debug_mode:
                        print(f"[DEBUG] Setup form - Invalid carousel libraries found: {invalid_carousels}")
                        print(f"[DEBUG] Setup form - These libraries are not in the selected library IDs")
                    
                    # Only keep carousel libraries that are actually selected
                    valid_carousels = list(carousel_set & selected_set)
                    if debug_mode:
                        print(f"[DEBUG] Setup form - Valid carousel libraries: {valid_carousels}")
                    
                    safe_set_key(env_path, "LIBRARY_CAROUSELS", ",".join(valid_carousels))
                else:
                    # If no carousels selected, set to empty to show all
                    safe_set_key(env_path, "LIBRARY_CAROUSELS", "")
                
                # Handle Library Carousel Tab Order
                library_carousel_order = request.form.get("library_carousel_order", "").strip()
                if debug_mode:
                    print(f"[DEBUG] Setup form - Raw carousel order from form: '{library_carousel_order}'")
                
                if library_carousel_order:
                    # Validate that all libraries in the order are in the selected libraries
                    order_ids = [id.strip() for id in library_carousel_order.split(",") if id.strip()]
                    if debug_mode:
                        print(f"[DEBUG] Setup form - Carousel order from form: {order_ids}")
                    
                    # Filter to only include libraries that are actually selected
                    valid_order_ids = [id for id in order_ids if id in cleaned_library_ids]
                    if debug_mode:
                        print(f"[DEBUG] Setup form - Valid carousel order: {valid_order_ids}")
                    
                    safe_set_key(env_path, "LIBRARY_CAROUSEL_ORDER", ",".join(valid_order_ids))
                else:
                    if debug_mode:
                        print(f"[DEBUG] Setup form - No carousel order provided, setting to empty string")
                    safe_set_key(env_path, "LIBRARY_CAROUSEL_ORDER", "")
            except Exception as e:
                if debug_mode:
                    print(f"[DEBUG] Setup form - API call failed, saving library IDs without names: {e}")
                safe_set_key(env_path, "LIBRARY_IDS", ",".join(cleaned_library_ids))
                safe_set_key(env_path, "LIBRARY_NAMES", "")
                if debug_mode:
                    print(f"[DEBUG] Setup form - Saved LIBRARY_IDS (fallback): {','.join(cleaned_library_ids)}")
        if not cleaned_library_ids and debug_mode:
            print(f"[DEBUG] Setup form - No library_ids found in form data")
        # Save service URLs
        service_keys = [
            'PLEX', 'LIDARR', 'RADARR', 'SONARR', 'TAUTULLI', 'QBITTORRENT', 'IMMICH',
            'PROWLARR', 'BAZARR', 'PULSARR', 'AUDIOBOOKSHELF', 'OVERSEERR', 'JELLYSEERR'
        ]
        for key in service_keys:
            url_val = form.get(key, "").strip()
            safe_set_key(env_path, key, url_val)
        
        # Handle IP management enabled setting
        ip_management_enabled = form.get("ip_management_enabled", "no")
        safe_set_key(env_path, "IP_MANAGEMENT_ENABLED", ip_management_enabled)
        
        # Handle rate limiting settings
        rate_limit_settings_enabled = form.get("rate_limit_settings_enabled", "yes")
        safe_set_key(env_path, "RATE_LIMIT_SETTINGS_ENABLED", rate_limit_settings_enabled)
        
        # Handle rate limiting values
        max_login_attempts = form.get("max_login_attempts")
        if max_login_attempts is not None:
            try:
                max_login_attempts = int(max_login_attempts)
                if 0 <= max_login_attempts <= 10:
                    safe_set_key(env_path, "RATE_LIMIT_MAX_LOGIN_ATTEMPTS", str(max_login_attempts))
            except ValueError:
                pass

        max_form_submissions = form.get("max_form_submissions")
        if max_form_submissions is not None:
            try:
                max_form_submissions = int(max_form_submissions)
                if 0 <= max_form_submissions <= 10:
                    safe_set_key(env_path, "RATE_LIMIT_MAX_FORM_SUBMISSIONS", str(max_form_submissions))
            except ValueError:
                pass
        
        # Handle section 7 content (personal message and payment services)
        personal_message = form.get("personal_message", "").strip()
        payment_services = []
        for i in range(3):
            title = form.get(f"payment_service_{i}_title", "").strip()
            handle = form.get(f"payment_service_{i}_handle", "").strip()
            if title or handle:  # Save even if only one field is filled
                payment_services.append({
                    "title": title,
                    "handle": handle
                })
            else:
                # Add empty service to maintain 3 slots
                payment_services.append({
                    "title": "",
                    "handle": ""
                })
        
        section7_content = {
            "personal_message": personal_message,
            "payment_services": payment_services
        }
        save_section7_content(section7_content)
        
        safe_set_key(env_path, "SETUP_COMPLETE", "1")
        load_dotenv(override=True)
        
        # Track what settings changed for adaptive restart (setup always changes critical settings)
        changed_settings = {"server_name", "plex_token", "plex_url", "library_ids", "accent_color_text"}
        if form.get("abs_enabled") == "yes":
            changed_settings.update({"abs_enabled", "audiobooks_id", "audiobookshelf_url", "audiobookshelf_token"})
        
        # Calculate restart delay for setup changes
        restart_delay = get_restart_delay_for_changes(changed_settings)
        
        # Add debug output to show what's being passed to setup_complete
        if debug_mode:
            print(f"[DEBUG] Setup form completed successfully")
            print(f"[DEBUG] Changed settings: {changed_settings}")
            print(f"[DEBUG] Restart delay: {restart_delay}")
            print(f"[DEBUG] ABS enabled: {form.get('abs_enabled')}")
            print(f"[DEBUG] Plex URL: {form.get('plex_url')}")
            print(f"[DEBUG] Library IDs: {form.getlist('library_ids')}")
            print(f"[DEBUG] Redirecting to setup_complete with from_setup=true")
        
        # Redirect to setup_complete with adaptive restart info
        return redirect(url_for("setup_complete", from_setup="true", 
                              restart_delay=str(restart_delay),
                              changed_settings=",".join(changed_settings)))
    # Get template context including rate limiting variables
    template_context = get_template_context()
    template_context.update({
        "error_message": error_message,
        "ip_lists": get_ip_lists(),
        "section7_content": load_section7_content()
    })
    return render_template("setup.html", **template_context)

def ensure_worker_running():
    """Ensure the background poster worker is running"""
    global poster_download_running
    if not poster_download_running:
        if debug_mode:
            print("[INFO] Restarting background poster worker")
        start_background_poster_worker()

def trigger_poster_downloads():
    """Manually trigger poster downloads - used as backup after setup"""
    try:
        # Ensure worker is running
        ensure_worker_running()
        
        # Get Plex credentials directly from environment
        plex_token = os.getenv("PLEX_TOKEN")
        
        if os.getenv("SETUP_COMPLETE") == "1" and plex_token:
            # Get selected libraries - no need to fetch from Plex API since we already have the IDs
            selected_ids = os.getenv("LIBRARY_IDS", "")
            selected_ids = [i.strip() for i in selected_ids.split(",") if i.strip()]
            
            # Create library objects from the IDs we already have
            libraries = []
            library_notes = load_library_notes()
            for lib_id in selected_ids:
                # Get library name from library notes, fallback to environment variable, then to ID
                lib_name = None
                if lib_id in library_notes and library_notes[lib_id].get('title'):
                    lib_name = library_notes[lib_id]['title']
                else:
                    # Fallback to environment variable
                    lib_name = os.getenv(f"LIBRARY_NAME_{lib_id}")
                    if not lib_name:
                        # Final fallback to ID
                        lib_name = f"Library {lib_id}"
                
                libraries.append({
                    "key": lib_id,
                    "title": lib_name,
                    "type": "show"  # Default type, could be enhanced if needed
                })
            
            if libraries:
                # Queue poster downloads
                download_and_cache_posters_for_libraries(libraries, background=True)
                if debug_mode:
                    print(f"[INFO] Manually triggered poster download for {len(libraries)} libraries")
            
            # Queue ABS poster download if enabled
            if os.getenv("ABS_ENABLED", "yes") == "yes":
                poster_download_queue.put(('abs', None, None))
                if debug_mode:
                    print("[INFO] Manually triggered ABS poster download")
    except Exception as e:
        if debug_mode:
            print(f"Warning: Could not trigger poster downloads: {e}")

@app.route("/setup_complete")
@limiter.exempt
def setup_complete():
    # Security check: Verify this request is legitimate
    from_services = request.args.get('from_services', 'false').lower() == 'true'
    from_setup = request.args.get('from_setup', 'false').lower() == 'true'
    
    # Add debug output to show setup completion is being reached
    if is_debug_mode():
        print(f"[DEBUG] Setup complete route accessed - from_services: {from_services}, from_setup: {from_setup}")
        print(f"[DEBUG] Request args: {dict(request.args)}")
    
    # If not from legitimate form submission, redirect to login
    if not from_services and not from_setup:
        if is_debug_mode():
            print("[DEBUG] Unauthorized setup complete access - redirecting to login")
        log_security_event("unauthorized_setup_complete_access", get_client_ip(), 
                         {"user_agent": request.headers.get('User-Agent', 'Unknown'),
                          "referer": request.headers.get('Referer', 'None')})
        return redirect(url_for("login"))
    
    restart_delay = request.args.get('restart_delay', '15')
    changed_settings = request.args.get('changed_settings', '').split(',') if request.args.get('changed_settings') else []
    
    # Determine if this is an adaptive restart (poster downloads needed)
    is_adaptive = restart_delay == 'adaptive'
    
    # For setup form submissions, always use adaptive restart since they change critical settings
    if from_setup:
        is_adaptive = True
        restart_delay = 'adaptive'
    
    if is_debug_mode():
        print(f"[DEBUG] Setup complete - restart_delay: {restart_delay}, is_adaptive: {is_adaptive}")
        print(f"[DEBUG] Changed settings: {changed_settings}")
    
    # Show the setup_complete template instead of running downloads synchronously
    # The template will handle the poster downloads asynchronously
    return render_template("setup_complete.html", 
                         restart_delay=restart_delay,
                         is_adaptive=is_adaptive,
                         changed_settings=changed_settings)

@app.route("/ajax/setup-poster-downloads", methods=["POST"])
@csrf.exempt
def setup_poster_downloads():
    """Handle poster downloads for setup completion using smart logic"""
    if is_debug_mode():
        print("[DEBUG] Setup poster downloads route accessed")
    
    try:
        # Get parameters
        changed_settings = request.json.get('changed_settings', []) if request.json else []
        
        if is_debug_mode():
            print(f"[DEBUG] Setup poster downloads - changed settings: {changed_settings}")
        
        # Get Plex credentials
        plex_token = os.getenv("PLEX_TOKEN")
        plex_url = os.getenv("PLEX_URL")
        
        if not plex_token or not plex_url:
            if is_debug_mode():
                print("[DEBUG] No Plex credentials available, skipping poster downloads")
            return jsonify({"success": False, "error": "No Plex credentials available"})
        
        # Ensure worker is running
        ensure_worker_running()
        
        # Get selected libraries
        selected_ids = os.getenv("LIBRARY_IDS", "")
        selected_ids = [i.strip() for i in selected_ids.split(",") if i.strip()]
        
        # Create library objects
        libraries = []
        library_notes = load_library_notes()
        for lib_id in selected_ids:
            # Get library name from library notes, fallback to environment variable, then to ID
            lib_name = None
            if lib_id in library_notes and library_notes[lib_id].get('title'):
                lib_name = library_notes[lib_id]['title']
            else:
                # Fallback to environment variable
                lib_name = os.getenv(f"LIBRARY_NAME_{lib_id}")
                if not lib_name:
                    # Final fallback to ID
                    lib_name = f"Library {lib_id}"
            
            libraries.append({
                "key": lib_id,
                "title": lib_name,
                "type": "show"  # Default type
            })
        
        # Initialize unified progress tracking with checking status
        with poster_download_lock:
            poster_download_progress['unified'] = {
                'status': 'checking',
                'message': 'Checking poster downloads...',
                'current': 0,
                'total': 0,
                'start_time': time.time()
            }
        
        # Use smart logic to determine what needs downloading
        abs_enabled = os.getenv("ABS_ENABLED", "yes") == "yes"
        download_needs = determine_download_needs(libraries, abs_enabled)
        
        if is_debug_mode():
            print(f"[DEBUG] Smart download analysis - Plex: {download_needs['plex_needs_download']}, ABS: {download_needs['abs_needs_download']}")
            print(f"[DEBUG] Totals: {download_needs['total_new']} new, {download_needs['total_changed']} changed, {download_needs['total_removed']} removed")
            print(f"[DEBUG] Server offline: {download_needs['any_server_offline']}")
        
        # Handle server offline case
        if download_needs['any_server_offline']:
            with poster_download_lock:
                poster_download_progress['unified'].update({
                    'status': 'server_offline',
                    'message': 'Server offline, skipping...',
                    'end_time': time.time()
                })
            
            return jsonify({
                "success": True,
                "message": "Server offline, skipping poster downloads",
                "needs_plex": False,
                "needs_abs": False,
                "libraries_count": len(libraries),
                "server_offline": True
            })
        
        # Handle no downloads needed case
        if not download_needs['plex_needs_download'] and not download_needs['abs_needs_download']:
            with poster_download_lock:
                poster_download_progress['unified'].update({
                    'status': 'no_downloads_needed',
                    'message': 'No downloads needed',
                    'end_time': time.time()
                })
            
            return jsonify({
                "success": True,
                "message": "No downloads needed",
                "needs_plex": False,
                "needs_abs": False,
                "libraries_count": len(libraries),
                "no_downloads_needed": True
            })
        
        # Phase 1: Download Plex posters if needed
        if libraries and download_needs['plex_needs_download']:
            if is_debug_mode():
                print(f"[INFO] Starting Plex poster downloads for {len(libraries)} libraries")
            
            # Update progress status
            with poster_download_lock:
                poster_download_progress['unified'].update({
                    'status': 'plex_downloading',
                    'message': 'Downloading Plex posters...',
                    'current': 0,
                    'total': len(libraries),
                    'last_update': time.time()
                })
            
            # Queue Plex downloads to background worker with smart data
            poster_download_queue.put(('smart_plex', libraries, None, True, True, download_needs['plex_results']))
            
        elif libraries:
            if is_debug_mode():
                print(f"[INFO] Skipping Plex poster downloads - no changes detected")
        
        # Phase 2: Queue ABS downloads if needed
        if abs_enabled and download_needs['abs_needs_download']:
            if is_debug_mode():
                print("[INFO] Queuing Audiobookshelf poster downloads")
            
            # Update unified status to show ABS downloads will start after Plex
            with poster_download_lock:
                if 'unified' in poster_download_progress:
                    poster_download_progress['unified'].update({
                        'status': 'plex_downloading',
                        'message': 'Downloading Plex posters... (ABS will follow)',
                        'last_update': time.time()
                    })
            
            # Queue ABS downloads to background worker with smart data
            poster_download_queue.put(('smart_abs', None, None, True, True, download_needs['abs_result']))
            
        elif abs_enabled:
            if is_debug_mode():
                print(f"[INFO] Skipping ABS poster downloads - no changes detected")
        
        # Phase 3: Start periodic refresh in background (but don't wait for it)
        if libraries:
            # Start periodic refresh in a separate thread that won't block restart
            def start_periodic_refresh_delayed():
                # Wait a bit before starting periodic refresh to avoid blocking restart
                time.sleep(5)
                periodic_poster_refresh(libraries, 24)
                if is_debug_mode():
                    print(f"[DEBUG] Started 24-hour periodic refresh for {len(libraries)} libraries")
            
            threading.Thread(target=start_periodic_refresh_delayed, daemon=True).start()
        
        if is_debug_mode():
            print("[INFO] Setup poster downloads initiated successfully")
        
        return jsonify({
            "success": True,
            "message": "Poster downloads initiated",
            "needs_plex": download_needs['plex_needs_download'],
            "needs_abs": download_needs['abs_needs_download'],
            "libraries_count": len(libraries)
        })
        
    except Exception as e:
        if is_debug_mode():
            print(f"[ERROR] Error in setup poster downloads: {e}")
        
        # Update progress status to show error
        with poster_download_lock:
            if 'unified' in poster_download_progress:
                poster_download_progress['unified'].update({
                    'status': 'error',
                    'message': f'Error: {str(e)}',
                    'end_time': time.time()
                })
        
        return jsonify({"success": False, "error": str(e)})

def periodic_poster_refresh_worker(libraries, interval_hours):
    """Background worker for periodic poster refresh"""
    while True:
        if is_debug_mode():
            print("[INFO] Refreshing library posters...")
        # Use configuration to determine refresh mode
        incremental_mode = config.get_poster_refresh_mode()
        download_and_cache_posters_for_libraries(libraries, background=True, incremental_mode=incremental_mode)
        time.sleep(interval_hours * 3600)

def periodic_poster_refresh(libraries, interval_hours=24):
    """Start periodic poster refresh in background thread"""
    t = threading.Thread(target=periodic_poster_refresh_worker, args=(libraries, interval_hours), daemon=True)
    t.start()

def refresh_posters_on_demand(libraries=None):
    """Refresh posters in background when settings are applied"""
    if libraries is None:
        selected_ids = os.getenv("LIBRARY_IDS", "")
        selected_ids = [i.strip() for i in selected_ids.split(",") if i.strip()]
        
        # Create library objects from the IDs we already have - no need to fetch from Plex API
        libraries = []
        library_notes = load_library_notes()
        for lib_id in selected_ids:
            # Get library name from library notes, fallback to environment variable, then to ID
            lib_name = None
            if lib_id in library_notes and library_notes[lib_id].get('title'):
                lib_name = library_notes[lib_id]['title']
            else:
                # Fallback to environment variable
                lib_name = os.getenv(f"LIBRARY_NAME_{lib_id}")
                if not lib_name:
                    # Final fallback to ID
                    lib_name = f"Library {lib_id}"
            
            libraries.append({
                "key": lib_id,
                "title": lib_name,
                "type": "show"  # Default type, could be enhanced if needed
            })
    
    if libraries:
        if is_debug_mode():
            print(f"[INFO] Refreshing posters for {len(libraries)} libraries on demand")
        # Use configuration to determine refresh mode
        incremental_mode = config.get_poster_refresh_mode()
        download_and_cache_posters_for_libraries(libraries, background=True, incremental_mode=incremental_mode)
        
        # Also refresh ABS posters if enabled - but wait for Plex to complete first
        if os.getenv("ABS_ENABLED", "yes") == "yes":
            def queue_abs_after_plex_on_demand():
                # Wait for Plex downloads to complete before starting ABS
                if is_debug_mode():
                    print("[INFO] Waiting for Plex poster downloads to complete before starting ABS (on demand)...")
                
                # Wait for Plex poster downloads to complete
                if wait_for_poster_completion(POSTER_DOWNLOAD_TIMEOUT):
                    if is_debug_mode():
                        print("[INFO] Plex poster downloads completed, now starting ABS poster downloads (on demand)")
                    
                    try:
                        poster_download_queue.put(('abs', None, None))
                        if is_debug_mode():
                            print("[INFO] Queued ABS poster refresh on demand after Plex completion")
                    except Exception as e:
                        if is_debug_mode():
                            print(f"Warning: Could not queue ABS poster downloads after Plex completion (on demand): {e}")
                else:
                    if is_debug_mode():
                        print("[WARN] Plex poster download timeout reached, skipping ABS downloads (on demand)")
            
            # Start ABS downloads in a separate thread that waits for Plex
            threading.Thread(target=queue_abs_after_plex_on_demand, daemon=True).start()
    
    if libraries:
        # Queue for background processing
        download_and_cache_posters_for_libraries(libraries, background=True)
        if is_debug_mode():
            print(f"[INFO] Queued poster refresh for {len(libraries)} libraries")
        return True
    return False

def invite_plex_user(email, libraries_titles):
    """Invite/share Plex libraries with a user via the Plex API."""
    plex_url = os.getenv("PLEX_URL")
    plex_token = os.getenv("PLEX_TOKEN")
    if not plex_url or not plex_token:
        return {"success": False, "email": email, "error": "Plex URL or token not configured"}
    try:
        plex = PlexServer(plex_url, plex_token)
        account = plex.myPlexAccount()
        # Check if user already exists as a friend
        for user in account.users():
            if user.email and user.email.lower() == email.lower():
                # Update libraries for existing user
                account.updateFriend(user=user, server=plex, sections=libraries_titles)
                return {"success": True, "email": email, "message": "Updated existing Plex friend with new libraries."}
        # If not, invite as new friend
        account.inviteFriend(user=email, server=plex, sections=libraries_titles)
        return {"success": True, "email": email, "message": "Invited new Plex user."}
    except Exception as e:
        return {"success": False, "email": email, "error": str(e)}

# --- Utility Functions for DRY Code ---

def get_service_definitions():
    """Centralized service definitions to avoid repetition"""
    return [
        ("Plex", "PLEX", "plex.webp"),
        ("Tautulli", "TAUTULLI", "tautulli.webp"),
        ("Audiobookshelf", "AUDIOBOOKSHELF", "abs.webp"),
        ("qbittorrent", "QBITTORRENT", "qbit.webp"),
        ("Immich", "IMMICH", "immich.webp"),
        ("Sonarr", "SONARR", "sonarr.webp"),
        ("Radarr", "RADARR", "radarr.webp"),
        ("Lidarr", "LIDARR", "lidarr.webp"),
        ("Prowlarr", "PROWLARR", "prowlarr.webp"),
        ("Bazarr", "BAZARR", "bazarr.webp"),
        ("Pulsarr", "PULSARR", "pulsarr.webp"),
        ("Overseerr", "OVERSEERR", "overseerr.webp"),
        ("Jellyseerr", "JELLYSEERR", "jellyseerr.webp"),
    ]

def get_public_service_definitions():
    """Service definitions for end users (non-admin services)"""
    return [
        ("Plex", "PLEX", "plex.webp"),
        ("Audiobookshelf", "AUDIOBOOKSHELF", "abs.webp"),
        ("Tautulli", "TAUTULLI", "tautulli.webp"),
        ("Overseerr", "OVERSEERR", "overseerr.webp"),
        ("Jellyseerr", "JELLYSEERR", "jellyseerr.webp"),
    ]

def load_json_file(filename, default=None):
    """Utility function to load JSON files with improved error handling and recovery"""
    if default is None:
        default = []
    
    def load_operation():
        with open(os.path.join(os.getcwd(), filename), "r", encoding="utf-8") as f:
            return json.load(f)
    
    try:
        data = safe_operation(
            load_operation,
            f"Failed to load JSON file: {filename}",
            "file_operation",
            default
        )
        
        if data is not None and debug_mode:
            print(f"[DEBUG] Loaded {len(data)} entries from {filename}")
        return data
        
    except FileNotFoundError:
        if debug_mode:
            print(f"[DEBUG] No {filename} file found, using default")
        return default
    except json.JSONDecodeError as e:
        log_error("json_decode", f"JSON decode error in {filename}", {"filename": filename}, e)
        return default
    except Exception as e:
        log_error("file_load", f"Unexpected error loading {filename}", {"filename": filename}, e)
        return default

def save_json_file(filename, data):
    """Utility function to save JSON files with improved error handling and recovery"""
    def save_operation():
        file_path = os.path.join(os.getcwd(), filename)
        # Create directory if it doesn't exist (only if there's a directory component)
        dir_path = os.path.dirname(file_path)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    try:
        success = safe_operation(
            save_operation,
            f"Failed to save JSON file: {filename}",
            "file_operation",
            False
        )
        
        if success and debug_mode:
            print(f"[DEBUG] Successfully saved {len(data)} entries to {filename}")
        return success
        
    except Exception as e:
        log_error("file_save", f"Unexpected error saving {filename}", {"filename": filename}, e)
        return False

def build_services_data():
    """Build services data for templates, avoiding repetition"""
    service_defs = get_service_definitions()
    services = []
    all_services = []
    
    for name, env, logo in service_defs:
        url = os.getenv(env, "")
        all_services.append({"name": name, "env": env, "url": url, "logo": logo})
        if url:
            services.append({"name": name, "url": url, "logo": logo})
    
    return services, all_services

def build_public_services_data():
    """Build public services data for end users (non-admin services)"""
    service_defs = get_public_service_definitions()
    services = []
    
    for name, env, logo in service_defs:
        url = os.getenv(env, "")
        if url:
            services.append({"name": name, "url": url, "logo": logo})
    
    return services

def build_quick_access_services_data():
    """Build filtered services data for quick access panel (desktop and mobile)"""
    service_defs = get_public_service_definitions()
    services = []
    
    for name, env, logo in service_defs:
        url = os.getenv(env, "")
        if not url:
            continue
            
        # Check individual QA service toggles
        qa_env = f"QA_{env}_ENABLED"
        qa_enabled = os.getenv(qa_env, "yes")  # Default to "yes" for backward compatibility
        
        if qa_enabled.lower() == "yes":
            services.append({"name": name, "url": url, "logo": logo})
    
    return services

def get_storage_info():
    """Get storage information for templates"""
    drives_env = os.getenv("DRIVES")
    if not drives_env:
        if platform.system() == "Windows":
            drives = ["C:\\"]
        else:
            drives = ["/"]
    else:
        drives = [d.strip() for d in drives_env.split(",") if d.strip()]
    
    storage_info = []
    for drive in drives:
        try:
            usage = psutil.disk_usage(drive)
            storage_info.append({
                "mount": drive,
                "used": round(usage.used / (1024**3), 1),
                "total": round(usage.total / (1024**3), 1),
                "percent": int(usage.percent)
            })
        except Exception as e:
            if debug_mode:
                print(f"Error reading {drive}: {e}")
    
    return storage_info

def get_lastfm_url(artist_name):
    """Generate Last.fm URL for an artist"""
    if not artist_name:
        return None
    
    # Clean the artist name for URL
    import urllib.parse
    # Replace spaces with + for Last.fm URL format
    clean_name = artist_name.replace(' ', '+')
    # URL encode for special characters
    encoded_name = urllib.parse.quote(clean_name)
    
    return f"https://www.last.fm/music/{encoded_name}"

def is_music_artist(poster_data, library_info=None):
    """Check if a poster represents a music artist"""
    if not poster_data:
        return False
    
    # If library info is provided, check if it's actually a music library
    if library_info and library_info.get("media_type") == "artist":
        title = poster_data.get("title")
        year = poster_data.get("year")
        
        # For music libraries, if it has a title but no year, it's likely an artist
        if title and year is None:
            return True
    
    return False

def get_template_context():
    """Get common template context data to avoid repetition"""
    services, all_services = build_services_data()
    quick_access_services = build_quick_access_services_data()
    storage_info = get_storage_info()
    library_notes = load_library_notes()
    
    # Load submissions
    submissions = load_json_file("plex_submissions.json", [])
    audiobookshelf_submissions = load_json_file("audiobookshelf_submissions.json", [])
    
    return {
        "services": services,
        "quick_access_services": quick_access_services,
        "all_services": all_services,
        "submissions": submissions,
        "storage_info": storage_info,
        "audiobookshelf_submissions": audiobookshelf_submissions,
        "library_notes": library_notes,
        "SERVER_NAME": os.getenv("SERVER_NAME", ""),
        "ACCENT_COLOR": os.getenv("ACCENT_COLOR", "#d33fbc"),
        "PLEX_TOKEN": os.getenv("PLEX_TOKEN", ""),
        "PLEX_URL": os.getenv("PLEX_URL", ""),
        "AUDIOBOOKS_ID": os.getenv("AUDIOBOOKS_ID", ""),
        "ABS_ENABLED": os.getenv("ABS_ENABLED", "no"),
        "LIBRARY_IDS": os.getenv("LIBRARY_IDS", ""),
        "LIBRARY_CAROUSELS": os.getenv("LIBRARY_CAROUSELS", ""),
        "LIBRARY_CAROUSEL_ORDER": os.getenv("LIBRARY_CAROUSEL_ORDER", ""),
        "DISCORD_WEBHOOK": os.getenv("DISCORD_WEBHOOK", ""),
        "DISCORD_USERNAME": os.getenv("DISCORD_USERNAME", ""),
        "DISCORD_AVATAR": os.getenv("DISCORD_AVATAR", ""),
        "DISCORD_COLOR": os.getenv("DISCORD_COLOR", ""),
        "AUDIOBOOKSHELF_URL": os.getenv("AUDIOBOOKSHELF_URL", ""),
        "AUDIOBOOKSHELF_TOKEN": os.getenv("AUDIOBOOKSHELF_TOKEN", ""),
        "show_services": os.getenv("SHOW_SERVICES", "yes").lower() == "yes",
        "custom_services_url": os.getenv("CUSTOM_SERVICES_URL", "").strip(),
        "DISCORD_NOTIFY_PLEX": os.getenv("DISCORD_NOTIFY_PLEX", "1"),
        "DISCORD_NOTIFY_ABS": os.getenv("DISCORD_NOTIFY_ABS", "1"),
        "DISCORD_NOTIFY_RATE_LIMITING": os.getenv("DISCORD_NOTIFY_RATE_LIMITING", "0"),
        "DISCORD_NOTIFY_IP_MANAGEMENT": os.getenv("DISCORD_NOTIFY_IP_MANAGEMENT", "0"),
        "DISCORD_NOTIFY_LOGIN_ATTEMPTS": os.getenv("DISCORD_NOTIFY_LOGIN_ATTEMPTS", "0"),
        "DISCORD_NOTIFY_FORM_RATE_LIMITING": os.getenv("DISCORD_NOTIFY_FORM_RATE_LIMITING", "0"),
        "DISCORD_NOTIFY_FIRST_ACCESS": os.getenv("DISCORD_NOTIFY_FIRST_ACCESS", "0"),
        "QUICK_ACCESS_ENABLED": os.getenv("QUICK_ACCESS_ENABLED", "yes"),
        "QA_PLEX_ENABLED": os.getenv("QA_PLEX_ENABLED", "yes"),
        "QA_AUDIOBOOKSHELF_ENABLED": os.getenv("QA_AUDIOBOOKSHELF_ENABLED", "yes"),
        "QA_TAUTULLI_ENABLED": os.getenv("QA_TAUTULLI_ENABLED", "yes"),
        "QA_OVERSEERR_ENABLED": os.getenv("QA_OVERSEERR_ENABLED", "yes"),
        "QA_JELLYSEERR_ENABLED": os.getenv("QA_JELLYSEERR_ENABLED", "yes"),
        "IP_MANAGEMENT_ENABLED": os.getenv("IP_MANAGEMENT_ENABLED", "no"),
        "RATE_LIMIT_SETTINGS_ENABLED": os.getenv("RATE_LIMIT_SETTINGS_ENABLED", "yes"),
        "RATE_LIMIT_MAX_LOGIN_ATTEMPTS": int(os.getenv("RATE_LIMIT_MAX_LOGIN_ATTEMPTS", os.getenv("RATE_LIMIT_LOGIN_ATTEMPTS", "5"))),
        "RATE_LIMIT_MAX_FORM_SUBMISSIONS": int(os.getenv("RATE_LIMIT_MAX_FORM_SUBMISSIONS", os.getenv("RATE_LIMIT_FORM_SUBMISSIONS", "1"))),
        "ip_lists": get_ip_lists()
    }

@app.route("/ajax/load-library-posters", methods=["POST"])
def ajax_load_library_posters():
    """Load poster data for a specific library on-demand"""
    if not session.get("authenticated"):
        return jsonify({"success": False, "error": "Unauthorized"})
    
    try:
        data = request.get_json()
        library_index = data.get("library_index")
        
        if library_index is None:
            return jsonify({"success": False, "error": "Library index required"})
        
        # Get the library info - use local files for better performance
        libraries = get_libraries_from_local_files()
        selected_ids = os.getenv("LIBRARY_IDS", "")
        selected_ids = [i.strip() for i in selected_ids.split(",") if i.strip()]
        filtered_libraries = [lib for lib in libraries if lib["key"] in selected_ids]
        
        if library_index >= len(filtered_libraries):
            return jsonify({"success": False, "error": "Invalid library index"})
        
        library = filtered_libraries[library_index]
        section_id = library["key"]
        name = library["title"]
        
        # First, get ALL titles from the library (same as fetch_titles_for_library)
        all_titles = []
        
        # Get Plex credentials directly from environment
        plex_token = os.getenv("PLEX_TOKEN")
        plex_url = os.getenv("PLEX_URL")
        
        if not plex_token or not plex_url:
            if debug_mode:
                print("[ERROR] Plex credentials not available for loading library posters")
            return jsonify({"success": False, "error": "Plex credentials not available"})
        
        headers = {"X-Plex-Token": plex_token}
        url = f"{plex_url}/library/sections/{section_id}/all"
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            root = ET.fromstring(response.content)
            for el in root.findall(".//Video"):
                title = el.attrib.get("title")
                if title:
                    all_titles.append(title)
            for el in root.findall(".//Directory"):
                title = el.attrib.get("title")
                if title and title not in all_titles:
                    all_titles.append(title)
        except Exception as e:
            if debug_mode:
                print(f"Error fetching titles for section {section_id}: {e}")
        
        # Create a dictionary to map titles to their poster data
        title_to_poster = {}
        
        # Load poster metadata for this specific library
        poster_dir = get_library_poster_dir(section_id)
        if os.path.exists(poster_dir):
            # Get all JSON files and sort by modification time (most recent first)
            json_files = [f for f in os.listdir(poster_dir) if f.endswith(".json")]
            json_files.sort(key=lambda f: os.path.getmtime(os.path.join(poster_dir, f)), reverse=True)
            
            for fname in json_files:
                meta_path = os.path.join(poster_dir, fname)
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                    title = meta.get("title")
                    if title:
                        poster_file = meta.get("poster")
                        poster_url = f"/static/posters/{section_id}/{poster_file}" if poster_file else None
                        # Check if this is a music artist and add Last.fm URL
                        is_artist = is_music_artist(meta, library)
                        lastfm_url = get_lastfm_url(title) if is_artist else None
                        
                        title_to_poster[title] = {
                            "poster": poster_url,
                            "title": title,
                            "imdb": meta.get("imdb"),
                            "tmdb": meta.get("tmdb"),
                            "tvdb": meta.get("tvdb"),
                            "lastfm_url": lastfm_url,
                            "is_artist": is_artist,
                        }
                except Exception as e:
                    if debug_mode:
                        print(f"Error loading poster metadata: {e}")
                    # Skip corrupted files
                    continue
        
        # Create unified items list - include ALL titles with poster data when available
        unified_items = []
        for title in all_titles:
            if title in title_to_poster:
                # Use poster data if available
                unified_items.append(title_to_poster[title])
            else:
                # Just the title without poster
                # Check if this might be a music artist (no year typically indicates artist)
                is_artist = is_music_artist({"title": title, "year": None}, library)
                lastfm_url = get_lastfm_url(title) if is_artist else None
                
                unified_items.append({
                    "poster": None,
                    "title": title,
                    "imdb": None,
                    "tmdb": None,
                    "tvdb": None,
                    "lastfm_url": lastfm_url,
                    "is_artist": is_artist,
                })
        
        # Group items by letter
        poster_groups = group_posters_by_letter(unified_items)
        
        return jsonify({
            "success": True,
            "library_name": name,
            "poster_groups": poster_groups
        })
        
    except Exception as e:
        if debug_mode:
            print(f"Error loading library posters: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route("/ajax/load-all-items", methods=["POST"])
def ajax_load_all_items():
    if not session.get("authenticated"):
        return jsonify({"success": False, "error": "Not authenticated"})
    
    try:
        data = request.get_json()
        library_index = data.get("library_index")
        
        if library_index is None:
            return jsonify({"success": False, "error": "Library index required"})
        
        # Convert library_index to integer
        try:
            library_index = int(library_index)
            if debug_mode:
                print(f"DEBUG: library_index = {library_index} (type: {type(library_index)})")
        except (ValueError, TypeError):
            return jsonify({"success": False, "error": "Invalid library index format"})
        
        # Get all libraries - use local files for better performance
        libraries = get_libraries_from_local_files()
        selected_ids = os.getenv("LIBRARY_IDS", "")
        selected_ids = [i.strip() for i in selected_ids.split(",") if i.strip()]
        filtered_libraries = [lib for lib in libraries if lib["key"] in selected_ids]
        
        if debug_mode:
            print(f"DEBUG: len(filtered_libraries) = {len(filtered_libraries)}")
        
        if library_index >= len(filtered_libraries):
            return jsonify({"success": False, "error": "Invalid library index"})
        
        library = filtered_libraries[library_index]
        section_id = library["key"]
        
        # Load cached poster metadata for this specific library
        poster_dir = get_library_poster_dir(section_id)
        items_with_posters = []
        
        if os.path.exists(poster_dir):
            # Get all JSON files
            json_files = [f for f in os.listdir(poster_dir) if f.endswith(".json")]
            
            for fname in json_files:
                meta_path = os.path.join(poster_dir, fname)
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                    
                    title = meta.get("title")
                    if title:
                        poster_file = meta.get("poster")
                        poster_url = f"/static/posters/{section_id}/{poster_file}" if poster_file else None
                        
                        # Check if this is a music artist and add Last.fm URL
                        is_artist = is_music_artist(meta, library)
                        lastfm_url = get_lastfm_url(title) if is_artist else None
                        
                        items_with_posters.append({
                            "title": title,
                            "poster": poster_url,
                            "imdb": meta.get("imdb"),
                            "tmdb": meta.get("tmdb"),
                            "tvdb": meta.get("tvdb"),
                            "lastfm_url": lastfm_url,
                            "is_artist": is_artist,
                        })
                except Exception as e:
                    if debug_mode:
                        print(f"Error loading poster metadata from {meta_path}: {e}")
                    continue
        
        # Sort items alphabetically by title (stripping articles for sorting)
        items_with_posters.sort(key=lambda x: strip_articles(x["title"]).lower())
        
        if debug_mode:
            print(f"DEBUG: Returning {len(items_with_posters)} items with posters")
            print(f"DEBUG: Items with posters: {[item.get('title', 'Unknown') for item in items_with_posters[:5]]}")
        
        return jsonify({"success": True, "items": items_with_posters})
        
    except Exception as e:
        if debug_mode:
            print(f"Error loading all items: {e}")
            import traceback
            traceback.print_exc()
        return jsonify({"success": False, "error": str(e)})

@app.route("/ajax/load-posters-by-letter", methods=["POST"])
def ajax_load_posters_by_letter():
    """Load poster data for a specific library and letter on-demand"""
    if not session.get("authenticated"):
        return jsonify({"success": False, "error": "Unauthorized"})
    
    try:
        data = request.get_json()
        library_index = data.get("library_index")
        letter = data.get("letter")
        
        if library_index is None or letter is None:
            return jsonify({"success": False, "error": "Library index and letter required"})
        
        # Convert library_index to integer
        try:
            library_index = int(library_index)
        except (ValueError, TypeError):
            return jsonify({"success": False, "error": "Invalid library index format"})
        
        # Get the library info - use local files for better performance
        libraries = get_libraries_from_local_files()
        selected_ids = os.getenv("LIBRARY_IDS", "")
        selected_ids = [i.strip() for i in selected_ids.split(",") if i.strip()]
        filtered_libraries = [lib for lib in libraries if lib["key"] in selected_ids]
        
        if library_index >= len(filtered_libraries):
            return jsonify({"success": False, "error": "Invalid library index"})
        
        library = filtered_libraries[library_index]
        section_id = library["key"]
        name = library["title"]
        
        # Load cached poster metadata for this specific library
        poster_dir = get_library_poster_dir(section_id)
        unified_items = []
        
        if os.path.exists(poster_dir):
            # Get all JSON files
            json_files = [f for f in os.listdir(poster_dir) if f.endswith(".json")]
            
            for fname in json_files:
                meta_path = os.path.join(poster_dir, fname)
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                    
                    title = meta.get("title")
                    if title:
                        # Strip articles for sorting purposes
                        sort_title = strip_articles(title)
                        
                        # Use the same letter extraction logic as group_titles_by_letter
                        letter_match = False
                        
                        if sort_title and sort_title[0].isdigit():
                            # Check if sort_title starts with a digit
                            if letter == "0-9":
                                letter_match = True
                        else:
                            # Find the first ASCII letter in the sort_title
                            match = re.search(r'[A-Za-z]', sort_title)
                            if match:
                                extracted_letter = match.group(0).upper()
                                if letter == extracted_letter:
                                    letter_match = True
                            elif any(c.isdigit() for c in sort_title):
                                if letter == "0-9":
                                    letter_match = True
                            else:
                                if letter == "Other":
                                    letter_match = True
                        
                        if letter_match:
                            poster_file = meta.get("poster")
                            poster_url = f"/static/posters/{section_id}/{poster_file}" if poster_file else None
                            
                            # Check if this is a music artist and add Last.fm URL
                            is_artist = is_music_artist(meta, library)
                            lastfm_url = get_lastfm_url(title) if is_artist else None
                            
                            unified_items.append({
                                "poster": poster_url,
                                "title": title,
                                "ratingKey": meta.get("ratingKey"),
                                "year": meta.get("year"),
                                "imdb": meta.get("imdb"),
                                "tmdb": meta.get("tmdb"),
                                "tvdb": meta.get("tvdb"),
                                "lastfm_url": lastfm_url,
                                "is_artist": is_artist,
                            })
                except Exception as e:
                    if debug_mode:
                        print(f"Error loading poster metadata: {e}")
                    continue
        
        # Sort items alphabetically by title (stripping articles for sorting)
        unified_items.sort(key=lambda x: strip_articles(x["title"]).lower())
        
        return jsonify({
            "success": True,
            "library_name": name,
            "letter": letter,
            "items": unified_items
        })
        
    except Exception as e:
        if debug_mode:
            print(f"Error loading posters by letter: {e}")
        return jsonify({"success": False, "error": str(e)})

# Hashing and encryption utilities
def generate_salt():
    """Generate a random salt for password hashing"""
    return secrets.token_bytes(32)

def hash_password(password, salt=None):
    """Hash a password using PBKDF2 with SHA256"""
    if salt is None:
        salt = generate_salt()
    
    # Use PBKDF2 with 100,000 iterations for security
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return base64.urlsafe_b64encode(salt).decode(), key.decode()

def verify_password(password, salt, hashed_password):
    """Verify a password against its hash"""
    try:
        salt_bytes = base64.urlsafe_b64decode(salt.encode())
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_bytes,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return hmac.compare_digest(key.decode(), hashed_password)
    except Exception:
        return False

def hash_api_key(api_key):
    """Hash an API key using SHA256"""
    if not api_key:
        return ""
    return hashlib.sha256(api_key.encode()).hexdigest()

def verify_api_key(api_key, hashed_api_key):
    """Verify an API key against its hash"""
    if not api_key and not hashed_api_key:
        return True  # Both empty is valid
    if not api_key or not hashed_api_key:
        return False
    return hmac.compare_digest(hash_api_key(api_key), hashed_api_key)

def encrypt_sensitive_data(data, key=None):
    """Encrypt sensitive data using Fernet"""
    if not data:
        return None, None
    
    if key is None:
        key = Fernet.generate_key()
    
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode())
    return base64.urlsafe_b64encode(key).decode(), encrypted_data.decode()

def decrypt_sensitive_data(encrypted_data, key):
    """Decrypt sensitive data using Fernet"""
    if not encrypted_data or not key:
        return None
    
    try:
        key_bytes = base64.urlsafe_b64decode(key.encode())
        f = Fernet(key_bytes)
        decrypted_data = f.decrypt(encrypted_data.encode())
        return decrypted_data.decode()
    except Exception:
        return None

def get_api_key_with_verification(api_key_name, provided_key=None):
    """Get API key with verification - checks hashed version if available, falls back to plain text"""
    if provided_key:
        # If a key is provided, verify it against the hash
        hashed_key = os.getenv(f"{api_key_name}_HASH")
        if hashed_key:
            return verify_api_key(provided_key, hashed_key)
        else:
            # No hash available, compare with plain text
            stored_key = os.getenv(api_key_name)
            return stored_key == provided_key if stored_key else False
    
    # Return the actual key for use (plain text for backward compatibility)
    return os.getenv(api_key_name)

def save_api_key_with_hash(env_path, api_key_name, api_key_value):
    """Save API key with hash for verification"""
    if api_key_value:
        # Hash the API key
        hashed_key = hash_api_key(api_key_value)
        safe_set_key(env_path, f"{api_key_name}_HASH", hashed_key)
        # Keep plain text for backward compatibility
        safe_set_key(env_path, api_key_name, api_key_value)
    else:
        # Clear both hash and plain text
        safe_set_key(env_path, f"{api_key_name}_HASH", "")
        safe_set_key(env_path, api_key_name, "")

@app.route("/trigger-abs-poster-downloads", methods=["POST"])
@csrf.exempt
def trigger_abs_poster_downloads_route():
    """Manually trigger ABS poster downloads"""
    try:
        if os.getenv("ABS_ENABLED", "yes") != "yes":
            return jsonify({"success": False, "error": "ABS is not enabled"})
        
        # Force refresh and queue download
        global abs_download_queued
        force_abs_poster_refresh()
        poster_download_queue.put(('abs', None, None))
        abs_download_queued = True
        
        if debug_mode:
            print("[INFO] Manually triggered ABS poster download")
        
        return jsonify({"success": True, "message": "ABS poster download queued"})
    except Exception as e:
        if debug_mode:
            print(f"[ERROR] Error triggering ABS poster download: {e}")
        return jsonify({"success": False, "error": str(e)})


@csrf.exempt
def trigger_poster_downloads_route():
    """Manually trigger poster downloads for debugging"""
    if not session.get("admin_authenticated"):
        return jsonify({"success": False, "error": "Unauthorized"})
    
    try:
        # Ensure worker is running
        ensure_worker_running()
        
        # Get current library selection - use cached data for better performance
        selected_ids = os.getenv("LIBRARY_IDS", "")
        selected_ids = [i.strip() for i in selected_ids.split(",") if i.strip()]
        all_libraries = get_plex_libraries(force_refresh=False)  # Use cached data for admin function
        libraries = [lib for lib in all_libraries if lib["key"] in selected_ids]
        
        if libraries:
            # Queue poster downloads for background processing
            download_and_cache_posters_for_libraries(libraries, background=True)
            if debug_mode:
                print(f"[INFO] Manually triggered poster download for {len(libraries)} libraries")
        
        # Queue ABS poster download if enabled
        if os.getenv("ABS_ENABLED", "yes") == "yes":
            global abs_download_queued
            poster_download_queue.put(('abs', None, None))
            abs_download_queued = True
            if debug_mode:
                print("[INFO] Manually triggered ABS poster download")
        
        return jsonify({"success": True, "message": "Poster downloads triggered"})
    except Exception as e:
        if debug_mode:
            print(f"Error triggering poster downloads: {e}")
        return jsonify({"success": False, "error": str(e)})





@app.route("/poster-status", methods=["GET"])
def poster_status():
    """Get poster download status for debugging"""
    if not session.get("admin_authenticated"):
        return jsonify({"success": False, "error": "Unauthorized"})
    
    try:
        queue_size = poster_download_queue.qsize()
        progress = get_poster_download_progress()
        
        return jsonify({
            "success": True,
            "worker_running": poster_download_running,
            "queue_size": queue_size,
            "progress": progress,
            "debug_mode": debug_mode
        })
    except Exception as e:
        if debug_mode:
            print(f"Error getting poster status: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route("/ajax/update-libraries", methods=["POST"])
def ajax_update_libraries():
    if not session.get("admin_authenticated"):
        return jsonify({"success": False, "error": "Unauthorized"})
    
    try:
        data = request.get_json()
        library_ids = data.get("library_ids", [])
        
        # Ensure library_ids are properly formatted (no commas within individual IDs)
        cleaned_library_ids = []
        for lib_id in library_ids:
            # Remove any commas from individual library IDs
            cleaned_id = str(lib_id).replace(",", "").strip()
            if cleaned_id:
                cleaned_library_ids.append(cleaned_id)
        
        # Update the LIBRARY_IDS environment variable
        env_path = os.path.join(os.getcwd(), ".env")
        safe_set_key(env_path, "LIBRARY_IDS", ",".join(cleaned_library_ids))
        
        # Reload environment variables
        load_dotenv(override=True)
        
        # Update library notes with media type information
        try:
            library_notes = load_library_notes()
            plex_token = os.getenv("PLEX_TOKEN")
            plex_url = os.getenv("PLEX_URL")
            
            if plex_token and plex_url:
                headers = {"X-Plex-Token": plex_token}
                
                # Get all libraries to get their media types
                url = f"{plex_url}/library/sections"
                response = requests.get(url, headers=headers, timeout=5)
                response.raise_for_status()
                root = ET.fromstring(response.text)
                
                # Create a mapping of library IDs to their titles and media types
                id_to_title = {}
                id_to_media_type = {}
                for directory in root.findall(".//Directory"):
                    key = directory.attrib.get("key")
                    title = directory.attrib.get("title")
                    media_type = directory.attrib.get("type")
                    if key:
                        if title:
                            id_to_title[key] = title
                        if media_type:
                            id_to_media_type[key] = media_type
                
                # Update library notes with titles and media types
                updated = False
                for lib_id in cleaned_library_ids:
                    if lib_id not in library_notes:
                        library_notes[lib_id] = {}
                    
                    # Update title if available
                    title = id_to_title.get(lib_id)
                    if title and library_notes[lib_id].get('title') != title:
                        library_notes[lib_id]['title'] = title
                        updated = True
                        if debug_mode:
                            print(f"[DEBUG] Updated title for library {lib_id}: {title}")
                    
                    # Update media type if available
                    media_type = id_to_media_type.get(lib_id)
                    if media_type and library_notes[lib_id].get('media_type') != media_type:
                        library_notes[lib_id]['media_type'] = media_type
                        updated = True
                        if debug_mode:
                            print(f"[DEBUG] Updated media type for library {lib_id}: {media_type}")
                
                if updated:
                    save_library_notes(library_notes)
                    if debug_mode:
                        print(f"[INFO] Updated titles and media types for {len(cleaned_library_ids)} libraries")
                        
        except Exception as e:
            if debug_mode:
                print(f"[WARN] Failed to update library media types: {e}")
        
        if debug_mode:
            print(f"[INFO] Updated library IDs to: {cleaned_library_ids}")
        
        return jsonify({"success": True})
        
    except Exception as e:
        if debug_mode:
            print(f"Error updating libraries: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route("/ajax/get-random-posters", methods=["POST"])
@csrf.exempt
def get_random_posters():
    """Get random posters for a specific library"""
    if not session.get("authenticated"):
        return jsonify({"error": "Not authenticated"}), 401
    
    data = request.get_json()
    if not data:
        print("No JSON data received")
        print(f"Request data: {request.data}")
        print(f"Request headers: {dict(request.headers)}")
        return jsonify({"error": "No JSON data"}), 400
    
    library_name = data.get('library')
    count = data.get('count', 5)
    
    print(f"Requested posters for library: '{library_name}', count: {count}")
    print(f"Full request data: {data}")
    
    if not library_name:
        print("Library name is empty")
        return jsonify({"error": "Library name required"}), 400
    
    # Find the library by name - use local files for better performance
    libraries = get_libraries_from_local_files()
    library = None
    for lib in libraries:
        if lib["title"] == library_name:
            library = lib
            break
    
    if not library:
        print(f"Library '{library_name}' not found. Available libraries: {[lib['title'] for lib in libraries]}")
        return jsonify({"error": f"Library '{library_name}' not found"}), 404
    
    section_id = library["key"]
    poster_dir = get_library_poster_dir(section_id)
    
    print(f"Looking for posters in: {poster_dir}")
    
    try:
        if os.path.exists(poster_dir):
            # Get all image files
            all_files = [f for f in os.listdir(poster_dir) if f.lower().endswith(('.webp', '.jpg', '.jpeg', '.png'))]
            
            print(f"Found {len(all_files)} poster files in {poster_dir}")
            
            if not all_files:
                print(f"No poster files found in {poster_dir}")
                return jsonify({"posters": [], "imdb_ids": [], "titles": []})
            
            # Get random posters
            import random
            if len(all_files) > count:
                selected_files = random.sample(all_files, count)
            else:
                selected_files = all_files
            
            posters = []
            imdb_ids = []
            lastfm_urls = []
            titles = []
            
            for fname in selected_files:
                poster_url = f"/static/posters/{section_id}/{fname}"
                posters.append(poster_url)
                
                # Extract title from filename
                title = fname.rsplit('.', 1)[0].replace('_', ' ').replace('-', ' ').title()
                titles.append(title)
                
                # Load metadata
                json_path = os.path.join(poster_dir, fname.rsplit('.', 1)[0] + '.json')
                imdb_id = None
                lastfm_url = None
                try:
                    if os.path.exists(json_path):
                        with open(json_path, 'r', encoding='utf-8') as f:
                            meta = json.load(f)
                            imdb_id = meta.get('imdb')
                            # Use metadata title if available
                            if meta.get('title'):
                                titles[-1] = meta.get('title')
                            # Check if this is a music artist
                            is_artist = is_music_artist(meta, lib)
                            if is_artist:
                                title = meta.get('title')
                                lastfm_url = get_lastfm_url(title) if title else None
                except (IOError, json.JSONDecodeError) as e:
                    print(f"Error loading metadata for {fname}: {e}")
                    pass
                
                imdb_ids.append(imdb_id)
                lastfm_urls.append(lastfm_url)
            
            print(f"Returning {len(posters)} posters for {library_name}")
            return jsonify({
                "posters": posters,
                "imdb_ids": imdb_ids,
                "lastfm_urls": lastfm_urls,
                "titles": titles
            })
        else:
            print(f"Poster directory does not exist: {poster_dir}")
            return jsonify({"posters": [], "imdb_ids": [], "lastfm_urls": [], "titles": []})
            
    except Exception as e:
        print(f"Error getting random posters for {library_name}: {e}")
        return jsonify({"error": "Failed to get posters"}), 500

@app.route("/ajax/get-random-posters-all", methods=["POST"])
@csrf.exempt
def get_random_posters_all():
    """Get random posters from all libraries combined (excluding music by default)"""
    if not session.get("authenticated"):
        return jsonify({"error": "Not authenticated"}), 401
    
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data"}), 400
    
    count = data.get('count', 5)
    include_music = data.get('include_music', False)  # Default to False
    
    print(f"Requested posters from all libraries, count: {count}, include_music: {include_music}")
    
    try:
        # Get all libraries from local files only (no Plex API calls)
        all_libraries = get_libraries_from_local_files()
        
        # First filter by LIBRARY_IDS to get only available libraries (same logic as onboarding route)
        selected_ids = [id.strip() for id in os.getenv("LIBRARY_IDS", "").split(",") if id.strip()]
        selected_ids_str = [str(id).strip() for id in selected_ids]
        available_libraries = [lib for lib in all_libraries if str(lib["key"]) in selected_ids_str]
        
        # Then filter by carousel settings to get libraries that should show carousels
        libraries = available_libraries.copy()
        library_carousels = os.getenv("LIBRARY_CAROUSELS", "")
        if library_carousels:
            # Only include libraries that have carousels enabled
            carousel_ids = [str(id).strip() for id in library_carousels.split(",") if str(id).strip()]
            libraries = [lib for lib in available_libraries if str(lib["key"]) in carousel_ids]
            print(f"Filtered to {len(libraries)} libraries with carousels enabled (from {len(available_libraries)} available libraries)")
        else:
            print(f"Using all {len(available_libraries)} available libraries for carousel")
        
        # Apply custom carousel tab order if specified
        library_carousel_order = os.getenv("LIBRARY_CAROUSEL_ORDER", "")
        if library_carousel_order and libraries:
            # Get the custom order of library IDs
            custom_order_ids = [str(id).strip() for id in library_carousel_order.split(",") if str(id).strip()]
            
            # Filter out non-existing library IDs and create ordered list
            ordered_libraries = []
            for lib_id in custom_order_ids:
                matching_lib = next((lib for lib in libraries if str(lib["key"]) == lib_id), None)
                if matching_lib:
                    ordered_libraries.append(matching_lib)
            
            # Add any remaining libraries that weren't in the custom order
            remaining_libs = [lib for lib in libraries if str(lib["key"]) not in custom_order_ids]
            ordered_libraries.extend(remaining_libs)
            
            # Update libraries with the custom order
            libraries = ordered_libraries
        
        all_posters = []
        all_imdb_ids = []
        all_lastfm_urls = []
        all_titles = []
        
        # Collect posters from libraries with carousels enabled (excluding music unless explicitly requested)
        for lib in libraries:
            section_id = lib["key"]
            media_type = lib.get("media_type", "")
            
            # Skip music libraries unless explicitly requested
            if media_type == "artist" and not include_music:
                if debug_mode:
                    print(f"Skipping music library: {lib['title']}")
                continue
                
            poster_dir = get_library_poster_dir(section_id)
            
            if os.path.exists(poster_dir):
                # Get all image files
                all_files = [f for f in os.listdir(poster_dir) if f.lower().endswith(('.webp', '.jpg', '.jpeg', '.png'))]
                
                for fname in all_files:
                    poster_url = f"/static/posters/{section_id}/{fname}"
                    all_posters.append(poster_url)
                    
                    # Extract title from filename
                    title = fname.rsplit('.', 1)[0].replace('_', ' ').replace('-', ' ').title()
                    all_titles.append(title)
                    
                    # Load metadata
                    json_path = os.path.join(poster_dir, fname.rsplit('.', 1)[0] + '.json')
                    imdb_id = None
                    lastfm_url = None
                    try:
                        if os.path.exists(json_path):
                            with open(json_path, 'r', encoding='utf-8') as f:
                                meta = json.load(f)
                                imdb_id = meta.get('imdb')
                                # Use metadata title if available
                                if meta.get('title'):
                                    all_titles[-1] = meta.get('title')
                                # Check if this is a music artist
                                is_artist = is_music_artist(meta, lib)
                                if is_artist:
                                    title = meta.get('title')
                                    lastfm_url = get_lastfm_url(title) if title else None
                    except (IOError, json.JSONDecodeError) as e:
                        print(f"Error loading metadata for {fname}: {e}")
                        pass
                    
                    all_imdb_ids.append(imdb_id)
                    all_lastfm_urls.append(lastfm_url)
        
        if not all_posters:
            print("No posters found in any library")
            return jsonify({"posters": [], "imdb_ids": [], "lastfm_urls": [], "titles": []})
        
        # Get random posters from all libraries combined
        import random
        if len(all_posters) > count:
            # Get random indices
            indices = random.sample(range(len(all_posters)), count)
            selected_posters = [all_posters[i] for i in indices]
            selected_imdb_ids = [all_imdb_ids[i] for i in indices]
            selected_lastfm_urls = [all_lastfm_urls[i] for i in indices]
            selected_titles = [all_titles[i] for i in indices]
        else:
            selected_posters = all_posters
            selected_imdb_ids = all_imdb_ids
            selected_lastfm_urls = all_lastfm_urls
            selected_titles = all_titles
        
        print(f"Returning {len(selected_posters)} posters from libraries with carousels enabled")
        return jsonify({
            "posters": selected_posters,
            "imdb_ids": selected_imdb_ids,
            "lastfm_urls": selected_lastfm_urls,
            "titles": selected_titles
        })
            
    except Exception as e:
        print(f"Error getting random posters from all libraries: {e}")
        return jsonify({"error": "Failed to get posters"}), 500

@app.route("/ajax/get-random-audiobook-posters", methods=["POST"])
@csrf.exempt
def get_random_audiobook_posters():
    """Get random audiobook posters for dynamic loading"""
    if not session.get("authenticated"):
        return jsonify({"error": "Not authenticated"}), 401
    
    data = request.get_json()
    if not data:
        print("No JSON data received for audiobook posters")
        return jsonify({"error": "No JSON data"}), 400
    
    count = data.get('count', 5)
    
    print(f"Requested audiobook posters, count: {count}")
    
    # Check which audiobook poster files actually exist
    audiobook_dir = os.path.join("static", "posters", "audiobooks")
    existing_paths = []
    goodreads_links = []
    titles = []
    
    try:
        if os.path.exists(audiobook_dir):
            # Get all image files
            all_files = [f for f in os.listdir(audiobook_dir) if f.lower().endswith(('.webp', '.jpg', '.jpeg', '.png'))]
            
            print(f"Found {len(all_files)} audiobook poster files")
            
            if not all_files:
                print(f"No audiobook poster files found in {audiobook_dir}")
                return jsonify({"posters": [], "goodreads_links": [], "titles": []})
            
            # Get random posters
            if len(all_files) > count:
                selected_files = random.sample(all_files, count)
            else:
                selected_files = all_files
            
            for fname in selected_files:
                poster_url = f"/static/posters/audiobooks/{fname}"
                existing_paths.append(poster_url)
                
                # Try to get actual title and author from metadata if available
                json_path = os.path.join(audiobook_dir, fname.rsplit('.', 1)[0] + '.json')
                search_query = ""
                title = ""
                
                try:
                    if os.path.exists(json_path):
                        with open(json_path, 'r', encoding='utf-8') as f:
                            meta = json.load(f)
                            title = meta.get('title', '')
                            author = meta.get('author', '')
                            
                            if title and author:
                                search_query = f"{author} {title}"
                            elif title:
                                search_query = title
                            else:
                                # Fallback to generic filename if no metadata
                                title = fname.rsplit('.', 1)[0].replace('_', ' ').replace('-', ' ').title()
                                search_query = title
                    else:
                        # Fallback to generic filename if no JSON file
                        title = fname.rsplit('.', 1)[0].replace('_', ' ').replace('-', ' ').title()
                        search_query = title
                except (IOError, json.JSONDecodeError):
                    # Fallback to generic filename if JSON read fails
                    title = fname.rsplit('.', 1)[0].replace('_', ' ').replace('-', ' ').title()
                    search_query = title
                
                # Create Goodreads search URL with proper URL encoding
                import urllib.parse
                encoded_query = urllib.parse.quote(search_query)
                goodreads_url = f"https://www.goodreads.com/search?q={encoded_query}"
                goodreads_links.append(goodreads_url)
                titles.append(title)
            
            print(f"Returning {len(existing_paths)} audiobook posters")
            return jsonify({
                "posters": existing_paths,
                "goodreads_links": goodreads_links,
                "titles": titles
            })
        else:
            print(f"Audiobook poster directory does not exist: {audiobook_dir}")
            return jsonify({"posters": [], "goodreads_links": [], "titles": []})
            
    except Exception as e:
        print(f"Error getting random audiobook posters: {e}")
        return jsonify({"error": "Failed to get audiobook posters"}), 500

def load_ip_lists_from_env():
    """Load IP lists from environment variables"""
    env_path = '.env'
    
    # Load whitelisted IPs
    whitelisted_str = os.getenv("IP_WHITELIST", "")
    if whitelisted_str:
        whitelisted_ips = [ip.strip() for ip in whitelisted_str.split(",") if ip.strip()]
        rate_limit_data['whitelisted_ips'].update(whitelisted_ips)
    
    # Load blacklisted IPs
    blacklisted_str = os.getenv("IP_BLACKLIST", "")
    if blacklisted_str:
        blacklisted_ips = [ip.strip() for ip in blacklisted_str.split(",") if ip.strip()]
        rate_limit_data['banned_ips'].update(blacklisted_ips)

def save_ip_lists_to_env():
    """Save IP lists to environment variables"""
    env_path = '.env'
    
    # Save whitelisted IPs
    whitelisted_str = ",".join(list(rate_limit_data['whitelisted_ips']))
    safe_set_key(env_path, "IP_WHITELIST", whitelisted_str)
    
    # Save blacklisted IPs
    blacklisted_str = ",".join(list(rate_limit_data['banned_ips']))
    safe_set_key(env_path, "IP_BLACKLIST", blacklisted_str)

def initialize_environment():
    """Initialize environment variables and global configuration"""
    global MOVIES_SECTION_ID, SHOWS_SECTION_ID, AUDIOBOOKS_SECTION_ID, debug_mode
    MOVIES_SECTION_ID = os.getenv("MOVIES_ID")
    SHOWS_SECTION_ID = os.getenv("SHOWS_ID")
    AUDIOBOOKS_SECTION_ID = os.getenv("AUDIOBOOKS_ID")
    
    # Update debug_mode from environment to ensure it's current
    # This ensures debug_mode is always up to date with the latest .env value
    debug_mode = os.getenv("FLASK_DEBUG", "0") == "1"
    return debug_mode

def setup_library_notes(debug_mode):
    """Setup and recreate library notes if needed"""
    if os.environ.get('WERKZEUG_RUN_MAIN') != 'true' and os.getenv("SETUP_COMPLETE") == "1":
        # Check if library notes exist and are complete
        existing_notes = load_library_notes()
        selected_ids_str = os.getenv("LIBRARY_IDS", "")
        selected_ids = [id.strip() for id in selected_ids_str.split(",") if id.strip()]
        
        # Only recreate if we're missing notes for any selected libraries
        missing_notes = [lib_id for lib_id in selected_ids if lib_id not in existing_notes]
        if missing_notes:
            if debug_mode:
                print(f"[INFO] Missing library notes for {len(missing_notes)} libraries, updating from Plex API...")
            recreate_library_notes()
        else:
            if debug_mode:
                print("[DEBUG] All library notes are up to date, skipping update")

def setup_poster_worker():
    """Start background poster worker"""
    if os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        if not poster_download_running:
            start_background_poster_worker()
        else:
            if is_debug_mode():
                print("[DEBUG] Background poster worker already running, skipping setup")

def setup_poster_downloads(debug_mode):
    """Setup poster downloads and periodic refresh - NON-BLOCKING"""
    if os.getenv("SETUP_COMPLETE") == "1":
        # Start poster downloads in background thread to avoid blocking startup
        def background_setup():
            try:
                # Get Plex credentials directly from environment
                plex_token = os.getenv("PLEX_TOKEN")
                if not plex_token:
                    if is_debug_mode():
                        print("[WARN] Skipping poster download: PLEX_TOKEN is not set.")
                    return
                
                # Ensure worker is running before queuing downloads
                ensure_worker_running()
                
                # Queue poster downloads for background processing instead of blocking startup
                selected_ids = os.getenv("LIBRARY_IDS", "")
                selected_ids = [i.strip() for i in selected_ids.split(",") if i.strip()]
                
                # Use local files for startup instead of relying on cache
                try:
                    all_libraries = get_libraries_from_local_files()
                    if is_debug_mode():
                        print(f"[DEBUG] Using local files for startup, found {len(all_libraries)} libraries")
                except Exception as e:
                    if is_debug_mode():
                        print(f"[DEBUG] Error getting libraries from local files: {e}")
                    all_libraries = []
                
                libraries = [lib for lib in all_libraries if lib["key"] in selected_ids]
                
                if libraries:
                    # Check if posters need downloading (first startup or missing posters)
                    needs_download = False
                    for lib in libraries:
                        if should_refresh_posters(lib["key"]):
                            needs_download = True
                            break
                    
                    if needs_download and not is_poster_download_in_progress():
                        download_and_cache_posters_for_libraries(libraries, background=True)
                        if is_debug_mode():
                            print(f"[INFO] Queued poster download for {len(libraries)} libraries")
                    else:
                        if is_debug_mode():
                            print("[INFO] Posters are recent or download already in progress, skipping")
                
                # Start periodic refresh in background
                periodic_poster_refresh(libraries, interval_hours=24)
                
                # --- ADD THIS FOR ABS ---
                if os.getenv("ABS_ENABLED", "yes") == "yes":
                    # Check if ABS posters need downloading
                    if should_refresh_abs_posters():
                        poster_download_queue.put(('abs', None, None))
                        if is_debug_mode():
                            print("[INFO] Queued ABS poster download")
                    else:
                        if is_debug_mode():
                            print("[INFO] ABS posters are recent, skipping download")
                        
            except Exception as e:
                if debug_mode:
                    print(f"[ERROR] Background poster setup failed: {e}")
        
        # Start background setup thread
        setup_thread = threading.Thread(target=background_setup, daemon=True)
        setup_thread.start()
        
        if debug_mode:
            print("[INFO] Started background poster setup thread")
    else:
        if debug_mode:
            print("[INFO] Skipping poster download: setup is not complete.")

def setup_browser_opening(is_first_run):
    """Setup browser opening for first run"""
    if is_first_run and os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        print(f"\n[INFO] First run detected! Setup not complete.")
        print(f"[INFO] Server will start and browser will open automatically.")
        browser_thread = threading.Thread(target=open_browser_delayed, daemon=True)
        browser_thread.start()

def queue_posters_delayed(libraries):
    """Queue poster downloads with a small delay to ensure worker is ready"""
    time.sleep(1)  # Small delay to ensure worker is ready
    if debug_mode:
        print(f"[INFO] Starting poster download for {len(libraries)} libraries after setup")
    download_and_cache_posters_for_libraries(libraries, background=True)
    if debug_mode:
        print(f"[INFO] Completed poster download for {len(libraries)} libraries after setup")

def queue_abs_posters_delayed():
    """Queue ABS poster download with a small delay to ensure worker is ready"""
    global abs_download_queued
    time.sleep(1)  # Small delay to ensure worker is ready
    if debug_mode:
        print("[INFO] Starting ABS poster download after setup")
    poster_download_queue.put(('abs', None, None))
    abs_download_queued = True
    if debug_mode:
        print("[INFO] Queued ABS poster download after setup")

def fix_metadata_delayed():
    """Fix any missing metadata files after a delay"""
    time.sleep(5)  # Wait for poster downloads to complete
    if debug_mode:
        print("[INFO] Checking for missing metadata files after setup")
    fix_missing_metadata_files()
    if debug_mode:
        print("[INFO] Completed metadata file check after setup")

@app.route("/error-logs", methods=["GET", "POST"])
def error_logs():
    """View error logs for debugging (admin only)"""
    if not session.get("admin_authenticated"):
        return redirect(url_for("login"))
    
    # Handle clear logs request
    if request.method == "POST" and "clear_logs" in request.form:
        with error_lock:
            error_log.clear()
        return redirect(url_for("error_logs"))
    
    # Get recent errors
    recent_errors = error_log[-50:] if error_log else []  # Show last 50 errors
    
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Error Logs - Onboarderr</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .error-entry { 
                border: 1px solid #ddd; 
                margin: 10px 0; 
                padding: 15px; 
                border-radius: 5px;
                background-color: #f9f9f9;
            }
            .error-type { font-weight: bold; color: #d33fbc; }
            .error-time { color: #666; font-size: 0.9em; }
            .error-message { margin: 10px 0; }
            .error-details { 
                background-color: #f0f0f0; 
                padding: 10px; 
                border-radius: 3px; 
                font-family: monospace; 
                font-size: 0.9em;
                white-space: pre-wrap;
            }
            .error-traceback { 
                background-color: #ffe6e6; 
                padding: 10px; 
                border-radius: 3px; 
                font-family: monospace; 
                font-size: 0.8em;
                white-space: pre-wrap;
                color: #d33fbc;
            }
            .clear-button {
                background-color: #d33fbc;
                color: white;
                padding: 10px 20px;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                margin-bottom: 20px;
            }
            .clear-button:hover { background-color: #b02a9e; }
        </style>
    </head>
    <body>
        <h1>Error Logs</h1>
        <p>Showing last {{ recent_errors|length }} errors</p>
        
        <form method="POST" style="margin-bottom: 20px;">
            <button type="submit" name="clear_logs" class="clear-button">Clear Error Logs</button>
        </form>
        
        {% if recent_errors %}
            {% for error in recent_errors|reverse %}
            <div class="error-entry">
                <div class="error-time">{{ error.timestamp }}</div>
                <div class="error-type">{{ error.type }}</div>
                <div class="error-message">{{ error.message }}</div>
                {% if error.details %}
                <div class="error-details">{{ error.details | tojson(indent=2) }}</div>
                {% endif %}
                {% if error.traceback %}
                <div class="error-traceback">{{ error.traceback }}</div>
                {% endif %}
            </div>
            {% endfor %}
        {% else %}
            <p>No errors logged.</p>
        {% endif %}
        
        <p><a href="/services">Back to Services</a></p>
    </body>
    </html>
    """, recent_errors=recent_errors)

@app.route("/medialists")
def medialists():
    if not session.get("authenticated"):
        # Use client-side redirect to preserve hash fragments
        return render_template_string("""
            <!DOCTYPE html>
            <html>
            <head><title>Redirecting...</title></head>
            <body>
                <script>
                    sessionStorage.setItem('intended_url_after_login', window.location.href);
                    window.location.href = '/login';
                </script>
            </body>
            </html>
        """)
    
    # Check for first-time IP access
    client_ip = get_client_ip()
    check_first_time_ip_access(client_ip)

    # Get query parameters for filtering
    selected_service = request.args.get("service", "plex")
    selected_library = request.args.get("library", "all")

    # Get all libraries - use local files for better performance (no Plex API calls)
    try:
        libraries = get_libraries_from_local_files()
    except Exception as e:
        if debug_mode:
            print(f"Failed to get libraries from local files: {e}")
        libraries = []

    # Only include libraries specified in LIBRARY_IDS
    selected_ids = os.getenv("LIBRARY_IDS", "")
    selected_ids = [i.strip() for i in selected_ids.split(",") if i.strip()]
    filtered_libraries = [lib for lib in libraries if lib["key"] in selected_ids]

    library_media = {}
    library_counts = {}  # Track total counts for each library
    # Only load titles for libraries (posters will be loaded on-demand via AJAX)
    for lib in filtered_libraries:
        section_id = lib["key"]
        name = lib["title"]
        titles = fetch_titles_for_library(section_id)
        
        grouped_titles = group_titles_by_letter(titles)
        library_media[name] = grouped_titles
        library_counts[name] = len(titles)  # Store total count

    abs_enabled = os.getenv("ABS_ENABLED", "yes") == "yes"
    audiobooks = {}
    if abs_enabled:
        # Use the cache function instead of the non-existent fetch_audiobooks
        audiobooks = fetch_audiobooks_from_cache()

    # Use the cache function instead of the non-existent fetch_abs_books
    abs_books = fetch_abs_books_from_cache() if abs_enabled else []
    abs_book_groups = group_books_by_letter(abs_books) if abs_books else {}
    abs_book_count = len(abs_books) if abs_books else 0

    # Get template context with quick_access_services
    context = get_template_context()
    
    # Add page-specific variables
    context.update({
        "library_media": library_media,
        "library_counts": library_counts,  # Pass library counts
        "audiobooks": audiobooks,
        "abs_enabled": abs_enabled,
        "library_posters": {},  # Empty - will be loaded on-demand
        "library_poster_groups": {},  # Empty - will be loaded on-demand
        "abs_books": abs_books,
        "abs_book_groups": abs_book_groups,
        "abs_book_count": abs_book_count,
        "filtered_libraries": filtered_libraries,  # Pass library info for AJAX
        "logo_filename": get_logo_filename(),
        "selected_library": selected_library,
        "selected_service": selected_service
    })
    
    return render_template("medialists.html", **context)

def get_library_poster_dir(library_id):
    """Get the poster directory path for a library using the old naming format (just ID)"""
    return os.path.join("static", "posters", str(library_id))

if __name__ == "__main__":
    # --- Dynamic configuration for section IDs ---
    initialize_environment()  # This will update the global debug_mode variable
    
    # Load IP lists from environment variables
    load_ip_lists_from_env()
    
    # Check if this is the first run (setup not complete)
    is_first_run = os.getenv("SETUP_COMPLETE", "0") != "1"
    
    # Setup components
    setup_library_notes(is_debug_mode())
    setup_poster_worker()
    
    try:
        setup_poster_downloads(is_debug_mode())
    except Exception as e:
        if is_debug_mode():
            print(f"Warning: Could not queue poster downloads: {e}")
    
    # Setup browser opening
    setup_browser_opening(is_first_run)
    
    # Start periodic cleanup thread
    def periodic_cleanup():
        """Periodic cleanup of memory and resources"""
        while True:
            try:
                time.sleep(300)  # Run every 5 minutes
                cleanup_poster_progress()
                cleanup_library_cache()
                cleanup_expired_lockouts()
                if is_debug_mode():
                    print("[DEBUG] Completed periodic cleanup")
            except Exception as e:
                if is_debug_mode():
                    print(f"[ERROR] Periodic cleanup failed: {e}")
    
    cleanup_thread = threading.Thread(target=periodic_cleanup, daemon=True)
    cleanup_thread.start()
    
    if is_debug_mode():
        print("[INFO] Started periodic cleanup thread")
    
    app.run(host="0.0.0.0", port=APP_PORT, debug=is_debug_mode())
