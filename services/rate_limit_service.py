"""
Rate Limit Service

This module provides the RateLimitService class for handling all rate limiting logic,
IP management, and security-related business logic.
"""

import time
from typing import Dict, List, Optional, Any


class RateLimitService:
    """
    Service class for handling rate limiting, IP management, and security logic.
    
    This class extracts all rate limiting and security-related business logic from app.py
    and provides a clean interface for rate limiting operations.
    """
    
    def __init__(self, config_instance=None):
        """Initialize the rate limit service."""
        self.config = config_instance
        self._rate_limit_data = {
            'failed_attempts': {},
            'lockout_end_times': {},
            'form_submissions': {},
            'suspicious_ips': set(),
            'banned_ips': set(),
            'whitelisted_ips': set()
        }
        self._initialized = False
    
    def initialize(self) -> None:
        """Initialize the rate limit service with configuration."""
        self._initialized = True
        print(f"[INFO] Rate limit service initialized successfully")
    
    def cleanup(self) -> None:
        """Clean up the rate limit service."""
        self._initialized = False
        print(f"[DEBUG] Rate limit service cleaned up")
    
    def is_initialized(self) -> bool:
        """Check if the rate limit service is properly initialized."""
        return self._initialized
    
    def is_enabled(self) -> bool:
        """Check if rate limiting is enabled in configuration."""
        return self.config.get_bool("RATE_LIMIT_SETTINGS_ENABLED", True)
    
    def check_ip_suspicious(self, ip: str) -> bool:
        """
        Check if an IP address is marked as suspicious.
        
        Args:
            ip: The IP address to check
            
        Returns:
            True if the IP is suspicious, False otherwise
        """
        return ip in self._rate_limit_data['suspicious_ips']
    
    def check_ip_banned(self, ip: str) -> bool:
        """
        Check if an IP address is banned.
        
        Args:
            ip: The IP address to check
            
        Returns:
            True if the IP is banned, False otherwise
        """
        return ip in self._rate_limit_data['banned_ips']
    
    def is_ip_whitelisted(self, ip: str) -> bool:
        """
        Check if an IP address is whitelisted.
        
        Args:
            ip: The IP address to check
            
        Returns:
            True if the IP is whitelisted, False otherwise
        """
        return ip in self._rate_limit_data['whitelisted_ips']
    
    def add_suspicious_ip(self, ip: str) -> None:
        """
        Mark an IP address as suspicious.
        
        Args:
            ip: The IP address to mark as suspicious
        """
        self._rate_limit_data['suspicious_ips'].add(ip)
        print(f"[WARN] IP {ip} marked as suspicious")
    
    def remove_suspicious_ip(self, ip: str) -> None:
        """
        Remove an IP address from the suspicious list.
        
        Args:
            ip: The IP address to remove from suspicious list
        """
        self._rate_limit_data['suspicious_ips'].discard(ip)
        print(f"[INFO] IP {ip} removed from suspicious list")
    
    def add_banned_ip(self, ip: str) -> None:
        """
        Ban an IP address.
        
        Args:
            ip: The IP address to ban
        """
        self._rate_limit_data['banned_ips'].add(ip)
        print(f"[WARN] IP {ip} has been banned")
    
    def remove_banned_ip(self, ip: str) -> None:
        """
        Remove an IP address from the banned list.
        
        Args:
            ip: The IP address to remove from banned list
        """
        self._rate_limit_data['banned_ips'].discard(ip)
        print(f"[INFO] IP {ip} removed from banned list")
    
    def add_failed_attempt(self, ip: str, action_type: str) -> None:
        """
        Add a failed attempt for an IP address.
        
        Args:
            ip: The IP address to add failed attempt for
            action_type: The type of action that failed
        """
        if self.is_ip_whitelisted(ip):
            return
        
        current_time = time.time()
        
        if ip not in self._rate_limit_data['failed_attempts']:
            self._rate_limit_data['failed_attempts'][ip] = []
        
        self._rate_limit_data['failed_attempts'][ip].append(current_time)
        
        # Clean old attempts (older than 15 minutes)
        cutoff_time = current_time - 900
        self._rate_limit_data['failed_attempts'][ip] = [
            t for t in self._rate_limit_data['failed_attempts'][ip] 
            if t > cutoff_time
        ]
        
        # Check if we should ban or mark as suspicious
        attempts = len(self._rate_limit_data['failed_attempts'][ip])
        max_attempts = self.config.get_int("RATE_LIMIT_MAX_LOGIN_ATTEMPTS", 5)
        suspicious_threshold = self.config.get_int("RATE_LIMIT_IP_SUSPICIOUS_THRESHOLD", 3)
        ban_threshold = self.config.get_int("RATE_LIMIT_IP_BAN_THRESHOLD", 10)
        
        if attempts >= ban_threshold:
            self.add_banned_ip(ip)
        elif attempts >= suspicious_threshold:
            self.add_suspicious_ip(ip)
        
        print(f"[DEBUG] Added failed {action_type} attempt for IP {ip}, total: {attempts}")
    
    def check_rate_limit(self, ip: str, action_type: str, form_type: str = None) -> tuple[bool, int]:
        """
        Check if an action is rate limited for an IP address.
        
        Args:
            ip: The IP address to check
            action_type: The type of action (e.g., "login", "form_submission")
            form_type: The type of form (e.g., "plex", "audiobookshelf") - optional
            
        Returns:
            Tuple of (is_rate_limited, remaining_time_seconds)
        """
        if self.is_ip_whitelisted(ip):
            return False, 0
        
        if self.check_ip_banned(ip):
            return True, 3600  # 1 hour ban
        
        current_time = time.time()
        
        if action_type == "login":
            # Check if IP is currently locked out
            if ip in self._rate_limit_data['lockout_end_times']:
                remaining_time = max(0, self._rate_limit_data['lockout_end_times'][ip] - current_time)
                
                if remaining_time > 0:
                    print(f"[DEBUG] IP {ip} rate limited, {remaining_time}s remaining")
                    return True, remaining_time
                else:
                    # Lockout expired, clear it
                    del self._rate_limit_data['lockout_end_times'][ip]
                    print(f"[DEBUG] IP {ip} lockout expired")
            
            # Check if IP should be locked out based on recent attempts
            if ip in self._rate_limit_data['failed_attempts']:
                attempts = len(self._rate_limit_data['failed_attempts'][ip])
                max_attempts = self.config.get_int("RATE_LIMIT_MAX_LOGIN_ATTEMPTS", 5)
                
                if attempts >= max_attempts:
                    lockout_duration = self.config.get_int("RATE_LIMIT_LOGIN_LOCKOUT_DURATION", 3600)
                    self._rate_limit_data['lockout_end_times'][ip] = current_time + lockout_duration
                    print(f"[DEBUG] IP {ip} lockout started")
                    return True, lockout_duration
        
        elif action_type == "form_submission":
            # Check form submission rate limiting
            if form_type is None:
                return False, 0
                
            if ip not in self._rate_limit_data['form_submissions']:
                self._rate_limit_data['form_submissions'][ip] = {}
            
            if form_type not in self._rate_limit_data['form_submissions'][ip]:
                self._rate_limit_data['form_submissions'][ip][form_type] = []
            
            submissions = self._rate_limit_data['form_submissions'][ip][form_type]
            max_submissions = self.config.get_int("RATE_LIMIT_MAX_FORM_SUBMISSIONS", 1)
            
            # Count submissions in last hour
            recent_submissions = [t for t in submissions if t > current_time - 3600]
            
            if len(recent_submissions) >= max_submissions:
                # Calculate remaining time until next submission allowed
                oldest_submission = min(recent_submissions)
                next_allowed = oldest_submission + 3600  # 1 hour
                remaining_time = max(0, next_allowed - current_time)
                return True, remaining_time
        
        return False, 0
    
    def format_time_remaining(self, seconds: int) -> str:
        """
        Format remaining time in a human-readable format.
        
        Args:
            seconds: Number of seconds remaining
            
        Returns:
            Formatted time string
        """
        if seconds < 60:
            return f"{seconds} seconds"
        elif seconds < 3600:
            minutes = seconds // 60
            return f"{minutes} minutes"
        else:
            hours = seconds // 3600
            return f"{hours} hours"
    
    def log_security_event(self, event_type: str, ip: str, message: str) -> None:
        """
        Log a security event.
        
        Args:
            event_type: Type of security event
            ip: IP address involved
            message: Event message
        """
        print(f"[WARN] Security event - {event_type}: IP {ip}: {message}")
    
    def check_first_time_ip_access(self, ip: str) -> None:
        """
        Check if this is the first time an IP is accessing the system.
        This method can be used to log or track new IP addresses.
        
        Args:
            ip: The IP address to check
        """
        # For now, just log the access
        print(f"[DEBUG] First time access from IP {ip}")
    
    def check_first_time_login_success(self, ip: str) -> None:
        """
        Handle successful login for an IP address.
        
        Args:
            ip: The IP address that successfully logged in
        """
        # Reset login attempts on successful login
        if ip in self._rate_limit_data['failed_attempts']:
            del self._rate_limit_data['failed_attempts'][ip]
        
        if ip in self._rate_limit_data['lockout_end_times']:
            del self._rate_limit_data['lockout_end_times'][ip]
        
        print(f"[INFO] Successful login from IP {ip}, attempts reset")
    
    def add_form_submission(self, ip: str, form_type: str) -> None:
        """
        Add a form submission for an IP address.
        
        Args:
            ip: The IP address to add submission for
            form_type: The type of form (e.g., "plex", "audiobookshelf")
        """
        if self.is_ip_whitelisted(ip):
            return
        
        current_time = time.time()
        
        if ip not in self._rate_limit_data['form_submissions']:
            self._rate_limit_data['form_submissions'][ip] = {}
        
        if form_type not in self._rate_limit_data['form_submissions'][ip]:
            self._rate_limit_data['form_submissions'][ip][form_type] = []
        
        self._rate_limit_data['form_submissions'][ip][form_type].append(current_time)
        
        # Clean old submissions (older than 24 hours)
        cutoff_time = current_time - 86400
        self._rate_limit_data['form_submissions'][ip][form_type] = [
            t for t in self._rate_limit_data['form_submissions'][ip][form_type] 
            if t > cutoff_time
        ]
        
        print(f"[INFO] Form submission recorded for IP {ip}, type: {form_type}")
    
    def get_service_status(self) -> Dict[str, Any]:
        """
        Get the current status of the rate limit service.
        
        Returns:
            Dictionary containing service status information
        """
        return {
            'initialized': self.is_initialized(),
            'enabled': self.is_enabled(),
            'suspicious_ips_count': len(self._rate_limit_data['suspicious_ips']),
            'banned_ips_count': len(self._rate_limit_data['banned_ips']),
            'whitelisted_ips_count': len(self._rate_limit_data['whitelisted_ips']),
            'login_attempts_tracked': len(self._rate_limit_data['failed_attempts']),
            'form_submissions_tracked': len(self._rate_limit_data['form_submissions'])
        } 