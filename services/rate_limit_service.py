"""
Rate Limit Service

This module provides the RateLimitService class for handling all rate limiting logic,
IP management, and security-related business logic.
"""

import time
import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from threading import Lock

from utils.network_utils import is_valid_ip_or_range, ip_in_range
from utils.data_utils import load_json_file, save_json_file
from utils.env_utils import safe_set_key


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
            'whitelisted_ips': set(),
            'first_failed_attempt_ips': set(),
            'lockout_notified_ips': set()
        }
        self._initialized = False
        self._lock = Lock()
        
        # API rate limiting state
        self._api_request_timestamps = {
            'plex': [],
            'abs': [],
            'discord': [],
            'general': []
        }
        self._api_rate_limit_lock = Lock()
        
        # API rate limiting configuration
        self._api_rate_limits = {
            'plex': {'requests_per_second': 10, 'burst_limit': 20},
            'abs': {'requests_per_second': 5, 'burst_limit': 10},
            'discord': {'requests_per_second': 2, 'burst_limit': 5},
            'general': {'requests_per_second': 20, 'burst_limit': 50}
        }
    
    def initialize(self) -> None:
        """Initialize the rate limit service with configuration."""
        self._initialized = True
        
        # Load IP lists from environment
        self.load_ip_lists_from_env()
        
        print(f"[INFO] Rate limit service initialized successfully")
    
    def load_ip_lists_from_env(self) -> None:
        """Load IP lists from environment variables"""
        # Load whitelisted IPs
        whitelisted_str = self.config.get("IP_WHITELIST", "")
        if whitelisted_str:
            whitelisted_ips = [ip.strip() for ip in whitelisted_str.split(",") if ip.strip()]
            self._rate_limit_data['whitelisted_ips'].update(whitelisted_ips)
            print(f"[INFO] Loaded {len(whitelisted_ips)} whitelisted IPs from environment")
        
        # Load blacklisted IPs
        blacklisted_str = self.config.get("IP_BLACKLIST", "")
        if blacklisted_str:
            blacklisted_ips = [ip.strip() for ip in blacklisted_str.split(",") if ip.strip()]
            self._rate_limit_data['banned_ips'].update(blacklisted_ips)
            print(f"[INFO] Loaded {len(blacklisted_ips)} blacklisted IPs from environment")
    
    def save_ip_lists_to_env(self) -> None:
        """Save IP lists to environment variables"""
        # Save whitelisted IPs
        whitelisted_str = ",".join(list(self._rate_limit_data['whitelisted_ips']))
        safe_set_key('.env', "IP_WHITELIST", whitelisted_str)
        
        # Save blacklisted IPs
        blacklisted_str = ",".join(list(self._rate_limit_data['banned_ips']))
        safe_set_key('.env', "IP_BLACKLIST", blacklisted_str)
        
        print(f"[INFO] Saved IP lists to environment")
    
    def get_ip_lists(self) -> Dict[str, List[str]]:
        """
        Get current IP whitelist and blacklist.
        
        Returns:
            Dictionary with 'whitelisted' and 'banned' IP lists
        """
        # Reload IP lists from environment variables to ensure we have the latest data
        self.load_ip_lists_from_env()
        
        return {
            'whitelisted': list(self._rate_limit_data['whitelisted_ips']),
            'banned': list(self._rate_limit_data['banned_ips'])
        }
    
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
    
    def is_ip_whitelisted(self, ip: str) -> bool:
        """
        Check if an IP address is whitelisted (supports both single IPs and ranges).
        
        Args:
            ip: The IP address to check
            
        Returns:
            True if the IP is whitelisted, False otherwise
        """
        # First check for exact matches
        if ip in self._rate_limit_data['whitelisted_ips']:
            return True
        
        # Then check if IP is within any whitelisted ranges
        for whitelisted_item in self._rate_limit_data['whitelisted_ips']:
            if '/' in whitelisted_item:  # This is an IP range
                if ip_in_range(ip, whitelisted_item):
                    return True
        
        return False
    
    def is_ip_banned(self, ip: str) -> bool:
        """
        Check if an IP address is banned (supports both single IPs and ranges).
        
        Args:
            ip: The IP address to check
            
        Returns:
            True if the IP is banned, False otherwise
        """
        # First check for exact matches
        if ip in self._rate_limit_data['banned_ips']:
            return True
        
        # Then check if IP is within any banned ranges
        for banned_item in self._rate_limit_data['banned_ips']:
            if '/' in banned_item:  # This is an IP range
                if ip_in_range(ip, banned_item):
                    return True
        
        return False
    
    def check_ip_suspicious(self, ip: str) -> bool:
        """
        Check if an IP address is marked as suspicious.
        
        Args:
            ip: The IP address to check
            
        Returns:
            True if the IP is suspicious, False otherwise
        """
        return ip in self._rate_limit_data['suspicious_ips']
    
    def add_ip_to_whitelist(self, ip_or_range: str) -> None:
        """
        Add IP or IP range to whitelist.
        
        Args:
            ip_or_range: IP address or range to add
        """
        if not is_valid_ip_or_range(ip_or_range):
            raise ValueError(f"Invalid IP or IP range format: {ip_or_range}")
        
        self._rate_limit_data['whitelisted_ips'].add(ip_or_range)
        # Remove from banned list if present
        if ip_or_range in self._rate_limit_data['banned_ips']:
            self._rate_limit_data['banned_ips'].remove(ip_or_range)
        # Persist to .env file
        self.save_ip_lists_to_env()
        self.log_security_event("ip_whitelisted", ip_or_range, "IP/IP range added to whitelist")
    
    def remove_ip_from_whitelist(self, ip_or_range: str) -> None:
        """
        Remove IP or IP range from whitelist.
        
        Args:
            ip_or_range: IP address or range to remove
        """
        if ip_or_range in self._rate_limit_data['whitelisted_ips']:
            self._rate_limit_data['whitelisted_ips'].remove(ip_or_range)
            # Persist to .env file
            self.save_ip_lists_to_env()
            self.log_security_event("ip_whitelist_removed", ip_or_range, "IP/IP range removed from whitelist")
    
    def add_ip_to_blacklist(self, ip_or_range: str) -> None:
        """
        Add IP or IP range to blacklist (banned).
        
        Args:
            ip_or_range: IP address or range to ban
        """
        if not is_valid_ip_or_range(ip_or_range):
            raise ValueError(f"Invalid IP or IP range format: {ip_or_range}")
        
        self._rate_limit_data['banned_ips'].add(ip_or_range)
        # Remove from whitelist if present
        if ip_or_range in self._rate_limit_data['whitelisted_ips']:
            self._rate_limit_data['whitelisted_ips'].remove(ip_or_range)
        # Persist to .env file
        self.save_ip_lists_to_env()
        self.log_security_event("ip_banned", ip_or_range, "IP/IP range added to blacklist")
    
    def remove_ip_from_blacklist(self, ip_or_range: str) -> None:
        """
        Remove IP or IP range from blacklist.
        
        Args:
            ip_or_range: IP address or range to remove from blacklist
        """
        if ip_or_range in self._rate_limit_data['banned_ips']:
            self._rate_limit_data['banned_ips'].remove(ip_or_range)
            # Persist to .env file
            self.save_ip_lists_to_env()
            self.log_security_event("ip_blacklist_removed", ip_or_range, "IP/IP range removed from blacklist")
    
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
    
    def check_first_time_ip_access(self, ip: str) -> bool:
        """
        Check if this is the first time an IP has accessed the site and notify if so.
        
        Args:
            ip: The IP address to check
            
        Returns:
            True if this is the first time access, False otherwise
        """
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
            self.log_security_event("first_access", ip, "IP accessed the site for the first time")
            return True
            
        except Exception as e:
            print(f"Error checking first time IP access: {e}")
            # If there's an error reading the log, fall back to logging the event
            self.log_security_event("first_access", ip, "IP accessed the site for the first time")
            return True
    
    def check_first_time_login_success(self, ip: str) -> bool:
        """
        Check if this is the first time an IP has successfully logged in and notify if so.
        
        Args:
            ip: The IP address to check
            
        Returns:
            True if this is the first time successful login, False otherwise
        """
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
            self.log_security_event("login_success", ip, "IP successfully logged in for the first time")
            return True
            
        except Exception as e:
            print(f"Error checking first time login success: {e}")
            # If there's an error reading the log, fall back to logging the event
            self.log_security_event("login_success", ip, "IP successfully logged in for the first time")
            return True
    
    def record_failed_attempt(self, ip: str, current_time: float) -> None:
        """Record a single failed attempt"""
        if ip not in self._rate_limit_data['failed_attempts']:
            self._rate_limit_data['failed_attempts'][ip] = []
        self._rate_limit_data['failed_attempts'][ip].append(current_time)
    
    def cleanup_old_attempts(self, ip: str, cutoff_time: float) -> None:
        """Remove attempts older than cutoff time"""
        if ip in self._rate_limit_data['failed_attempts']:
            self._rate_limit_data['failed_attempts'][ip] = [
                t for t in self._rate_limit_data['failed_attempts'][ip] 
                if t > cutoff_time
            ]
    
    def check_threshold_violations(self, ip: str, failed_count: int) -> Optional[str]:
        """Check if IP violates suspicious or ban thresholds"""
        ban_threshold = self.config.get_int("RATE_LIMIT_IP_BAN_THRESHOLD", 50)
        suspicious_threshold = self.config.get_int("RATE_LIMIT_IP_SUSPICIOUS_THRESHOLD", 20)
        
        if failed_count >= ban_threshold:
            self._rate_limit_data['banned_ips'].add(ip)
            self.log_security_event("ip_banned", ip, f"IP banned after {failed_count} failed attempts")
            return 'banned'
        elif failed_count >= suspicious_threshold:
            self.log_security_event("ip_suspicious", ip, f"IP marked as suspicious after {failed_count} failed attempts")
            return 'suspicious'
        return None
    
    def should_lockout_ip(self, ip: str, current_time: float) -> Optional[float]:
        """Check if IP should be locked out based on recent attempts"""
        max_attempts = self.config.get_int("RATE_LIMIT_MAX_LOGIN_ATTEMPTS", 5)
        
        if ip not in self._rate_limit_data['failed_attempts']:
            return None
        
        # Check attempts in last 15 minutes
        recent_attempts = [t for t in self._rate_limit_data['failed_attempts'][ip] if t > current_time - 900]
        if len(recent_attempts) >= max_attempts:
            return current_time
        
        # Check attempts in last hour (maintain lockout if enough attempts)
        hour_ago = current_time - 3600
        attempts_in_last_hour = [t for t in self._rate_limit_data['failed_attempts'][ip] if t > hour_ago]
        
        if len(attempts_in_last_hour) >= max_attempts:
            sorted_attempts = sorted(attempts_in_last_hour)
            return sorted_attempts[-max_attempts]
        
        return None
    
    def handle_security_notifications(self, ip: str, threshold_result: Optional[str], 
                                    lockout_start: Optional[float], recent_attempts: List[float]) -> None:
        """Handle security event notifications"""
        # Smart notification logic: Only notify on first failed attempt and when lockout occurs
        if ip not in self._rate_limit_data['first_failed_attempt_ips']:
            # This is the first failed attempt from this IP
            self._rate_limit_data['first_failed_attempt_ips'].add(ip)
            self.log_security_event("login_failed", ip, "First failed login attempt")
        elif lockout_start and ip not in self._rate_limit_data['lockout_notified_ips']:
            # IP just got locked out, notify about lockout
            self._rate_limit_data['lockout_notified_ips'].add(ip)
            self.log_security_event("login_lockout", ip, f"IP locked out after {len(recent_attempts)} failed attempts")
    
    def add_failed_attempt(self, ip: str, action_type: str = "login") -> None:
        """
        Add a failed attempt for an IP address.
        
        Args:
            ip: The IP address to add failed attempt for
            action_type: The type of action that failed
        """
        if self.is_ip_whitelisted(ip):
            return
        
        current_time = time.time()
        self.record_failed_attempt(ip, current_time)
        
        # Clean old attempts (older than 24 hours)
        self.cleanup_old_attempts(ip, current_time - 86400)
        
        # Check thresholds and ban if needed
        failed_count = len(self._rate_limit_data['failed_attempts'][ip])
        threshold_result = self.check_threshold_violations(ip, failed_count)
        
        # Check if IP should be locked out
        lockout_start = self.should_lockout_ip(ip, current_time)
        
        if lockout_start and ip not in self._rate_limit_data['lockout_end_times']:
            lockout_duration = self.config.get_int("RATE_LIMIT_LOGIN_LOCKOUT_DURATION", 3600)
            self._rate_limit_data['lockout_end_times'][ip] = lockout_start + lockout_duration
            print(f"[DEBUG] IP {ip} locked out until {self._rate_limit_data['lockout_end_times'][ip]}")
        
        # Handle notifications
        recent_attempts = [t for t in self._rate_limit_data['failed_attempts'][ip] if t > current_time - 900]
        self.handle_security_notifications(ip, threshold_result, lockout_start, recent_attempts)
        
        print(f"[DEBUG] Added failed {action_type} attempt for IP {ip}, total: {failed_count}")
    
    def check_rate_limit(self, ip: str, action_type: str, form_type: str = None) -> Tuple[bool, int]:
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
        
        if self.is_ip_banned(ip):
            return True, 3600  # 1 hour ban
        
        # Clean up expired lockouts periodically
        self.cleanup_expired_lockouts()
        
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
            lockout_start = self.should_lockout_ip(ip, current_time)
            if lockout_start and ip not in self._rate_limit_data['lockout_end_times']:
                lockout_duration = self.config.get_int("RATE_LIMIT_LOGIN_LOCKOUT_DURATION", 3600)
                self._rate_limit_data['lockout_end_times'][ip] = lockout_start + lockout_duration
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
    
    def log_security_event(self, event_type: str, ip: str, details: str) -> None:
        """
        Log security events with file persistence and Discord notifications.
        
        Args:
            event_type: Type of security event
            ip: IP address involved
            details: Event details
        """
        if not self.config.get_bool("ENABLE_AUDIT_LOGGING", True):
            return
        
        from flask import request
        
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "event_type": event_type,
            "ip_address": ip,
            "user_agent": request.headers.get('User-Agent', '') if request else '',
            "details": details
        }
        
        try:
            # Load existing logs
            log_file = "security_log.json"
            logs = load_json_file(log_file, [])
            
            # Add new log entry
            logs.append(log_entry)
            
            # Keep only last 90 days of logs
            retention_days = self.config.get_int("AUDIT_LOG_RETENTION_DAYS", 90)
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
            
            # Send Discord notification for security events
            self._send_security_discord_notification(event_type, ip, details)
                
        except Exception as e:
            print(f"Error logging security event: {e}")
    
    def _send_security_discord_notification(self, event_type: str, ip: str, details: str) -> None:
        """Send security event notification to Discord"""
        try:
            from services.notification_service import NotificationService
            notification_service = NotificationService(self.config)
            notification_service.initialize()
            notification_service.send_security_alert(event_type, ip, details)
        except Exception as e:
            print(f"Failed to send Discord notification: {e}")
    
    def format_time_remaining(self, seconds: int) -> str:
        """
        Format remaining time in a human-readable format.
        
        Args:
            seconds: Number of seconds remaining
            
        Returns:
            Formatted time string
        """
        if seconds < 60:
            return f"{int(seconds)} seconds"
        elif seconds < 3600:
            minutes = int(seconds // 60)
            return f"{minutes} minute{'s' if minutes != 1 else ''}"
        else:
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            return f"{hours} hour{'s' if hours != 1 else ''} and {minutes} minute{'s' if minutes != 1 else ''}"
    
    def cleanup_expired_data(self, current_time: float) -> None:
        """
        Clean up expired rate limit data.
        
        Args:
            current_time: Current timestamp
        """
        with self._lock:
            # Clean up failed attempts older than 24 hours
            cutoff_time = current_time - 86400
            for ip in list(self._rate_limit_data['failed_attempts'].keys()):
                self._rate_limit_data['failed_attempts'][ip] = [
                    t for t in self._rate_limit_data['failed_attempts'][ip] 
                    if t > cutoff_time
                ]
                if not self._rate_limit_data['failed_attempts'][ip]:
                    del self._rate_limit_data['failed_attempts'][ip]
            
            # Clean up expired lockouts
            expired_ips = [
                ip for ip, end_time in self._rate_limit_data['lockout_end_times'].items()
                if current_time >= end_time
            ]
            for ip in expired_ips:
                del self._rate_limit_data['lockout_end_times'][ip]
            
            # Clean up form submissions older than 24 hours
            for ip in list(self._rate_limit_data['form_submissions'].keys()):
                for form_type in list(self._rate_limit_data['form_submissions'][ip].keys()):
                    self._rate_limit_data['form_submissions'][ip][form_type] = [
                        t for t in self._rate_limit_data['form_submissions'][ip][form_type]
                        if t > cutoff_time
                    ]
                    if not self._rate_limit_data['form_submissions'][ip][form_type]:
                        del self._rate_limit_data['form_submissions'][ip][form_type]
                if not self._rate_limit_data['form_submissions'][ip]:
                    del self._rate_limit_data['form_submissions'][ip]
    
    def clear_failed_attempts(self, ip: str) -> None:
        """
        Clear failed attempts for an IP address.
        
        Args:
            ip: The IP address to clear failed attempts for
        """
        with self._lock:
            if ip in self._rate_limit_data['failed_attempts']:
                del self._rate_limit_data['failed_attempts'][ip]
    
    def clear_lockout(self, ip: str) -> None:
        """
        Clear lockout for an IP address.
        
        Args:
            ip: The IP address to clear lockout for
        """
        with self._lock:
            if ip in self._rate_limit_data['lockout_end_times']:
                del self._rate_limit_data['lockout_end_times'][ip]

    def cleanup_expired_lockouts(self) -> None:
        """Clean up expired lockouts from memory using the rate limit manager"""
        current_time = time.time()
        
        try:
            self.cleanup_expired_data(current_time)
            print(f"[DEBUG] Cleaned up expired rate limit data")
        except Exception as e:
            print(f"Error in cleanup_expired_lockouts: {e}")
    
    def check_api_rate_limit(self, api_type: str) -> None:
        """
        Check and enforce API rate limits.
        
        Args:
            api_type: Type of API ('plex', 'abs', 'discord', 'general')
        """
        with self._api_rate_limit_lock:
            current_time = time.time()
            timestamps = self._api_request_timestamps[api_type]
            limits = self._api_rate_limits[api_type]
            
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
            'form_submissions_tracked': len(self._rate_limit_data['form_submissions']),
            'lockouts_active': len(self._rate_limit_data['lockout_end_times'])
        } 