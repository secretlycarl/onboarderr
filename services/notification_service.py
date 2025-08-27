"""
Notification Service

This module provides the NotificationService class for handling Discord notifications
and other alerting functionality.
"""

import time
from typing import Dict, Optional, Any
from config import Config


class NotificationService:
    """
    Service class for handling notifications and alerting.
    
    This class extracts all notification-related business logic from app.py
    and provides a clean interface for sending notifications.
    """
    
    def __init__(self, config_instance=None):
        """Initialize the notification service."""
        self.config = config_instance or Config()
        self._initialized = False
    
    def initialize(self) -> None:
        """Initialize the notification service."""
        self._initialized = True
        print(f"[INFO] Notification service initialized successfully")
    
    def cleanup(self) -> None:
        """Clean up the notification service."""
        self._initialized = False
        print(f"[DEBUG] Notification service cleaned up")
    
    def is_initialized(self) -> bool:
        """Check if the notification service is properly initialized."""
        return self._initialized
    
    def is_enabled(self) -> bool:
        """Check if notifications are enabled in configuration."""
        return self.config.get_bool("DISCORD_NOTIFICATIONS_ENABLED", False)
    
    def send_security_alert(self, alert_type: str, ip: str, message: str) -> bool:
        """
        Send a security alert notification.
        
        Args:
            alert_type: The type of security alert
            ip: The IP address involved
            message: The alert message
            
        Returns:
            True if notification was sent successfully, False otherwise
        """
        if not self.is_enabled():
            return False
        
        try:
            webhook_url = self.config.get("DISCORD_WEBHOOK_URL")
            if not webhook_url:
                print(f"[WARN] Discord webhook URL not configured")
                return False
            
            # Create Discord embed
            embed = {
                "title": f"Security Alert: {alert_type.title()}",
                "description": message,
                "color": self._get_alert_color(alert_type),
                "fields": [
                    {
                        "name": "IP Address",
                        "value": ip,
                        "inline": True
                    },
                    {
                        "name": "Timestamp",
                        "value": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                        "inline": True
                    }
                ],
                "footer": {
                    "text": "Onboarderr Security System"
                }
            }
            
            # Send Discord notification
            success = self._send_discord_notification(webhook_url, embed)
            
            if success:
                print(f"[INFO] Security alert sent: {alert_type} for IP {ip}")
            else:
                print(f"[ERROR] Failed to send security alert: {alert_type} for IP {ip}")
            
            return success
            
        except Exception as e:
            print(f"[ERROR] Failed to send security alert: {e}")
            return False
    
    def send_login_notification(self, user_type: str, ip: str, success: bool) -> bool:
        """
        Send a login notification.
        
        Args:
            user_type: The type of user (admin, user)
            ip: The IP address that logged in
            success: Whether the login was successful
            
        Returns:
            True if notification was sent successfully, False otherwise
        """
        if not self.is_enabled():
            return False
        
        alert_type = "login_success" if success else "login_failed"
        message = f"{'Successful' if success else 'Failed'} login attempt by {user_type} user"
        
        return self.send_security_alert(alert_type, ip, message)
    
    def send_rate_limit_notification(self, ip: str, action_type: str, attempts: int) -> bool:
        """
        Send a rate limit notification.
        
        Args:
            ip: The IP address that was rate limited
            action_type: The type of action that was rate limited
            attempts: The number of attempts made
            
        Returns:
            True if notification was sent successfully, False otherwise
        """
        if not self.is_enabled():
            return False
        
        message = f"Rate limit triggered for {action_type} after {attempts} attempts"
        
        return self.send_security_alert("rate_limited", ip, message)
    
    def send_suspicious_activity_notification(self, ip: str, activity_type: str, details: str) -> bool:
        """
        Send a suspicious activity notification.
        
        Args:
            ip: The IP address involved
            activity_type: The type of suspicious activity
            details: Additional details about the activity
            
        Returns:
            True if notification was sent successfully, False otherwise
        """
        if not self.is_enabled():
            return False
        
        message = f"Suspicious activity detected: {activity_type} - {details}"
        
        return self.send_security_alert("suspicious_activity", ip, message)
    
    def send_security_notification(self, event_type: str, ip: str, details: Optional[Dict[str, Any]] = None) -> bool:
        """
        Send a security notification for security events.
        
        Args:
            event_type: The type of security event
            ip: The IP address involved
            details: Additional details about the event
            
        Returns:
            True if notification was sent successfully, False otherwise
        """
        if not self.is_enabled():
            return False
        
        # Format the message based on event type
        if event_type == "login_attempt":
            message = f"Login attempt from IP {ip}"
        elif event_type == "rate_limit_exceeded":
            message = f"Rate limit exceeded from IP {ip}"
        elif event_type == "suspicious_activity":
            message = f"Suspicious activity detected from IP {ip}"
        elif event_type == "ip_banned":
            message = f"IP {ip} has been banned"
        elif event_type == "ip_whitelisted":
            message = f"IP {ip} has been whitelisted"
        elif event_type == "ip_blacklisted":
            message = f"IP {ip} has been blacklisted"
        else:
            message = f"Security event '{event_type}' from IP {ip}"
        
        # Add details if provided
        if details:
            detail_str = ", ".join([f"{k}: {v}" for k, v in details.items() if k != 'user_agent'])
            if detail_str:
                message += f" - {detail_str}"
        
        return self.send_security_alert(event_type, ip, message)
    
    def _get_alert_color(self, alert_type: str) -> int:
        """
        Get the color for a Discord embed based on alert type.
        
        Args:
            alert_type: The type of alert
            
        Returns:
            Discord color code
        """
        colors = {
            "login_success": 0x00ff00,  # Green
            "login_failed": 0xff0000,   # Red
            "rate_limited": 0xffa500,   # Orange
            "suspicious_activity": 0xff0000,  # Red
            "ip_banned": 0x800000,      # Dark Red
            "security_breach": 0xff0000,  # Red
            "default": 0x808080         # Gray
        }
        
        return colors.get(alert_type, colors["default"])
    
    def _send_discord_notification(self, webhook_url: str, embed: Dict[str, Any]) -> bool:
        """
        Send a Discord notification via webhook.
        
        Args:
            webhook_url: The Discord webhook URL
            embed: The Discord embed to send
            
        Returns:
            True if sent successfully, False otherwise
        """
        try:
            import requests
            
            # Apply API rate limiting
            from services.rate_limit_service import RateLimitService
            rate_limit_service = RateLimitService(self.config)
            rate_limit_service.initialize()
            rate_limit_service.check_api_rate_limit('discord')
            
            payload = {
                "embeds": [embed]
            }
            
            response = requests.post(
                webhook_url,
                json=payload,
                timeout=10
            )
            
            if response.status_code == 204:
                return True
            else:
                print(f"[ERROR] Discord webhook returned status {response.status_code}")
                return False
                
        except ImportError:
            print(f"[ERROR] Requests library not available for Discord notifications")
            return False
        except Exception as e:
            print(f"[ERROR] Failed to send Discord notification: {e}")
            return False
    
    def get_service_status(self) -> Dict[str, Any]:
        """
        Get the current status of the notification service.
        
        Returns:
            Dictionary containing service status information
        """
        return {
            'initialized': self.is_initialized(),
            'enabled': self.is_enabled(),
            'webhook_configured': bool(self.config.get("DISCORD_WEBHOOK_URL")),
            'notifications_sent': 0  # This would be tracked in a real implementation
        }
    
    def send_security_discord_notification(self, event_type: str, ip: str, details: str) -> None:
        """
        Send Discord notification for security events, respecting notification toggles.
        
        Args:
            event_type: Type of security event
            ip: IP address involved
            details: Event details
        """
        # Check if Discord notifications are enabled for this event type
        if event_type == "rate_limited" and not self.config.get_bool("DISCORD_NOTIFY_RATE_LIMITING", False):
            return
        if event_type in ["ip_whitelisted", "ip_whitelist_removed", "ip_banned", "ip_blacklist_removed"] and not self.config.get_bool("DISCORD_NOTIFY_IP_MANAGEMENT", False):
            return
        if event_type in ["login_success", "login_failed", "login_lockout"] and not self.config.get_bool("DISCORD_NOTIFY_LOGIN_ATTEMPTS", False):
            return
        if event_type == "form_rate_limited" and not self.config.get_bool("DISCORD_NOTIFY_FORM_RATE_LIMITING", False):
            return
        if event_type == "first_access" and not self.config.get_bool("DISCORD_NOTIFY_FIRST_ACCESS", False):
            return
        
        webhook_url = self.config.get("DISCORD_WEBHOOK")
        if not self.config.validate_url(webhook_url, "DISCORD_WEBHOOK"):
            return
        
        username = self.config.get("DISCORD_USERNAME", "Onboarderr Security")
        avatar_url = self.config.get("DISCORD_AVATAR", "")
        color = self.config.get("DISCORD_COLOR", "#ff0000")  # Red for security events
        
        # Get Onboarderr URL for admin link
        onboarderr_url = self.config.get("ONBOARDERR_URL", "")
        
        # Build description with optional admin link
        description = f"**Security Event:** {event_type.replace('_', ' ').title()}\n**IP:** {ip}\n**Details:** {details}"
        if onboarderr_url:
            # Add linked text to admin page
            admin_link = f"{onboarderr_url}/services"
            description += f"\n\n[🔧 **View Admin Panel**]({admin_link})"
        
        embed = {
            "title": "🚨 Security Alert",
            "description": description,
            "color": int(color.lstrip('#'), 16) if color.startswith('#') else 0,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
        
        payload = {
            "username": username,
            "embeds": [embed]
        }
        if avatar_url:
            payload["avatar_url"] = avatar_url
        
        try:
            # Apply rate limiting for Discord API
            from services.rate_limit_service import RateLimitService
            rate_limit_service = RateLimitService(self.config)
            rate_limit_service.initialize()
            rate_limit_service.check_api_rate_limit('discord')
            
            timeout = self.config.get_int("DISCORD_API_TIMEOUT", 5)
            import requests
            requests.post(webhook_url, json=payload, timeout=timeout)
        except Exception as e:
            if self.config.get_bool("FLASK_DEBUG", False):
                print(f"Failed to send security Discord notification: {e}") 