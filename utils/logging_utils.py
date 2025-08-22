"""
Logging utilities for Onboarderr application.

This module provides centralized logging functions for error, debug, info, and warning messages.
"""

import time
import traceback
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from threading import Lock
from config import Config


# Global error log storage
error_log = []
error_lock = Lock()


def log_error(error_type: str, message: str, details: Optional[Dict[str, Any]] = None, 
              exception: Optional[Exception] = None) -> None:
    """
    Centralized error logging with recovery information.
    
    Args:
        error_type: Type of error for categorization
        message: Error message
        details: Additional error details
        exception: Exception object if available
    """
    error_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "type": error_type,
        "message": message,
        "details": details or {},
        "exception": str(exception) if exception else None,
        "traceback": None
    }
    
    if exception:
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
        if is_debug_mode():
            print(f"[ERROR] {error_type}: {message}")
            if exception:
                print(f"[ERROR] Exception: {exception}")
    except NameError:
        pass  # debug_mode not defined yet


def log_debug(debug_type: str, message: str, details: Optional[Dict[str, Any]] = None) -> None:
    """
    Centralized debug logging.
    
    Args:
        debug_type: Type of debug message for categorization
        message: Debug message
        details: Additional debug details
    """
    # Use the helper function to safely check debug mode status
    if is_debug_mode():
        print(f"[DEBUG] {debug_type}: {message}")
        if details:
            print(f"[DEBUG] {debug_type} details: {details}")


def log_info(info_type: str, message: str, details: Optional[Dict[str, Any]] = None) -> None:
    """
    Centralized info logging.
    
    Args:
        info_type: Type of info message for categorization
        message: Info message
        details: Additional info details
    """
    # Always print info messages
    print(f"[INFO] {info_type}: {message}")
    
    # Print additional details if debug mode is enabled
    if is_debug_mode() and details:
        print(f"[INFO] {info_type} details: {details}")


def log_warning(warning_type: str, message: str, details: Optional[Dict[str, Any]] = None) -> None:
    """
    Centralized warning logging.
    
    Args:
        warning_type: Type of warning message for categorization
        message: Warning message
        details: Additional warning details
    """
    # Always print warning messages
    print(f"[WARN] {warning_type}: {message}")
    
    # Print additional details if debug mode is enabled
    if is_debug_mode() and details:
        print(f"[WARN] {warning_type} details: {details}")


def log_security_event(event_type: str, ip: str, details: Optional[Dict[str, Any]] = None) -> None:
    """
    Log security-related events.
    
    Args:
        event_type: Type of security event
        ip: IP address associated with the event
        details: Additional security event details
    """
    security_details = {
        "ip": ip,
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "user_agent": details.get("user_agent", "Unknown") if details else "Unknown",
        "event_type": event_type
    }
    
    if details:
        security_details.update(details)
    
    log_warning("security", f"Security event: {event_type} from IP {ip}", security_details)


def is_debug_mode() -> bool:
    """
    Helper function to safely check debug mode status.
    
    Returns:
        bool: True if debug mode is enabled, False otherwise
    """
    try:
        config = Config()
        return config.get_bool("FLASK_DEBUG", False)
    except Exception:
        return False


def get_error_log() -> list:
    """
    Get the current error log.
    
    Returns:
        list: List of error log entries
    """
    with error_lock:
        return error_log.copy()


def clear_error_log() -> None:
    """
    Clear the error log.
    """
    with error_lock:
        error_log.clear()


def get_error_log_summary() -> Dict[str, Any]:
    """
    Get a summary of the error log.
    
    Returns:
        Dict[str, Any]: Error log summary
    """
    with error_lock:
        if not error_log:
            return {
                "total_errors": 0,
                "error_types": {},
                "recent_errors": []
            }
        
        # Count error types
        error_types = {}
        for entry in error_log:
            error_type = entry.get("type", "unknown")
            error_types[error_type] = error_types.get(error_type, 0) + 1
        
        # Get recent errors (last 10)
        recent_errors = error_log[-10:] if len(error_log) > 10 else error_log
        
        return {
            "total_errors": len(error_log),
            "error_types": error_types,
            "recent_errors": recent_errors
        }


def log_api_call(api_type: str, endpoint: str, status_code: int, 
                response_time: float, details: Optional[Dict[str, Any]] = None) -> None:
    """
    Log API call information.
    
    Args:
        api_type: Type of API (PLEX, ABS, etc.)
        endpoint: API endpoint called
        status_code: HTTP status code
        response_time: Response time in seconds
        details: Additional API call details
    """
    api_details = {
        "api_type": api_type,
        "endpoint": endpoint,
        "status_code": status_code,
        "response_time": response_time,
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z"
    }
    
    if details:
        api_details.update(details)
    
    if status_code >= 400:
        log_error("api_call", f"API call failed: {api_type} {endpoint} - {status_code}", api_details)
    elif status_code >= 300:
        log_warning("api_call", f"API call redirect: {api_type} {endpoint} - {status_code}", api_details)
    else:
        log_info("api_call", f"API call successful: {api_type} {endpoint} - {status_code} ({response_time:.2f}s)", api_details)


def log_user_action(user_ip: str, action: str, details: Optional[Dict[str, Any]] = None) -> None:
    """
    Log user actions for audit purposes.
    
    Args:
        user_ip: User's IP address
        action: Action performed
        details: Additional action details
    """
    action_details = {
        "user_ip": user_ip,
        "action": action,
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z"
    }
    
    if details:
        action_details.update(details)
    
    log_info("user_action", f"User action: {action} from IP {user_ip}", action_details)


def log_system_event(event_type: str, message: str, details: Optional[Dict[str, Any]] = None) -> None:
    """
    Log system-level events.
    
    Args:
        event_type: Type of system event
        message: Event message
        details: Additional event details
    """
    event_details = {
        "event_type": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z"
    }
    
    if details:
        event_details.update(details)
    
    log_info("system", f"System event: {event_type} - {message}", event_details)


def format_log_entry(entry: Dict[str, Any]) -> str:
    """
    Format a log entry for display.
    
    Args:
        entry: Log entry dictionary
        
    Returns:
        str: Formatted log entry string
    """
    timestamp = entry.get("timestamp", "Unknown")
    log_type = entry.get("type", "unknown")
    message = entry.get("message", "No message")
    
    formatted = f"[{timestamp}] {log_type.upper()}: {message}"
    
    if entry.get("details"):
        formatted += f" | Details: {entry['details']}"
    
    if entry.get("exception"):
        formatted += f" | Exception: {entry['exception']}"
    
    return formatted


def export_error_log(format: str = "json") -> str:
    """
    Export error log in specified format.
    
    Args:
        format: Export format ("json" or "text")
        
    Returns:
        str: Exported error log
    """
    with error_lock:
        if format.lower() == "json":
            import json
            return json.dumps(error_log, indent=2)
        elif format.lower() == "text":
            return "\n".join(format_log_entry(entry) for entry in error_log)
        else:
            raise ValueError(f"Unsupported format: {format}") 