"""
Network utilities for Onboarderr application.

This module provides network-related functions for IP handling, client detection,
API calls, and network operations.
"""

import ipaddress
import requests
import time
from typing import Tuple, Optional, Dict, Any
from flask import request
from config import Config


def get_client_ip() -> str:
    """
    Get the client's IP address, handling proxies.
    
    Returns:
        str: Client IP address
    """
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


def is_valid_ip_range(ip_range: str) -> bool:
    """
    Validate IP range format (CIDR notation).
    
    Args:
        ip_range: IP range in CIDR notation (e.g., 192.168.1.0/24)
        
    Returns:
        bool: True if IP range is valid, False otherwise
    """
    if not ip_range:
        return False
    
    # Must contain a slash to be a range
    if '/' not in ip_range:
        return False
    
    try:
        ipaddress.ip_network(ip_range, strict=False)
        return True
    except ValueError:
        return False


def is_valid_single_ip(ip: str) -> bool:
    """
    Validate single IP address format.
    
    Args:
        ip: IP address to validate
        
    Returns:
        bool: True if IP is valid, False otherwise
    """
    if not ip:
        return False
    
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_ip_or_range(ip_or_range: str) -> bool:
    """
    Validate if string is a valid IP address or IP range.
    
    Args:
        ip_or_range: IP address or range to validate
        
    Returns:
        bool: True if valid IP or range, False otherwise
    """
    return is_valid_single_ip(ip_or_range) or is_valid_ip_range(ip_or_range)


def ip_in_range(client_ip: str, ip_range: str) -> bool:
    """
    Check if client IP is within the specified IP range.
    
    Args:
        client_ip: Client IP address
        ip_range: IP range in CIDR notation
        
    Returns:
        bool: True if client IP is in range, False otherwise
    """
    try:
        client_ip_obj = ipaddress.ip_address(client_ip)
        network = ipaddress.ip_network(ip_range, strict=False)
        return client_ip_obj in network
    except ValueError:
        return False


def safe_api_call(api_func, timeout: Optional[int] = None, 
                  max_retries: int = 3, operation_name: str = "api_call") -> Any:
    """
    Safely execute API calls with proper error handling and timeouts.
    
    Args:
        api_func: Function to execute
        timeout: Request timeout in seconds
        max_retries: Maximum number of retry attempts
        operation_name: Name of the operation for logging
        
    Returns:
        Any: Result of the API call
        
    Raises:
        requests.exceptions.RequestException: If API call fails
    """
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
        from utils.logging_utils import log_error
        log_error("api_timeout", f"API call timed out after {timeout}s", {"operation": operation_name})
        raise
    except requests.exceptions.ConnectionError:
        from utils.logging_utils import log_error
        log_error("api_connection", f"Failed to connect to API", {"operation": operation_name})
        raise
    except requests.exceptions.HTTPError as e:
        from utils.logging_utils import log_error
        log_error("api_http_error", f"HTTP error in API call: {e}", 
                 {"operation": operation_name, "status_code": e.response.status_code})
        raise
    except Exception as e:
        from utils.logging_utils import log_error
        log_error("api_unknown", f"Unexpected error in API call: {e}", {"operation": operation_name})
        raise


def retry_operation(operation, max_retries: int = 3, delay: float = 1.0, 
                   backoff_factor: float = 2.0, exceptions: Tuple = (Exception,), 
                   operation_name: str = "operation") -> Any:
    """
    Retry an operation with exponential backoff and proper error handling.
    
    Args:
        operation: Function to retry
        max_retries: Maximum number of retry attempts
        delay: Initial delay between retries
        backoff_factor: Multiplier for delay on each retry
        exceptions: Tuple of exceptions to catch and retry
        operation_name: Name of the operation for logging
        
    Returns:
        Any: Result of the operation
        
    Raises:
        Exception: Last exception if all retries fail
    """
    from utils.logging_utils import log_error
    
    last_exception = None
    
    for attempt in range(max_retries):
        try:
            return operation()
        except exceptions as e:
            last_exception = e
            if attempt < max_retries - 1:
                sleep_time = delay * (backoff_factor ** attempt)
                log_error("retry_operation", 
                         f"{operation_name} attempt {attempt + 1} failed, retrying in {sleep_time}s", 
                         {"attempt": attempt + 1, "max_retries": max_retries, "operation": operation_name}, e)
                time.sleep(sleep_time)
            else:
                log_error("retry_operation", f"All {max_retries} attempts failed for {operation_name}", 
                         {"attempts": max_retries, "operation": operation_name}, e)
                raise last_exception
    
    raise last_exception


def safe_operation(operation, error_message: str, error_type: str = "general", 
                  default_return: Any = None, log_error_flag: bool = True) -> Any:
    """
    Safely execute an operation with comprehensive error handling.
    
    Args:
        operation: Function to execute
        error_message: Error message for logging
        error_type: Type of error for categorization
        default_return: Default value to return on error
        log_error_flag: Whether to log errors
        
    Returns:
        Any: Result of operation or default_return on error
    """
    try:
        return operation()
    except Exception as e:
        if log_error_flag:
            from utils.logging_utils import log_error
            log_error(error_type, error_message, {}, e)
        if default_return is not None:
            return default_return
        raise


def get_app_url() -> str:
    """
    Determine the correct URL to open in browser.
    
    Returns:
        str: Application URL
    """
    import os
    
    # Get port from environment variable
    port = int(os.getenv('APP_PORT', 10000))
    
    # Check if we're in Docker
    if is_running_in_docker():
        # In Docker, we need to determine the external URL
        # This could be localhost if port is mapped, or a different host
        # For now, we'll use localhost as the most common case
        return f"http://localhost:{port}"
    else:
        # Native installation
        return f"http://localhost:{port}"


def is_running_in_docker() -> bool:
    """
    Check if the application is running in a Docker container.
    
    Returns:
        bool: True if running in Docker, False otherwise
    """
    try:
        with open('/proc/1/cgroup', 'r') as f:
            return any('docker' in line for line in f)
    except (FileNotFoundError, PermissionError):
        # Check for Docker environment variables
        return any(var in os.environ for var in ['DOCKER_CONTAINER', 'KUBERNETES_SERVICE_HOST'])


def check_network_connectivity(url: str, timeout: int = 10) -> Tuple[bool, str]:
    """
    Check network connectivity to a URL.
    
    Args:
        url: URL to check connectivity to
        timeout: Timeout in seconds
        
    Returns:
        Tuple[bool, str]: (success, message)
    """
    try:
        response = requests.get(url, timeout=timeout)
        if response.status_code == 200:
            return True, "Connection successful"
        else:
            return False, f"HTTP {response.status_code}"
    except requests.exceptions.Timeout:
        return False, "Connection timed out"
    except requests.exceptions.ConnectionError:
        return False, "Connection failed"
    except Exception as e:
        return False, f"Error: {str(e)}"


def get_request_headers() -> Dict[str, str]:
    """
    Get common request headers for API calls.
    
    Returns:
        Dict[str, str]: Dictionary of headers
    """
    return {
        'User-Agent': 'Onboarderr/1.0',
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }


def open_browser_delayed():
    """Open browser after a delay to ensure server is running"""
    import time
    import webbrowser
    
    time.sleep(2)  # Wait for Flask to start
    try:
        url = get_app_url()
        print(f"\n[INFO] Opening browser to: {url}")
        webbrowser.open(url)
    except Exception as e:
        print(f"[WARN] Failed to open browser: {e}")
        print(f"[INFO] Please manually open: {get_app_url()}")


def get_abs_headers() -> Dict[str, str]:
    """
    Get headers for ABS API requests.
    
    Returns:
        Dict[str, str]: Headers dictionary with authorization if token is available
    """
    import os
    from utils.logging_utils import log_debug, log_warning
    
    headers = {}
    abs_token = os.getenv("AUDIOBOOKSHELF_TOKEN")
    if abs_token:
        headers["Authorization"] = f"Bearer {abs_token}"
        log_debug("network_utils", "Using ABS token for authentication")
    else:
        log_warning("network_utils", "No ABS token provided, trying without authentication")
    return headers


def format_time_remaining(seconds: int) -> str:
    """
    Format remaining time in a human-readable format.
    
    Args:
        seconds: Number of seconds remaining
        
    Returns:
        str: Formatted time string
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