"""
Validation utilities for Onboarderr application.

This module provides comprehensive validation functions for URLs, tokens, emails,
API connections, and other input validation needs.
"""

import re
import requests
from typing import Tuple, Optional
from config import Config
import os


def validate_url(url: str, name: str = "URL") -> bool:
    """
    Validate URL format.
    
    Args:
        url: The URL to validate
        name: Name of the URL for error messages
        
    Returns:
        bool: True if URL is valid, False otherwise
    """
    if not url:
        return False
    
    try:
        if not url.startswith(('http://', 'https://')):
            url = f"http://{url}"
        
        # Parse the URL
        if '://' not in url:
            return False
        
        protocol, rest = url.split('://', 1)
        if not rest:
            return False
        
        # Check for hostname (allow localhost, IP addresses, and domain names)
        if '/' in rest:
            hostname = rest.split('/', 1)[0]
        else:
            hostname = rest
        
        # Handle port numbers
        if ':' in hostname:
            hostname = hostname.split(':', 1)[0]
        
        # Allow localhost, IP addresses, and domain names with dots
        if hostname == 'localhost' or hostname == '127.0.0.1':
            return True
        
        # Check if it's a valid IP address
        try:
            import ipaddress
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            pass
        
        # Check if it's a domain name (should have at least one dot)
        if '.' in hostname:
            return True
        
        return False
    except Exception:
        return False


def validate_token(token: str, name: str = "Token") -> bool:
    """
    Validate token format with API-specific checks.
    
    Args:
        token: The token to validate
        name: Name of the token for API-specific validation
        
    Returns:
        bool: True if token is valid, False otherwise
    """
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


def validate_api_connection(api_type: str, url: str, token: str) -> Tuple[bool, str]:
    """
    Validate API connection by making a test call.
    
    Args:
        api_type: Type of API (PLEX, ABS, AUDIOBOOKSHELF)
        url: API base URL
        token: API authentication token
        
    Returns:
        Tuple[bool, str]: (success, message)
    """
    config = Config()
    
    if not validate_token(token, api_type):
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
        
        timeout = config.get_int(f"{api_type.upper()}_API_TIMEOUT", 10)
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


def validate_email(email: str) -> bool:
    """
    Basic email validation.
    
    Args:
        email: Email address to validate
        
    Returns:
        bool: True if email is valid, False otherwise
    """
    if not email:
        return False
    
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_ip_address(ip: str) -> bool:
    """
    Validate IP address format.
    
    Args:
        ip: IP address to validate
        
    Returns:
        bool: True if IP is valid, False otherwise
    """
    if not ip:
        return False
    
    try:
        import ipaddress
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_ip_range(ip_range: str) -> bool:
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
        import ipaddress
        ipaddress.ip_network(ip_range, strict=False)
        return True
    except ValueError:
        return False


def validate_port(port: str) -> bool:
    """
    Validate port number.
    
    Args:
        port: Port number as string
        
    Returns:
        bool: True if port is valid, False otherwise
    """
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False


def validate_filename(filename: str) -> bool:
    """
    Validate filename for security.
    
    Args:
        filename: Filename to validate
        
    Returns:
        bool: True if filename is safe, False otherwise
    """
    if not filename:
        return False
    
    # Check for dangerous characters
    dangerous_chars = ['<', '>', ':', '"', '|', '?', '*', '\\', '/']
    if any(char in filename for char in dangerous_chars):
        return False
    
    # Check for reserved names (Windows)
    reserved_names = ['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 
                     'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 
                     'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9']
    
    name_without_ext = filename.split('.')[0].upper()
    if name_without_ext in reserved_names:
        return False
    
    return True


def validate_file_extension(filename: str, allowed_extensions: set) -> bool:
    """
    Validate file extension.
    
    Args:
        filename: Filename to check
        allowed_extensions: Set of allowed extensions (e.g., {'.png', '.jpg'})
        
    Returns:
        bool: True if extension is allowed, False otherwise
    """
    if not filename:
        return False
    
    file_ext = os.path.splitext(filename)[1].lower()
    return file_ext in allowed_extensions 