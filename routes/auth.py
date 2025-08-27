"""
Authentication routes for Onboarderr application.

This module handles user authentication including login and logout functionality.
"""

from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify
from flask_wtf.csrf import CSRFProtect

from services.auth_service import AuthService
from services.rate_limit_service import RateLimitService
from services.notification_service import NotificationService
import os

def debug_log(message: str) -> None:
    """Log a debug message only if FLASK_DEBUG is enabled."""
    try:
        flask_debug = os.getenv("FLASK_DEBUG", "0") == "1"
        if flask_debug:
            print(f"[DEBUG] {message}")
    except Exception:
        pass

debug_log("Importing config in auth routes")
from config import get_config

# Create blueprint
auth_bp = Blueprint('auth', __name__)

def get_services():
    """Get service instances."""
    debug_log("Getting service instances")
    config = get_config()
    
    # Only initialize services if not already done
    if not hasattr(get_services, '_auth_service'):
        auth_service = AuthService(config)
        auth_service.initialize()
        get_services._auth_service = auth_service
    else:
        auth_service = get_services._auth_service
    
    if not hasattr(get_services, '_rate_limit_service'):
        rate_limit_service = RateLimitService(config)
        rate_limit_service.initialize()
        get_services._rate_limit_service = rate_limit_service
    else:
        rate_limit_service = get_services._rate_limit_service
    
    if not hasattr(get_services, '_notification_service'):
        notification_service = NotificationService(config)
        notification_service.initialize()
        get_services._notification_service = notification_service
    else:
        notification_service = get_services._notification_service
    
    debug_log("Service instances retrieved successfully")
    return auth_service, rate_limit_service, notification_service

def get_client_ip():
    """Get client IP address from request."""
    # Check for forwarded headers first (for proxy setups)
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        return forwarded_for.split(',')[0].strip()
    
    # Fall back to remote address
    return request.remote_addr

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Handle user login with rate limiting and authentication."""
    debug_log(f"Login route accessed - Method: {request.method}")
    
    auth_service, rate_limit_service, notification_service = get_services()
    config = get_config()
    
    # Check if setup is complete
    if not config.is_setup_complete():
        debug_log("Setup not complete, redirecting to setup")
        return redirect(url_for("setup"))
    
    # Get client IP for rate limiting
    client_ip = get_client_ip()
    
    # Check for first-time IP access
    rate_limit_service.check_first_time_ip_access(client_ip)
    
    if request.method == "POST":
        # Check rate limiting only for POST requests (actual login attempts)
        is_rate_limited, remaining_time = rate_limit_service.check_rate_limit(client_ip, "login")
        if is_rate_limited:
            time_remaining = rate_limit_service.format_time_remaining(remaining_time)
            rate_limit_service.log_security_event("rate_limited", client_ip, f"Login attempt rate limited, {time_remaining} remaining")
            return render_template("login.html", 
                error=f"Too many failed attempts. Please try again in {time_remaining}.",
                SERVER_NAME=config.get_server_name(),
                ACCENT_COLOR=config.get_accent_color()
            )
        
        entered_password = request.form.get("password")
        debug_log(f"Login attempt from IP: {client_ip}")
        debug_log(f"Entered password length: {len(entered_password) if entered_password else 0}")
        
        # Authenticate user
        auth_result = auth_service.authenticate_user(entered_password)
        debug_log(f"Authentication result: {auth_result}")
        
        if auth_result["success"]:
            # Create session
            session_data = auth_service.create_session(auth_result["user_type"])
            session.update(session_data)
            
            # Record successful login and check if it's first time
            rate_limit_service.check_first_time_login_success(client_ip)
            
            # Reset failed attempts on successful login
            rate_limit_service.clear_failed_attempts(client_ip)
            rate_limit_service.clear_lockout(client_ip)
            
            # Get intended URL from form data (sent by client-side JavaScript)
            intended_url_after_login = request.form.get("intended_url_after_login")
            
            if auth_result["user_type"] == "admin":
                redirect_url = intended_url_after_login if intended_url_after_login else url_for("services")
            else:
                redirect_url = intended_url_after_login if intended_url_after_login else url_for("onboarding.onboarding")
            
            # If redirecting to services with a hash fragment, ensure it's preserved
            if (intended_url_after_login and 
                intended_url_after_login.startswith(url_for("services")) and 
                "#" in intended_url_after_login):
                # Extract the hash fragment
                hash_fragment = intended_url_after_login.split("#", 1)[1]
                redirect_url = f"{url_for('services')}#{hash_fragment}"
            
            # Send notification for successful login
            notification_service.send_security_alert(
                "login_success",
                client_ip,
                f"Successful login by {auth_result['user_type']} user"
            )
            
            debug_log(f"Successful login for {auth_result['user_type']} user, redirecting to {redirect_url}")
            return redirect(redirect_url)
        else:
            # Record failed attempt
            rate_limit_service.add_failed_attempt(client_ip, "login")
            
            # Send notification for failed login
            notification_service.send_security_alert(
                "login_failed",
                client_ip,
                "Failed login attempt"
            )
            
            # Check if this is an AJAX request
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                debug_log(f"AJAX login failed, returning JSON error response")
                return jsonify({"success": False, "error": "Incorrect password"}), 401
            else:
                debug_log(f"Regular form login failed, returning template with error")
                return render_template("login.html", 
                    error="Incorrect password",
                    SERVER_NAME=config.get_server_name(),
                    ACCENT_COLOR=config.get_accent_color()
                )

    return render_template("login.html",
        SERVER_NAME=config.get_server_name(),
        ACCENT_COLOR=config.get_accent_color()
    )

@auth_bp.route("/logout")
def logout():
    """Clear session and redirect to login."""
    session.clear()
    return redirect(url_for("login"))

def register_auth_routes(app):
    """Register authentication routes with the Flask app."""
    # Import limiter from app to exempt login from default rate limiting
    from app import limiter
    
    # Exempt login from Flask-Limiter's default rate limiting since it has custom rate limiting
    login_exempt = limiter.exempt(login)
    
    # Register routes directly on the app to maintain the same endpoint names
    app.add_url_rule('/login', 'login', login_exempt, methods=['GET', 'POST'])
    app.add_url_rule('/logout', 'logout', logout) 