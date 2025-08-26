"""
Setup routes for Onboarderr

This module handles all setup-related routes including the main setup page
and setup completion page.
"""

from flask import render_template, request, redirect, url_for, jsonify
from typing import Dict, Any
import os
import time
from config.constants import (
    PLEX_TOKEN_KEY, PLEX_URL_KEY, LIBRARY_IDS_KEY
)

def debug_log(message: str) -> None:
    """Log a debug message only if FLASK_DEBUG is enabled."""
    try:
        flask_debug = os.getenv("FLASK_DEBUG", "0") == "1"
        if flask_debug:
            print(f"[DEBUG] {message}")
    except Exception:
        pass

debug_log("Importing setup service in setup routes")
from services.setup_service import SetupService
debug_log("Importing constants in setup routes")
from config.constants import *

# Initialize service
debug_log("Initializing setup service")
setup_service = SetupService()
debug_log("Setup service initialized")

def setup():
    """
    Handle setup page requests.
    
    GET: Display setup form
    POST: Process setup form submission
    """
    debug_log(f"Setup route accessed - Method: {request.method}")
    
    # If setup is complete, redirect to login
    if setup_service.is_setup_complete():
        debug_log(f"Setup already complete, redirecting to login")
        return redirect(url_for("login"))
    
    if request.method == "GET":
        # Display setup form
        debug_log(f"Displaying setup form")
        context = setup_service.get_setup_context()
        return render_template("setup.html", **context)
    
    elif request.method == "POST":
        # Process form submission
        debug_log(f"Processing setup form submission")
        return _handle_setup_form_submission()

def _handle_setup_form_submission():
    """Handle setup form submission."""
    debug_log(f"Handling setup form submission")
    
    # Check if this is a valid setup form submission
    form_data = request.form
    files = request.files
    
    debug_log(f"Form data keys: {list(form_data.keys())}")
    debug_log(f"Files: {list(files.keys())}")
    
    # Check if any setup-related fields are present
    setup_fields = [
        FORM_SERVER_NAME, FORM_PLEX_TOKEN, FORM_PLEX_URL, FORM_ABS_ENABLED,
        FORM_AUDIOBOOKS_ID, FORM_DISCORD_WEBHOOK, FORM_DISCORD_NOTIFY_PLEX,
        FORM_DISCORD_NOTIFY_ABS, FORM_ONBOARDERR_URL, FORM_LIBRARY_IDS,
        FORM_AUDIOBOOKSHELF_URL, FORM_ACCENT_COLOR, FORM_LOGO_FILE,
        FORM_WORDMARK_FILE, FORM_SITE_PASSWORD, FORM_ADMIN_PASSWORD, FORM_DRIVES
    ]
    
    has_setup_fields = any(form_data.get(field) for field in setup_fields)
    has_setup_files = any(files.get(field) for field in [FORM_LOGO_FILE, FORM_WORDMARK_FILE])
    
    debug_log(f"Has setup fields: {has_setup_fields}")
    debug_log(f"Has setup files: {has_setup_files}")
    
    if not has_setup_fields and not has_setup_files:
        # Not a setup form submission, show error
        debug_log(f"[WARN] Invalid setup form submission - no setup fields found")
        context = setup_service.get_setup_context()
        context["error_message"] = "Invalid form submission"
        return render_template("setup.html", **context)
    
    # Validate form data
    is_valid, error_message, error_context = setup_service.validate_setup_form(form_data)
    
    debug_log(f"Form validation result: {is_valid}")
    if not is_valid:
        debug_log(f"[DEBUG] Validation error: {error_message}")
        return render_template("setup.html", **error_context)
    
    # Process the form
    debug_log(f"Processing setup form")
    success, error_message = setup_service.process_setup_form(form_data, files)
    
    debug_log(f"Form processing result: {success}")
    if not success:
        debug_log(f"[DEBUG] Processing error: {error_message}")
        context = setup_service.get_setup_context()
        context["error_message"] = error_message
        return render_template("setup.html", **context)
    
    # Setup completed successfully, redirect to setup_complete
    debug_log(f"Setup completed successfully, redirecting to setup_complete")
    
    # For setup form submissions, we always change critical settings that require poster downloads
    changed_settings = [
        'plex_url', 'plex_token', 'library_ids', 'abs_enabled', 
        'audiobookshelf_url', 'audiobookshelf_token'
    ]
    
    return redirect(url_for("setup_complete", 
                           from_setup="true",
                           changed_settings=','.join(changed_settings)))

def setup_complete():
    """
    Handle setup completion page.
    
    This page is shown after successful setup and handles
    adaptive restart and poster downloads.
    """
    debug_log(f"Setup complete route accessed")
    
    # Security check: Verify this request is legitimate
    from_services = request.args.get('from_services', 'false').lower() == 'true'
    from_setup = request.args.get('from_setup', 'false').lower() == 'true'
    
    debug_log(f"From services: {from_services}")
    debug_log(f"From setup: {from_setup}")
    
    # If not from legitimate form submission, redirect to login
    if not from_services and not from_setup:
        # Log security event and redirect
        debug_log(f"[WARN] Unauthorized access to setup_complete, redirecting to login")
        # TODO: Implement security logging
        return redirect(url_for("login"))
    
    restart_delay = request.args.get('restart_delay', '15')
    changed_settings = request.args.get('changed_settings', '').split(',') if request.args.get('changed_settings') else []
    
    debug_log(f"Restart delay: {restart_delay}")
    debug_log(f"Changed settings: {changed_settings}")
    
    # Determine if this is an adaptive restart (poster downloads needed)
    is_adaptive = restart_delay == 'adaptive'
    
    # For setup form submissions, always use adaptive restart since they change critical settings
    if from_setup:
        is_adaptive = True
        restart_delay = 'adaptive'
    
    debug_log(f"Is adaptive restart: {is_adaptive}")
    
    # Show the setup_complete template
    return render_template("setup_complete.html", 
                         restart_delay=restart_delay,
                         is_adaptive=is_adaptive,
                         changed_settings=changed_settings)

def setup_poster_downloads():
    """
    Handle poster downloads for setup completion using smart logic.
    
    This endpoint is called by the setup_complete page to trigger
    poster downloads asynchronously.
    """
    try:
        debug_log(f"Starting setup poster downloads")
        
        # Get parameters
        changed_settings = request.json.get('changed_settings', []) if request.json else []
        debug_log(f"Changed settings: {changed_settings}")
        
        # Get Plex credentials
        from config import get_config
        config = get_config()
        plex_token = config.get(PLEX_TOKEN_KEY)
        plex_url = config.get(PLEX_URL_KEY)
        
        debug_log(f"Plex token exists: {bool(plex_token)}")
        debug_log(f"Plex URL: {plex_url}")
        
        if not plex_token or not plex_url:
            debug_log(f"[WARN] No Plex credentials available for poster downloads")
            return jsonify({"success": False, "error": "No Plex credentials available"})
        
        # Get selected libraries
        library_ids = config.get(LIBRARY_IDS_KEY, "")
        selected_ids = [i.strip() for i in library_ids.split(",") if i.strip()]
        
        debug_log(f"Selected library IDs: {selected_ids}")
        
        if not selected_ids:
            debug_log(f"[WARN] No libraries selected for poster downloads")
            return jsonify({"success": False, "error": "No libraries selected"})
        
        # Create library objects
        libraries = []
        
        # Get library names from LIBRARY_NAMES environment variable
        library_names_str = config.get("LIBRARY_NAMES", "")
        library_names = {}
        if library_names_str:
            names_list = library_names_str.split(",")
            for i, lib_id in enumerate(selected_ids):
                if i < len(names_list):
                    library_names[lib_id] = names_list[i].strip()
        
        for lib_id in selected_ids:
            # Get library name from parsed names, fallback to ID
            lib_name = library_names.get(lib_id, f"Library {lib_id}")
            libraries.append({
                "key": lib_id,
                "title": lib_name,
                "type": "show"  # Default type
            })
        
        # Import poster service (singleton)
        from services.poster_service import PosterService
        poster_service = PosterService()
        
        # Ensure worker is running
        poster_service.ensure_worker_running()
        
        # Initialize unified progress tracking
        poster_service.initialize_unified_progress()
        
        # Use smart logic to determine what needs downloading
        abs_enabled = config.get("ABS_ENABLED", "yes") == "yes"
        download_needs = poster_service.determine_download_needs(libraries, abs_enabled)
        
        debug_log(f"Smart download analysis - Plex: {download_needs['plex_needs_download']}, ABS: {download_needs['abs_needs_download']}")
        debug_log(f"Totals: {download_needs['total_new']} new, {download_needs['total_changed']} changed, {download_needs['total_removed']} removed")
        debug_log(f"Server offline: {download_needs['any_server_offline']}")
        
        # Handle server offline case
        if download_needs['any_server_offline']:
            poster_service.update_unified_status({
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
            poster_service.update_unified_status({
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
        
        # Start downloads based on smart analysis
        libraries_started = 0
        
        # Phase 1: Download Plex posters if needed
        if libraries and download_needs['plex_needs_download']:
            debug_log(f"Starting Plex poster downloads for {len(libraries)} libraries")
            
            # Update progress status
            poster_service.update_unified_status({
                'status': 'plex_downloading',
                'message': 'Downloading Plex posters...',
                'current': 0,
                'total': len(libraries),
                'last_update': time.time()
            })
            
            # Start downloads for each library that needs it
            for i, lib in enumerate(libraries):
                lib_result = download_needs['plex_results'][i]
                if lib_result['needs_download']:
                    success = poster_service.start_smart_poster_download(lib, lib_result)
                    if success:
                        libraries_started += 1
                        debug_log(f"Started smart poster downloads for library {lib['key']}")
                    else:
                        debug_log(f"Failed to start smart poster downloads for library {lib['key']}")
        
        # Phase 2: Queue ABS downloads if needed
        if abs_enabled and download_needs['abs_needs_download']:
            debug_log("Queuing ABS poster downloads")
            
            # Check if there are actual ABS poster files (not just completion file)
            audiobook_dir = os.path.join("static", "posters", "audiobooks")
            abs_poster_files = [f for f in os.listdir(audiobook_dir) if f.endswith('.webp')] if os.path.exists(audiobook_dir) else []
            
            # Force download if no actual poster files exist
            force_abs_download = len(abs_poster_files) == 0
            
            if force_abs_download:
                debug_log("No ABS poster files found, forcing download")
                # Remove completion file to force download
                completion_file = os.path.join(audiobook_dir, ".last_completion")
                if os.path.exists(completion_file):
                    os.remove(completion_file)
                    debug_log("Removed ABS completion file to force download")
            
            # Update progress status to show ABS downloads will start after Plex
            poster_service.update_unified_status({
                'status': 'plex_downloading',
                'message': 'Downloading Plex posters...',
                'last_update': time.time()
            })
            
            # Queue ABS poster downloads (force if no files exist)
            success = poster_service.start_abs_poster_download(force_download=force_abs_download)
            if success:
                debug_log("ABS poster downloads queued successfully")
            else:
                debug_log("Failed to queue ABS poster downloads")
        
        debug_log(f"[INFO] Smart poster downloads initiated for {libraries_started} libraries")
        
        # Return response with detailed status
        return jsonify({
            "success": True,
            "message": f"Smart poster downloads initiated for {libraries_started} libraries",
            "libraries_count": libraries_started,
            "changed_settings": changed_settings,
            "needs_plex": libraries_started > 0,
            "needs_abs": abs_enabled and download_needs['abs_needs_download'],
            "status": "initiated",
            "download_analysis": {
                "total_new": download_needs['total_new'],
                "total_changed": download_needs['total_changed'],
                "total_removed": download_needs['total_removed']
            }
        })
        
    except Exception as e:
        debug_log(f"[ERROR] Setup poster downloads failed: {e}")
        return jsonify({
            "success": False,
            "error": f"Failed to initiate poster downloads: {str(e)}"
        })

def setup_ip_management():
    """
    Handle IP management during setup (no authentication required).
    
    This endpoint is called by the setup page to manage IP whitelist/blacklist
    during the initial setup process.
    """
    try:
        debug_log(f"Setup IP management accessed")
        
        # Check if setup is complete - if so, this route shouldn't be accessible
        if setup_service.is_setup_complete():
            debug_log(f"Setup complete, IP management not allowed")
            return jsonify({"error": "Setup already complete"}), 403
        
        data = request.get_json()
        action = data.get('action')
        ip_address = data.get('ip_address')
        
        if not action or not ip_address:
            return jsonify({"error": "Action and IP address are required"}), 400
        
        # Validate IP address format
        from utils.network_utils import is_valid_ip_or_range
        if not is_valid_ip_or_range(ip_address):
            return jsonify({"error": f"Invalid IP address or IP range format: {ip_address}. Use single IP (e.g., 192.168.1.1) or IP range (e.g., 192.168.1.0/24)"}), 400
        
        # Initialize rate limiting service
        from services.rate_limit_service import RateLimitService
        from config import get_config
        config = get_config()
        rate_limit_service = RateLimitService(config)
        rate_limit_service.initialize()
        
        # Perform the requested action
        if action == "whitelist":
            # Add to whitelist
            rate_limit_service.add_ip_to_whitelist(ip_address)
            message = f"IP {ip_address} added to whitelist"
            
        elif action == "remove_whitelist":
            # Remove from whitelist
            rate_limit_service.remove_ip_from_whitelist(ip_address)
            message = f"IP {ip_address} removed from whitelist"
                
        elif action == "blacklist":
            # Add to blacklist
            rate_limit_service.add_ip_to_blacklist(ip_address)
            message = f"IP {ip_address} added to blacklist"
            
        elif action == "remove_blacklist":
            # Remove from blacklist
            rate_limit_service.remove_ip_from_blacklist(ip_address)
            message = f"IP {ip_address} removed from blacklist"
        else:
            return jsonify({"error": f"Invalid action: {action}"}), 400
        
        # Get updated IP lists
        ip_lists = rate_limit_service.get_ip_lists()
        
        debug_log(f"Setup IP management: {message}")
        
        return jsonify({
            "status": "success", 
            "message": message,
            "whitelist": ip_lists.get('whitelisted', []),
            "blacklist": ip_lists.get('banned', [])
        })
        
    except Exception as e:
        debug_log(f"[ERROR] Setup IP management failed: {e}")
        return jsonify({
            "success": False,
            "error": f"Failed to manage IP: {str(e)}"
        })

def setup_get_ip_lists():
    """
    Get IP whitelist and blacklist during setup (no authentication required).
    
    This endpoint is called by the setup page to display current IP lists.
    """
    try:
        debug_log(f"Setup get IP lists accessed")
        
        # Check if setup is complete - if so, this route shouldn't be accessible
        if setup_service.is_setup_complete():
            debug_log(f"Setup complete, IP lists not accessible")
            return jsonify({"error": "Setup already complete"}), 403
        
        # Use the rate limiting service to get IP lists
        from services.rate_limit_service import RateLimitService
        from config import get_config
        config = get_config()
        rate_limit_service = RateLimitService(config)
        rate_limit_service.initialize()
        
        ip_lists = rate_limit_service.get_ip_lists()
        
        return jsonify({
            "whitelist": ip_lists.get('whitelisted', []),
            "blacklist": ip_lists.get('banned', [])
        })
        
    except Exception as e:
        debug_log(f"[ERROR] Setup get IP lists failed: {e}")
        return jsonify({"error": str(e)}), 500

def register_setup_routes(app):
    """
    Register setup routes with the Flask app.
    
    Args:
        app: Flask application instance
    """
    # Get the limiter instance from the app
    limiter = getattr(app, 'limiter', None)
    
    # Register routes directly on the app to maintain the same endpoint names
    # Setup routes should be exempt from rate limiting since they're part of initial setup
    if limiter:
        # Apply rate limiting exemption to setup routes
        setup_exempt = limiter.exempt(setup)
        setup_complete_exempt = limiter.exempt(setup_complete)
        app.add_url_rule("/setup", "setup", setup_exempt, methods=["GET", "POST"])
        app.add_url_rule("/setup_complete", "setup_complete", setup_complete_exempt)
    else:
        app.add_url_rule("/setup", "setup", setup, methods=["GET", "POST"])
        app.add_url_rule("/setup_complete", "setup_complete", setup_complete)
    
    # Add a route to clear rate limiting for setup (emergency use)
    if limiter:
        @app.route("/clear-rate-limit", methods=["GET"])
        @limiter.exempt
        def clear_rate_limit():
            """Clear rate limiting for the current IP (emergency use during setup)"""
            try:
                from services.rate_limit_service import RateLimitService
                from config import get_config
                from flask import request
                
                config = get_config()
                rate_limit_service = RateLimitService(config)
                rate_limit_service.initialize()
                
                # Get client IP
                client_ip = request.remote_addr
                if request.headers.get('X-Forwarded-For'):
                    client_ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
                elif request.headers.get('X-Real-IP'):
                    client_ip = request.headers.get('X-Real-IP')
                
                # Clear rate limiting for this IP
                rate_limit_service.clear_failed_attempts(client_ip)
                rate_limit_service.clear_lockout(client_ip)
                
                debug_log(f"Rate limiting cleared for IP: {client_ip}")
                return jsonify({"success": True, "message": f"Rate limiting cleared for IP: {client_ip}"})
                
            except Exception as e:
                debug_log(f"Failed to clear rate limiting: {e}")
                return jsonify({"success": False, "error": str(e)}), 500
    else:
        @app.route("/clear-rate-limit", methods=["GET"])
        def clear_rate_limit():
            """Clear rate limiting for the current IP (emergency use during setup)"""
            try:
                from services.rate_limit_service import RateLimitService
                from config import get_config
                from flask import request
                
                config = get_config()
                rate_limit_service = RateLimitService(config)
                rate_limit_service.initialize()
                
                # Get client IP
                client_ip = request.remote_addr
                if request.headers.get('X-Forwarded-For'):
                    client_ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
                elif request.headers.get('X-Real-IP'):
                    client_ip = request.headers.get('X-Real-IP')
                
                # Clear rate limiting for this IP
                rate_limit_service.clear_failed_attempts(client_ip)
                rate_limit_service.clear_lockout(client_ip)
                
                debug_log(f"Rate limiting cleared for IP: {client_ip}")
                return jsonify({"success": True, "message": f"Rate limiting cleared for IP: {client_ip}"})
                
            except Exception as e:
                debug_log(f"Failed to clear rate limiting: {e}")
                return jsonify({"success": False, "error": str(e)}), 500
    
    # Note: setup-poster-downloads route is registered in app.py with CSRF exemption 