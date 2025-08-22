"""
Setup routes for Onboarderr

This module handles all setup-related routes including the main setup page
and setup completion page.
"""

from flask import render_template, request, redirect, url_for, jsonify
from typing import Dict, Any
import os

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
    return redirect(url_for("setup_complete", from_setup="true"))

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
        
        # Import poster service and start downloads
        from services.poster_service import PosterService
        poster_service = PosterService()
        
        # Start poster downloads for each selected library
        libraries_started = 0
        for lib_id in selected_ids:
            try:
                success = poster_service.start_poster_download(lib_id)
                if success:
                    libraries_started += 1
                    debug_log(f"Started poster downloads for library {lib_id}")
                else:
                    debug_log(f"Failed to start poster downloads for library {lib_id}")
            except Exception as e:
                debug_log(f"Error starting poster downloads for library {lib_id}: {e}")
        
        debug_log(f"[INFO] Poster downloads initiated for {libraries_started} libraries")
        
        # Return response with detailed status
        return jsonify({
            "success": True,
            "message": f"Poster downloads initiated for {libraries_started} libraries",
            "libraries_count": libraries_started,
            "changed_settings": changed_settings,
            "needs_plex": libraries_started > 0,
            "needs_abs": False,  # ABS downloads not implemented yet
            "status": "initiated"
        })
        
    except Exception as e:
        debug_log(f"[ERROR] Setup poster downloads failed: {e}")
        return jsonify({
            "success": False,
            "error": f"Failed to initiate poster downloads: {str(e)}"
        })

def register_setup_routes(app):
    """
    Register setup routes with the Flask app.
    
    Args:
        app: Flask application instance
    """
    # Register routes directly on the app to maintain the same endpoint names
    app.add_url_rule("/setup", "setup", setup, methods=["GET", "POST"])
    app.add_url_rule("/setup_complete", "setup_complete", setup_complete)
    # Note: setup-poster-downloads route is registered in app.py with CSRF exemption 