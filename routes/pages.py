"""
Pages routes for Onboarderr

This module handles the main page routes including the index page,
services page, and other general pages.
"""

from flask import render_template, request, redirect, url_for, session, jsonify
from typing import Dict, Any

from services.template_context_service import TemplateContextService

def debug_log(message: str) -> None:
    """Log a debug message only if FLASK_DEBUG is enabled."""
    try:
        import os
        flask_debug = os.getenv("FLASK_DEBUG", "0") == "1"
        if flask_debug:
            print(f"[DEBUG] {message}")
    except Exception:
        pass

# Initialize services once
import os
if os.getenv("VERBOSE_DEBUG", "0") == "1":
    debug_log("Initializing template context service for pages")
template_context_service = TemplateContextService()
if os.getenv("VERBOSE_DEBUG", "0") == "1":
    debug_log("Template context service initialized for pages")

def index():
    """Handle the main index page."""
    debug_log("Index route accessed")
    
    # Check if user is authenticated
    if not session.get("authenticated"):
        debug_log("User not authenticated, redirecting to login")
        return redirect(url_for("login"))
    
    # Get template context
    context = template_context_service.get_template_context()
    
    debug_log("Rendering index page")
    return render_template("onboarding.html", **context)

def services():
    """Handle the services page."""
    debug_log("Services route accessed")
    
    # Check if user is authenticated
    if not session.get("authenticated"):
        debug_log("User not authenticated, redirecting to login")
        return redirect(url_for("login"))
    
    if request.method == "POST":
        # Handle services form submission
        debug_log("Processing services form submission")
        return _handle_services_form_submission()
    
    # Get template context
    context = template_context_service.get_template_context()
    
    debug_log("Rendering services page")
    return render_template("services.html", **context)

def _handle_services_form_submission():
    """Handle services form submission."""
    debug_log("Handling services form submission")
    
    try:
        # Import setup service to reuse form processing logic
        from services.setup_service import SetupService
        setup_service = SetupService()
        
        # Get form data
        form_data = request.form
        files = request.files
        
        debug_log(f"Services form data keys: {list(form_data.keys())}")
        debug_log(f"Services form files: {list(files.keys())}")
        
        # Process the form using setup service
        success, error_message = setup_service.process_setup_form(form_data, files)
        
        if not success:
            debug_log(f"Services form processing error: {error_message}")
            context = template_context_service.get_template_context()
            context["error_message"] = error_message
            return render_template("services.html", **context)
        
        # Services form processed successfully, redirect to setup_complete
        debug_log("Services form processed successfully, redirecting to setup_complete")
        
        # Determine changed settings based on form data
        changed_settings = []
        if form_data.get('plex_url') or form_data.get('plex_token'):
            changed_settings.extend(['plex_url', 'plex_token'])
        if form_data.get('abs_enabled') or form_data.get('audiobookshelf_url') or form_data.get('audiobookshelf_token'):
            changed_settings.extend(['abs_enabled', 'audiobookshelf_url', 'audiobookshelf_token'])
        if form_data.get('library_ids'):
            changed_settings.append('library_ids')
        
        return redirect(url_for("setup_complete", 
                               from_services="true",
                               changed_settings=",".join(changed_settings)))
        
    except Exception as e:
        debug_log(f"Error in services form submission: {e}")
        context = template_context_service.get_template_context()
        context["error_message"] = f"An error occurred: {str(e)}"
        return render_template("services.html", **context)

def medialists():
    """Handle the media lists page."""
    debug_log("Media lists route accessed")
    
    # Check if user is authenticated
    if not session.get("authenticated"):
        debug_log("User not authenticated, redirecting to login")
        return redirect(url_for("login"))
    
    # Get template context
    context = template_context_service.get_template_context()
    
    debug_log("Rendering media lists page")
    return render_template("medialists.html", **context)

def register_pages_routes(app):
    """
    Register pages routes with the Flask app.
    
    Args:
        app: Flask application instance
    """
    # Register routes directly on the app to maintain the same endpoint names
    app.add_url_rule("/", "index", index)
    app.add_url_rule("/services", "services", services, methods=["GET", "POST"])
    app.add_url_rule("/medialists", "medialists", medialists) 