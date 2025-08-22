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

# Initialize services
debug_log("Initializing template context service for pages")
template_context_service = TemplateContextService()
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
    
    # Get template context
    context = template_context_service.get_template_context()
    
    debug_log("Rendering services page")
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
    app.add_url_rule("/services", "services", services)
    app.add_url_rule("/medialists", "medialists", medialists) 