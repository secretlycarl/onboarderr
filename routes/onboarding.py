"""
Onboarding Routes Module

Handles the onboarding page functionality that was previously in old_app.py.
This module manages the onboarding flow for new users.
"""

from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify
from services.template_context_service import TemplateContextService
from services.library_service import LibraryService
from services.submissions_service import SubmissionsService
from config import get_config

def register_onboarding_routes(app):
    """Register onboarding routes with the Flask app."""
    
    # Create blueprint for onboarding routes
    onboarding_bp = Blueprint('onboarding', __name__)
    
    # Initialize services
    template_context_service = TemplateContextService()
    library_service = LibraryService()
    submissions_service = SubmissionsService()
    
    @onboarding_bp.route("/onboarding", methods=["GET", "POST"])
    def onboarding():
        """Handle the onboarding page - main entry point for new users."""
        
        # Check if user is authenticated (check both admin and user sessions)
        if not session.get("admin_authenticated", False) and not session.get("user_authenticated", False):
            return redirect(url_for("login"))
        
        # Get template context
        context = template_context_service.get_template_context()
        
        # Add onboarding-specific context
        context.update({
            'page_title': 'Onboarding - Onboarderr',
            'current_page': 'onboarding'
        })
        
        return render_template("onboarding.html", **context)
    
    # Register the blueprint with the app
    app.register_blueprint(onboarding_bp) 