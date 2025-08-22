"""
Admin Routes Module

Handles admin and system functionality that was previously in old_app.py.
This module manages system operations, error logs, and administrative tasks.
"""

from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify
from services.template_context_service import TemplateContextService
from services.library_service import LibraryService
from services.submissions_service import SubmissionsService
from config import get_config

def register_admin_routes(app):
    """Register admin routes with the Flask app."""
    
    # Create blueprint for admin routes
    admin_bp = Blueprint('admin', __name__)
    
    # Initialize services
    template_context_service = TemplateContextService()
    library_service = LibraryService()
    submissions_service = SubmissionsService()
    
    @admin_bp.route("/trigger_restart", methods=["POST"])
    def trigger_restart():
        """Trigger application restart."""
        
        # Check if user is authenticated
        if not session.get("admin_authenticated", False):
            return jsonify({"error": "Unauthorized"}), 401
        
        try:
            # This will be implemented with actual restart logic
            return jsonify({"status": "success", "message": "Restart triggered successfully"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    # Note: check-restart-readiness route is handled separately to avoid authentication issues
    # It will be registered directly on the app in the main app.py file
    
    @admin_bp.route("/error-logs", methods=["GET", "POST"])
    def error_logs():
        """Handle error logs page."""
        
        # Check if user is authenticated
        if not session.get("admin_authenticated", False):
            return redirect(url_for("login"))
        
        try:
            # Get template context
            context = template_context_service.get_template_context()
            
            # Add error logs specific context
            context.update({
                'page_title': 'Error Logs - Onboarderr',
                'current_page': 'error_logs'
            })
            
            # This will be implemented with actual error log loading logic
            context['error_logs'] = []
            
            return render_template("error_logs.html", **context)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    # Register the blueprint with the app
    app.register_blueprint(admin_bp) 