"""
Audiobookshelf Routes Module

Handles audiobookshelf-related functionality that was previously in old_app.py.
This module manages audiobookshelf pages and poster management.
"""

from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify
from services.template_context_service import TemplateContextService
from services.library_service import LibraryService
from services.submissions_service import SubmissionsService
from config import get_config

def register_audiobookshelf_routes(app):
    """Register audiobookshelf routes with the Flask app."""
    
    # Create blueprint for audiobookshelf routes
    audiobookshelf_bp = Blueprint('audiobookshelf', __name__)
    
    # Initialize services
    template_context_service = TemplateContextService()
    library_service = LibraryService()
    submissions_service = SubmissionsService()
    
    @audiobookshelf_bp.route("/audiobookshelf", methods=["GET", "POST"])
    def audiobookshelf():
        """Handle the audiobookshelf page."""
        
        # Check if user is authenticated (regular or admin)
        if not session.get("authenticated", False) and not session.get("admin_authenticated", False):
            return redirect(url_for("login"))
        
        # Get template context
        context = template_context_service.get_template_context()
        
        # Add audiobookshelf-specific context
        context.update({
            'page_title': 'Audiobookshelf - Onboarderr',
            'current_page': 'audiobookshelf'
        })
        
        return render_template("audiobookshelf.html", **context)
    
    @audiobookshelf_bp.route("/audiobook-covers")
    def audiobook_covers():
        """Handle audiobook covers page."""
        
        # Check if user is authenticated
        if not session.get("admin_authenticated", False):
            return redirect(url_for("login"))
        
        # Get template context
        context = template_context_service.get_template_context()
        
        # Add audiobook covers specific context
        context.update({
            'page_title': 'Audiobook Covers - Onboarderr',
            'current_page': 'audiobook_covers'
        })
        
        return render_template("audiobook_covers.html", **context)
    
    @audiobookshelf_bp.route("/audiobook-covers-with-links")
    def audiobook_covers_with_links():
        """Handle audiobook covers with links page."""
        
        # Check if user is authenticated
        if not session.get("admin_authenticated", False):
            return redirect(url_for("login"))
        
        # Get template context
        context = template_context_service.get_template_context()
        
        # Add audiobook covers with links specific context
        context.update({
            'page_title': 'Audiobook Covers with Links - Onboarderr',
            'current_page': 'audiobook_covers_with_links'
        })
        
        return render_template("audiobook_covers_with_links.html", **context)
    
    # Register the blueprint with the app
    app.register_blueprint(audiobookshelf_bp) 