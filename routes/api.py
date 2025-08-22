"""
API Routes Module

Handles AJAX/API endpoints that were previously in old_app.py.
This module manages all AJAX interactions and API responses.
"""

from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify, current_app
from services.template_context_service import TemplateContextService
from services.library_service import LibraryService
from services.submissions_service import SubmissionsService
from services.notification_service import NotificationService
from services.rate_limit_service import RateLimitService
from config import get_config
import requests
import xml.etree.ElementTree as ET

def register_api_routes(app):
    """Register API routes with the Flask app."""
    
    # Create blueprint for API routes
    api_bp = Blueprint('api', __name__)
    
    # Initialize services
    template_context_service = TemplateContextService()
    library_service = LibraryService()
    submissions_service = SubmissionsService()
    notification_service = NotificationService()
    rate_limit_service = RateLimitService()
    
    # Note: We'll handle rate limiting and CSRF differently for the fetch-libraries route
    
    # Note: fetch-libraries route is handled separately to avoid CSRF issues
    # It will be registered directly on the app in the main app.py file
    
    @api_bp.route("/ajax/delete-plex-request", methods=["POST"])
    def delete_plex_request():
        """Delete a Plex request."""
        
        # Check if user is authenticated
        if not session.get("admin_authenticated", False):
            return jsonify({"error": "Unauthorized"}), 401
        
        try:
            data = request.get_json()
            request_id = data.get('request_id')
            
            if not request_id:
                return jsonify({"error": "Request ID is required"}), 400
            
            # Delete the request using submissions service
            success = submissions_service.delete_plex_submission(request_id)
            
            if success:
                return jsonify({"status": "success", "message": "Request deleted successfully"})
            else:
                return jsonify({"error": "Failed to delete request"}), 500
                
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @api_bp.route("/ajax/delete-abs-request", methods=["POST"])
    def delete_abs_request():
        """Delete an Audiobookshelf request."""
        
        # Check if user is authenticated
        if not session.get("admin_authenticated", False):
            return jsonify({"error": "Unauthorized"}), 401
        
        try:
            data = request.get_json()
            request_id = data.get('request_id')
            
            if not request_id:
                return jsonify({"error": "Request ID is required"}), 400
            
            # Delete the request using submissions service
            success = submissions_service.delete_abs_submission(request_id)
            
            if success:
                return jsonify({"status": "success", "message": "Request deleted successfully"})
            else:
                return jsonify({"error": "Failed to delete request"}), 500
                
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @api_bp.route("/ajax/ip-management", methods=["POST"])
    def ip_management():
        """Handle IP management operations."""
        
        # Check if user is authenticated
        if not session.get("admin_authenticated", False):
            return jsonify({"error": "Unauthorized"}), 401
        
        try:
            data = request.get_json()
            action = data.get('action')
            ip_address = data.get('ip_address')
            
            if not action or not ip_address:
                return jsonify({"error": "Action and IP address are required"}), 400
            
            # This will be implemented with actual IP management logic
            return jsonify({"status": "success", "message": f"IP {action} completed"})
                
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @api_bp.route("/ajax/get-ip-lists", methods=["GET"])
    def get_ip_lists():
        """Get IP whitelist and blacklist."""
        
        # Check if user is authenticated
        if not session.get("admin_authenticated", False):
            return jsonify({"error": "Unauthorized"}), 401
        
        try:
            # This will be implemented with actual IP list retrieval
            config = get_config()
            whitelist = config.get('IP_WHITELIST', '').split(',') if config.get('IP_WHITELIST') else []
            blacklist = config.get('IP_BLACKLIST', '').split(',') if config.get('IP_BLACKLIST') else []
            
            return jsonify({
                "whitelist": [ip.strip() for ip in whitelist if ip.strip()],
                "blacklist": [ip.strip() for ip in blacklist if ip.strip()]
            })
                
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @api_bp.route("/ajax/check-rate-limit", methods=["GET"])
    def check_rate_limit():
        """Check current rate limit status."""
        
        # This endpoint should be accessible during login, so don't require authentication
        # The rate limit check is used to prevent login attempts when rate limited
        
        try:
            # Get client IP
            from utils.data_utils import get_client_ip
            client_ip = get_client_ip()
            
            # Check if IP is whitelisted or banned
            if rate_limit_service.is_ip_whitelisted(client_ip):
                return jsonify({"rate_limited": False})
            
            if rate_limit_service.is_ip_banned(client_ip):
                return jsonify({"rate_limited": True, "time_remaining": 86400})  # 24 hours
            
            # Check login rate limit
            rate_limited, time_remaining = rate_limit_service.check_rate_limit(client_ip, "login")
            if rate_limited:
                return jsonify({
                    "rate_limited": True,
                    "time_remaining": int(time_remaining)  # Ensure it's an integer for JavaScript
                })
            
            return jsonify({"rate_limited": False})
                
        except Exception as e:
            return jsonify({"rate_limited": False})
    
    @api_bp.route("/ajax/rate-limit-settings", methods=["POST"])
    def rate_limit_settings():
        """Update rate limit settings."""
        
        # Check if user is authenticated
        if not session.get("admin_authenticated", False):
            return jsonify({"error": "Unauthorized"}), 401
        
        try:
            data = request.get_json()
            # This will be implemented with actual rate limit settings update
            return jsonify({"status": "success", "message": "Rate limit settings updated"})
                
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @api_bp.route("/ajax/get-rate-limit-settings", methods=["GET"])
    def get_rate_limit_settings():
        """Get current rate limit settings."""
        
        # Check if user is authenticated
        if not session.get("admin_authenticated", False):
            return jsonify({"error": "Unauthorized"}), 401
        
        try:
            # Get rate limit settings from service
            settings = rate_limit_service.get_settings()
            return jsonify(settings)
                
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @api_bp.route("/ajax/invite-plex-users", methods=["POST"])
    def invite_plex_users():
        """Invite users to Plex."""
        
        # Check if user is authenticated
        if not session.get("admin_authenticated", False):
            return jsonify({"error": "Unauthorized"}), 401
        
        try:
            data = request.get_json()
            emails = data.get('emails', [])
            
            if not emails:
                return jsonify({"error": "Email addresses are required"}), 400
            
            # This will be implemented with actual Plex user invitation logic
            return jsonify({"status": "success", "message": f"Invited {len(emails)} users to Plex"})
                
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @api_bp.route("/ajax/create-abs-users", methods=["POST"])
    def create_abs_users():
        """Create users in Audiobookshelf."""
        
        # Check if user is authenticated
        if not session.get("admin_authenticated", False):
            return jsonify({"error": "Unauthorized"}), 401
        
        try:
            data = request.get_json()
            users = data.get('users', [])
            
            if not users:
                return jsonify({"error": "User data is required"}), 400
            
            # This will be implemented with actual ABS user creation logic
            return jsonify({"status": "success", "message": f"Created {len(users)} users in Audiobookshelf"})
                
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @api_bp.route("/ajax/poster-progress", methods=["GET"])
    def poster_progress():
        """Get poster download progress."""
        
        # Check if user is authenticated
        if not session.get("admin_authenticated", False):
            return jsonify({"error": "Unauthorized"}), 401
        
        try:
            # Import poster service
            from services.poster_service import PosterService
            poster_service = PosterService()
            
            # Get download status
            status = poster_service.get_download_status()
            
            return jsonify({
                "status": "success",
                "download_running": status["download_running"],
                "queue_size": status["queue_size"],
                "progress": status["progress"]
            })
                
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @api_bp.route("/ajax/get-library-notes", methods=["GET"])
    def get_library_notes():
        """Get library notes."""
        
        # Check if user is authenticated
        if not session.get("admin_authenticated", False):
            return jsonify({"error": "Unauthorized"}), 401
        
        try:
            # Get library notes from service
            notes = library_service.get_library_notes()
            return jsonify({"status": "success", "notes": notes})
                
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    # Register the blueprint with the app
    app.register_blueprint(api_bp) 