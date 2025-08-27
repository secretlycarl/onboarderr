"""
API Routes

This module provides API endpoints for various operations.
"""

import os
import json
import random
import urllib.parse
from flask import Blueprint, request, jsonify, session
from services.library_service import LibraryService
from services.notification_service import NotificationService
from services.rate_limit_service import RateLimitService
from config import get_config
import time

# Initialize services
library_service = LibraryService()
notification_service = NotificationService()
rate_limit_service = RateLimitService()

def register_api_routes(app):
    """Register API routes with the Flask app."""
    
    api_bp = Blueprint('api', __name__)
    
    @api_bp.route("/ajax/delete-plex-request", methods=["POST"])
    def delete_plex_request():
        """Delete a Plex access request."""
        if not session.get("admin_authenticated", False):
            return jsonify({"error": "Unauthorized"}), 401
        
        try:
            data = request.get_json()
            email = data.get('email')
            
            if not email:
                return jsonify({"error": "Email is required"}), 400
            
            # Load existing requests
            requests_file = "plex_submissions.json"
            if os.path.exists(requests_file):
                with open(requests_file, 'r', encoding='utf-8') as f:
                    requests = json.load(f)
            else:
                requests = []
            
            # Remove the request
            original_count = len(requests)
            requests = [req for req in requests if req.get('email') != email]
            
            # Save updated requests
            with open(requests_file, 'w', encoding='utf-8') as f:
                json.dump(requests, f, indent=2)
            
            # Send notification
            notification_service.send_security_alert(
                "plex_request_deleted",
                request.remote_addr,
                f"Plex request deleted for {email}"
            )
            
            return jsonify({
                "success": True,
                "message": f"Request for {email} deleted successfully",
                "deleted_count": original_count - len(requests)
            })
            
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @api_bp.route("/ajax/delete-abs-request", methods=["POST"])
    def delete_abs_request():
        """Delete an Audiobookshelf access request."""
        if not session.get("admin_authenticated", False):
            return jsonify({"error": "Unauthorized"}), 401
        
        try:
            data = request.get_json()
            email = data.get('email')
            
            if not email:
                return jsonify({"error": "Email is required"}), 400
            
            # Load existing requests
            requests_file = "audiobookshelf_submissions.json"
            if os.path.exists(requests_file):
                with open(requests_file, 'r', encoding='utf-8') as f:
                    requests = json.load(f)
            else:
                requests = []
            
            # Remove the request
            original_count = len(requests)
            requests = [req for req in requests if req.get('email') != email]
            
            # Save updated requests
            with open(requests_file, 'w', encoding='utf-8') as f:
                json.dump(requests, f, indent=2)
            
            # Send notification
            notification_service.send_security_alert(
                "abs_request_deleted",
                request.remote_addr,
                f"Audiobookshelf request deleted for {email}"
            )
            
            return jsonify({
                "success": True,
                "message": f"Request for {email} deleted successfully",
                "deleted_count": original_count - len(requests)
            })
            
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @api_bp.route("/ajax/ip-management", methods=["POST"])
    def ip_management():
        """Handle IP management operations."""
        if not session.get("admin_authenticated", False):
            return jsonify({"error": "Unauthorized"}), 401
        
        try:
            data = request.get_json()
            action = data.get('action')
            ip_address = data.get('ip_address')
            
            if not action or not ip_address:
                return jsonify({"error": "Action and IP address are required"}), 400
            
            if action == "whitelist":
                rate_limit_service.whitelist_ip(ip_address)
                message = f"IP {ip_address} whitelisted successfully"
            elif action == "blacklist":
                rate_limit_service.blacklist_ip(ip_address)
                message = f"IP {ip_address} blacklisted successfully"
            elif action == "remove_whitelist":
                rate_limit_service.remove_whitelist_ip(ip_address)
                message = f"IP {ip_address} removed from whitelist"
            elif action == "remove_blacklist":
                rate_limit_service.remove_blacklist_ip(ip_address)
                message = f"IP {ip_address} removed from blacklist"
            else:
                return jsonify({"error": "Invalid action"}), 400
            
            return jsonify({"success": True, "message": message})
            
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @api_bp.route("/ajax/get-ip-lists", methods=["GET"])
    def get_ip_lists():
        """Get current IP whitelist and blacklist."""
        if not session.get("admin_authenticated", False):
            return jsonify({"error": "Unauthorized"}), 401
        
        try:
            whitelist = rate_limit_service.get_whitelist()
            blacklist = rate_limit_service.get_blacklist()
            
            return jsonify({
                "whitelist": whitelist,
                "blacklist": blacklist
            })
            
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @api_bp.route("/ajax/check-rate-limit", methods=["GET"])
    def check_rate_limit():
        """Check current rate limit status."""
        try:
            client_ip = request.remote_addr
            is_rate_limited, remaining_time = rate_limit_service.check_rate_limit(client_ip, "general")
            
            return jsonify({
                "rate_limited": is_rate_limited,
                "remaining_time": remaining_time
            })
            
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @api_bp.route("/ajax/rate-limit-settings", methods=["POST"])
    def rate_limit_settings():
        """Update rate limit settings."""
        if not session.get("admin_authenticated", False):
            return jsonify({"error": "Unauthorized"}), 401
        
        try:
            data = request.get_json()
            max_attempts = data.get('max_attempts')
            lockout_duration = data.get('lockout_duration')
            window_size = data.get('window_size')
            
            # Update settings in environment
            config = get_config()
            if max_attempts is not None:
                config.set("RATE_LIMIT_MAX_ATTEMPTS", str(max_attempts))
            if lockout_duration is not None:
                config.set("RATE_LIMIT_LOCKOUT_DURATION", str(lockout_duration))
            if window_size is not None:
                config.set("RATE_LIMIT_WINDOW_SIZE", str(window_size))
            
            return jsonify({"success": True, "message": "Rate limit settings updated"})
            
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @api_bp.route("/ajax/get-rate-limit-settings", methods=["GET"])
    def get_rate_limit_settings():
        """Get current rate limit settings."""
        if not session.get("admin_authenticated", False):
            return jsonify({"error": "Unauthorized"}), 401
        
        try:
            config = get_config()
            settings = {
                "max_attempts": int(config.get("RATE_LIMIT_MAX_ATTEMPTS", "5")),
                "lockout_duration": int(config.get("RATE_LIMIT_LOCKOUT_DURATION", "300")),
                "window_size": int(config.get("RATE_LIMIT_WINDOW_SIZE", "60"))
            }
            
            return jsonify(settings)
            
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @api_bp.route("/ajax/invite-plex-users", methods=["POST"])
    def invite_plex_users():
        """Invite users to Plex."""
        if not session.get("admin_authenticated", False):
            return jsonify({"error": "Unauthorized"}), 401
        
        try:
            data = request.get_json()
            emails = data.get('emails', [])
            
            if not emails:
                return jsonify({"error": "No emails provided"}), 400
            
            # Load existing requests
            requests_file = "plex_submissions.json"
            if os.path.exists(requests_file):
                with open(requests_file, 'r', encoding='utf-8') as f:
                    requests = json.load(f)
            else:
                requests = []
            
            # Add new requests
            for email in emails:
                if not any(req.get('email') == email for req in requests):
                    requests.append({
                        "email": email,
                        "timestamp": time.time(),
                        "status": "pending"
                    })
            
            # Save updated requests
            with open(requests_file, 'w', encoding='utf-8') as f:
                json.dump(requests, f, indent=2)
            
            return jsonify({
                "success": True,
                "message": f"Invited {len(emails)} users to Plex"
            })
            
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @api_bp.route("/ajax/create-abs-users", methods=["POST"])
    def create_abs_users():
        """Create Audiobookshelf users."""
        if not session.get("admin_authenticated", False):
            return jsonify({"error": "Unauthorized"}), 401
        
        try:
            data = request.get_json()
            emails = data.get('emails', [])
            
            if not emails:
                return jsonify({"error": "No emails provided"}), 400
            
            # Load existing requests
            requests_file = "audiobookshelf_submissions.json"
            if os.path.exists(requests_file):
                with open(requests_file, 'r', encoding='utf-8') as f:
                    requests = json.load(f)
            else:
                requests = []
            
            # Add new requests
            for email in emails:
                if not any(req.get('email') == email for req in requests):
                    requests.append({
                        "email": email,
                        "timestamp": time.time(),
                        "status": "pending"
                    })
            
            # Save updated requests
            with open(requests_file, 'w', encoding='utf-8') as f:
                json.dump(requests, f, indent=2)
            
            return jsonify({
                "success": True,
                "message": f"Created {len(emails)} Audiobookshelf user requests"
            })
            
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @api_bp.route("/ajax/poster-progress", methods=["GET"])
    def poster_progress():
        """Get poster download progress."""
        if not session.get("admin_authenticated", False):
            return jsonify({"error": "Unauthorized"}), 401
        
        try:
            # This would be implemented to show poster download progress
            return jsonify({"progress": 0, "status": "idle"})
            
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @api_bp.route("/ajax/get-library-notes", methods=["GET"])
    def get_library_notes():
        """Get library notes for display."""
        if not session.get("authenticated"):
            return jsonify({"error": "Not authenticated"}), 401
        
        try:
            # Load library notes from file
            notes_file = "library_notes.json"
            if os.path.exists(notes_file):
                with open(notes_file, 'r', encoding='utf-8') as f:
                    notes = json.load(f)
            else:
                notes = {}
            
            return jsonify(notes)
            
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @api_bp.route("/ajax/load-library-posters", methods=["POST"])
    def load_library_posters():
        """Load posters for a specific library."""
        if not session.get("authenticated"):
            return jsonify({"error": "Not authenticated"}), 401
        
        try:
            data = request.get_json()
            library_name = data.get("library_name")
            
            if not library_name:
                return jsonify({"error": "Library name required"}), 400
            
            # Get library information
            libraries = library_service.get_libraries_from_local_files()
            library = None
            for lib in libraries:
                if lib["title"] == library_name:
                    library = lib
                    break
            
            if not library:
                return jsonify({"error": "Library not found"}), 404
            
            # Load posters for the library
            section_id = library["key"]
            poster_dir = library_service.get_library_poster_dir(section_id)
            
            posters = []
            if os.path.exists(poster_dir):
                # Get all image files
                all_files = [f for f in os.listdir(poster_dir) if f.lower().endswith(('.webp', '.jpg', '.jpeg', '.png'))]
                
                for fname in all_files:
                    poster_url = f"/static/posters/{section_id}/{fname}"
                    title = fname.rsplit('.', 1)[0].replace('_', ' ').replace('-', ' ').title()
                    
                    # Load metadata if available
                    json_path = os.path.join(poster_dir, fname.rsplit('.', 1)[0] + '.json')
                    if os.path.exists(json_path):
                        try:
                            with open(json_path, 'r', encoding='utf-8') as f:
                                meta = json.load(f)
                                if meta.get('title'):
                                    title = meta.get('title')
                        except (IOError, json.JSONDecodeError):
                            pass
                    
                    posters.append({
                        "url": poster_url,
                        "title": title
                    })
            
            return jsonify({
                "success": True,
                "library": library_name,
                "posters": posters
            })
            
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @api_bp.route("/ajax/load-all-items", methods=["POST"])
    def load_all_items():
        """Load all items for a library with metadata."""
        if not session.get("authenticated"):
            return jsonify({"error": "Not authenticated"}), 401
        
        try:
            data = request.get_json()
            library_name = data.get("library_name")
            
            if not library_name:
                return jsonify({"error": "Library name required"}), 400
            
            # Get ordered libraries using the helper function
            ordered_libraries = library_service.get_ordered_libraries()
            
            # Find library by name
            library = None
            for lib in ordered_libraries:
                if lib["title"] == library_name:
                    library = lib
                    break
            
            if library is None:
                return jsonify({"error": "Library not found"}), 404
            
            section_id = library["key"]
            
            # Load cached poster metadata for this specific library
            poster_dir = library_service.get_library_poster_dir(section_id)
            
            items_with_posters = []
            
            if os.path.exists(poster_dir):
                # Get all JSON files
                json_files = [f for f in os.listdir(poster_dir) if f.endswith(".json")]
                
                for fname in json_files:
                    meta_path = os.path.join(poster_dir, fname)
                    try:
                        with open(meta_path, "r", encoding="utf-8") as f:
                            meta = json.load(f)
                        
                        title = meta.get("title")
                        if title:
                            poster_file = meta.get("poster")
                            poster_url = f"/static/posters/{section_id}/{poster_file}" if poster_file else None
                            
                            # Check if this is a music artist and add Last.fm URL
                            is_artist = meta.get('media_type') == 'artist' or library.get('media_type') == 'artist'
                            lastfm_url = f"https://www.last.fm/music/{urllib.parse.quote(title)}" if is_artist else None
                            
                            items_with_posters.append({
                                "title": title,
                                "poster": poster_url,
                                "imdb": meta.get("imdb"),
                                "tmdb": meta.get("tmdb"),
                                "tvdb": meta.get("tvdb"),
                                "lastfm_url": lastfm_url,
                                "is_artist": is_artist,
                            })
                    except Exception as e:
                        print(f"Error loading poster metadata from {meta_path}: {e}")
                        continue
            
            # Sort items alphabetically by title (stripping articles for sorting)
            def strip_articles(title):
                """Strip common articles from the beginning of titles for sorting"""
                if not title:
                    return title
                title = title.strip()
                articles = ['a ', 'an ', 'the ']
                for article in articles:
                    if title.lower().startswith(article):
                        return title[len(article):].strip()
                return title
            
            items_with_posters.sort(key=lambda x: strip_articles(x["title"]).lower())
            
            return jsonify({
                "success": True,
                "library": library_name,
                "items": items_with_posters
            })
            
        except Exception as e:
            print(f"Error loading all items: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({"error": str(e)}), 500
    
    # Note: load-posters-by-letter route is now handled by routes/posters.py to avoid conflicts
    
    # Register the blueprint with the app
    app.register_blueprint(api_bp) 