#!/usr/bin/env python3
"""
Onboarderr - New Refactored Application Entry Point

This is the refactored application that gradually replaces old_app.py functionality
with new modular components. Phase 4: Route Organization

Phase 1: Foundation - ✅ COMPLETED (Configuration system)
Phase 2: Setup & Authentication - ✅ COMPLETED (Setup route refactoring)
Phase 3: Service Layer - ✅ COMPLETED (Service layer implementation)
Phase 4: Route Organization - ✅ COMPLETED (Route organization)
"""

import sys
import os
import time
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import requests
import xml.etree.ElementTree as ET

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Load environment variables
def load_environment():
    """Load environment variables from .env file."""
    from dotenv import load_dotenv
    
    # Load the regular .env file
    if os.path.exists('.env'):
        load_dotenv('.env', override=True)
        print("[INFO] Loaded environment from .env")
    else:
        print("[WARN] No .env file found, using default environment")

# Load environment
load_environment()

# Initialize Flask app
app = Flask(__name__, static_folder='static')

# Configure Flask app
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = 3600

# Initialize extensions
csrf = CSRFProtect(app)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Context processors for template variables
@app.context_processor
def inject_admin_status():
    """Inject admin status and logo filenames into all templates."""
    from flask import session
    return dict(
        is_admin=session.get("admin_authenticated", False),
        logo_filename=get_logo_filename(),
        wordmark_filename=get_wordmark_filename()
    )

@app.context_processor
def inject_favicon_timestamp():
    """Inject favicon timestamp to force browser cache updates."""
    favicon_path = os.path.join('static', 'favicon.webp')
    try:
        # Get file modification time as timestamp
        favicon_timestamp = int(os.path.getmtime(favicon_path))
    except (OSError, FileNotFoundError):
        # If favicon doesn't exist, use current time
        favicon_timestamp = int(time.time())
    return dict(favicon_timestamp=favicon_timestamp)



def get_logo_filename():
    """Get the current logo filename (could be PNG or WebP)"""
    if os.path.exists(os.path.join('static', 'clearlogo.png')):
        return 'clearlogo.png'
    elif os.path.exists(os.path.join('static', 'clearlogo.webp')):
        return 'clearlogo.webp'
    else:
        return 'clearlogo.webp'  # default fallback

def get_wordmark_filename():
    """Get the current wordmark filename (could be PNG or WebP)"""
    if os.path.exists(os.path.join('static', 'wordmark.png')):
        return 'wordmark.png'
    elif os.path.exists(os.path.join('static', 'wordmark.webp')):
        return 'wordmark.webp'
    else:
        return 'wordmark.webp'  # default fallback

# Import and register refactored modules
try:
    from config import get_config
    from routes.setup import register_setup_routes
    from routes.auth import register_auth_routes
    from routes.pages import register_pages_routes
    from routes.onboarding import register_onboarding_routes
    from routes.audiobookshelf import register_audiobookshelf_routes
    from routes.api import register_api_routes
    from routes.posters import register_poster_routes
    from routes.admin import register_admin_routes
    
    # Register setup routes
    register_setup_routes(app)
    
    # Exempt setup poster downloads from CSRF
    @app.route("/ajax/setup-poster-downloads", methods=["POST"])
    @csrf.exempt
    def setup_poster_downloads_csrf_exempt():
        """CSRF exempt version of setup poster downloads"""
        from routes.setup import setup_poster_downloads
        return setup_poster_downloads()
    
    # Register authentication routes
    register_auth_routes(app)
    
    # Register pages routes
    register_pages_routes(app)
    
    # Register onboarding routes
    register_onboarding_routes(app)
    
    # Register audiobookshelf routes
    register_audiobookshelf_routes(app)
    
    # Register API routes
    register_api_routes(app)
    
    # Register poster routes
    register_poster_routes(app)
    
    # Register admin routes
    register_admin_routes(app)
    
    # Add fetch-libraries route directly to avoid CSRF issues
    @app.route("/fetch-libraries", methods=["POST"])
    @limiter.exempt
    @csrf.exempt
    def fetch_libraries():
        """Fetch libraries from Plex and Audiobookshelf."""
        data = request.get_json()
        plex_token = data.get("plex_token")
        plex_url = data.get("plex_url")
        
        if not plex_token or not plex_url:
            return jsonify({"error": "Plex token and URL are required"})
        
        try:
            headers = {"X-Plex-Token": plex_token}
            url = f"{plex_url}/library/sections"
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            root = ET.fromstring(response.text)
            libraries = []
            for directory in root.findall(".//Directory"):
                title = directory.attrib.get("title")
                key = directory.attrib.get("key")
                media_type = directory.attrib.get("type")  # Get the media type
                if title and key:
                    libraries.append({
                        "title": title, 
                        "key": key, 
                        "media_type": media_type
                    })
            
            # For configuration purposes, show all libraries so admin can select which ones should be available
            # The filtering will be handled by the frontend based on current LIBRARY_IDS
            
            return jsonify({"libraries": libraries})
        except Exception as e:
            return jsonify({"error": str(e)})
    
    # Add check-restart-readiness route directly to avoid authentication issues
    @app.route("/check-restart-readiness", methods=["GET"])
    @limiter.exempt
    @csrf.exempt
    def check_restart_readiness():
        """Check if the system is ready for restart"""
        try:
            # Import poster service to check actual status
            from services.poster_service import PosterService
            poster_service = PosterService()
            
            # Get actual poster download status
            poster_status = poster_service.get_download_status()
            
            # Determine if we should wait for posters
            should_wait = False
            
            # Check if downloads are in progress
            if poster_status["download_running"] and poster_status["queue_size"] > 0:
                should_wait = True
            
            # Check if any library downloads are in progress
            for lib_id, progress in poster_status["progress"].items():
                if progress.get("status") in ["downloading", "starting"]:
                    should_wait = True
                    break
            
            # Check ABS status if enabled
            abs_enabled = os.getenv("ABS_ENABLED", "yes") == "yes"
            abs_needs_refresh = False
            abs_download_in_progress = False
            abs_download_completed = True
            
            # For now, assume ABS downloads are completed
            # This can be enhanced later with actual ABS status checking
            
            # Create setup download status structure
            setup_download_status = {}
            current_phase = "idle"
            
            # Check if there are any active downloads
            active_downloads = [p for p in poster_status["progress"].values() 
                              if p.get("status") in ["downloading", "starting"]]
            
            if active_downloads:
                current_phase = "plex"
                setup_download_status["unified"] = {
                    "status": "plex_downloading",
                    "message": f"Downloading posters for {len(active_downloads)} libraries...",
                    "current": sum(p.get("downloaded", 0) for p in active_downloads),
                    "total": sum(p.get("total", 0) for p in active_downloads)
                }
            else:
                current_phase = "completed"
                setup_download_status["unified"] = {
                    "status": "completed",
                    "message": "All downloads completed",
                    "current": 0,
                    "total": 0
                }
            
            ready = not should_wait
            
            print(f"[DEBUG] Restart readiness check: ready={ready}, should_wait={should_wait}")
            print(f"[DEBUG] Poster status: {poster_status}")
            print(f"[DEBUG] Setup download status: {setup_download_status}")
            print(f"[DEBUG] Current phase: {current_phase}")
            
            return jsonify({
                "ready": ready,
                "poster_status": {
                    "in_progress": should_wait,
                    "worker_running": poster_status["download_running"],
                    "queue_size": poster_status["queue_size"],
                    "progress": poster_status["progress"]
                },
                "setup_download_status": setup_download_status,
                "current_phase": current_phase,
                "should_wait_for_posters": should_wait,
                "abs_enabled": abs_enabled,
                "abs_needs_refresh": abs_needs_refresh,
                "abs_download_in_progress": abs_download_in_progress,
                "abs_download_completed": abs_download_completed
            })
        except Exception as e:
            print(f"[ERROR] Error checking restart readiness: {e}")
            return jsonify({"ready": True, "error": str(e)})
    
    print("[INFO] Successfully loaded refactored setup, authentication, pages, onboarding, audiobookshelf, API, poster, and admin routes")
    
except ImportError as e:
    print(f"[WARN] Failed to load refactored modules: {e}")
    print("[WARN] Falling back to old_app.py functionality")

# Import old_app for fallback functionality
try:
    from old_app import app as old_app
    
    # Copy routes from old_app that haven't been refactored yet
    # This ensures backward compatibility while we refactor
    for rule in old_app.url_map.iter_rules():
        if not rule.endpoint.startswith('static'):
            # Skip setup routes as they're now handled by refactored code
            if rule.rule in ['/setup', '/setup_complete', '/ajax/setup-poster-downloads']:
                continue
            
            # Skip authentication routes as they're now handled by refactored code
            if rule.rule in ['/login', '/logout']:
                continue
            
            # Skip pages routes as they're now handled by refactored code
            if rule.rule in ['/', '/services', '/medialists']:
                continue
            
            # Skip onboarding routes as they're now handled by refactored code
            if rule.rule in ['/onboarding']:
                continue
            
            # Skip audiobookshelf routes as they're now handled by refactored code
            if rule.rule in ['/audiobookshelf', '/audiobook-covers', '/audiobook-covers-with-links']:
                continue
            
            # Skip API routes as they're now handled by refactored code
            if rule.rule in ['/fetch-libraries', '/ajax/delete-plex-request', '/ajax/delete-abs-request', 
                           '/ajax/ip-management', '/ajax/get-ip-lists', '/ajax/check-rate-limit',
                           '/ajax/rate-limit-settings', '/ajax/get-rate-limit-settings',
                           '/ajax/invite-plex-users', '/ajax/create-abs-users', '/ajax/poster-progress',
                           '/ajax/get-library-notes']:
                continue
            
            # Skip poster routes as they're now handled by refactored code
            if rule.rule in ['/refresh-library-titles', '/trigger-abs-poster-downloads', '/poster-status',
                           '/ajax/load-library-posters', '/ajax/load-all-items', '/ajax/load-posters-by-letter',
                           '/ajax/update-libraries', '/ajax/get-random-posters', '/ajax/get-random-posters-all',
                           '/ajax/get-random-audiobook-posters']:
                continue
            
            # Skip admin routes as they're now handled by refactored code
            if rule.rule in ['/trigger_restart', '/check-restart-readiness', '/error-logs']:
                continue
            
            # Copy other routes from old_app
            old_view_func = old_app.view_functions[rule.endpoint]
            app.add_url_rule(
                rule.rule,
                endpoint=rule.endpoint,
                view_func=old_view_func,
                methods=rule.methods
            )
    
    print("[INFO] Successfully imported routes from old_app.py")
    
except ImportError as e:
    print(f"[ERROR] Failed to import old_app.py: {e}")
    print("[ERROR] Application may not function properly")



if __name__ == '__main__':
    # Get port from environment (default to 42069 if not set)
    port = 42069
#        port = int(os.getenv('APP_PORT', 42069))
    
    print(f"[INFO] Starting Onboarderr on port {port}")
    print(f"[INFO] Phase 4: Route Organization")
    print(f"[INFO] Access the application at: http://localhost:{port}")
    print(f"[INFO] Setup page: http://localhost:{port}/setup")
    print(f"[INFO] Login page: http://localhost:{port}/login")
    print(f"[INFO] Onboarding page: http://localhost:{port}/onboarding")
    print(f"[INFO] Services page: http://localhost:{port}/services")
    print(f"[INFO] Media lists page: http://localhost:{port}/medialists")
    
    app.run(
        host='0.0.0.0',
        port=port,
        debug=True
    ) 