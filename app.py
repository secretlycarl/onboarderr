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
import shutil
import threading
import webbrowser
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from config import get_config
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import requests
import xml.etree.ElementTree as ET

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def update_env_with_missing_variables():
    """Compare .env and empty.env, add missing variables to .env while preserving existing values and comments"""
    if not os.path.exists('empty.env'):
        print('[WARN] empty.env not found, skipping .env update')
        return
    
    if not os.path.exists('.env'):
        print('[WARN] .env not found, copying empty.env to .env')
        shutil.copyfile('empty.env', '.env')
        return
    
    try:
        # Read empty.env to get all expected variables
        with open('empty.env', 'r', encoding='utf-8') as f:
            empty_env_content = f.read()
        
        # Parse empty.env to get variable names and default values
        empty_vars = {}
        for line in empty_env_content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                empty_vars[key.strip()] = value.strip()
        
        # Read current .env
        with open('.env', 'r', encoding='utf-8') as f:
            current_env_content = f.read()
        
        # Parse current .env to get existing variables
        current_vars = {}
        current_lines = current_env_content.split('\n')
        for line in current_lines:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                current_vars[key.strip()] = value.strip()
        
        # Find missing variables
        missing_vars = {}
        for key, default_value in empty_vars.items():
            if key not in current_vars:
                missing_vars[key] = default_value
        
        if missing_vars:
            print(f'\n[INFO] Found {len(missing_vars)} missing variables in .env, adding them...')
            
            # Add missing variables to the end of .env file
            with open('.env', 'a', encoding='utf-8') as f:
                f.write('\n')
                for key, value in missing_vars.items():
                    f.write(f'{key}={value}\n')
                    print(f'[INFO] Added: {key}={value}')
            
            print('[INFO] .env file updated successfully\n')
        else:
            print('[INFO] .env file is up to date with empty.env\n')
        
        # Ensure SECRET_KEY is properly set
        ensure_secret_key()
            
    except Exception as e:
        print(f'[ERROR] Failed to update .env file: {e}')

def ensure_secret_key():
    """Ensure SECRET_KEY is properly set in .env file"""
    try:
        env_path = '.env'
        with open(env_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        found = False
        for i, line in enumerate(lines):
            if line.strip().startswith('SECRET_KEY='):
                found = True
                if line.strip() == 'SECRET_KEY=' or line.strip() == 'SECRET_KEY=""' or line.strip() == 'SECRET_KEY=':
                    # Generate and set a new key
                    import secrets
                    new_key = secrets.token_urlsafe(48)
                    lines[i] = f'SECRET_KEY={new_key}\n'
                    print(f'[INFO] Generated new SECRET_KEY: {new_key[:10]}...')
                break
        
        if not found:
            import secrets
            new_key = secrets.token_urlsafe(48)
            lines.append(f'SECRET_KEY={new_key}\n')
            print(f'[INFO] Added new SECRET_KEY: {new_key[:10]}...')
        
        with open(env_path, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        
        print('[INFO] SECRET_KEY updated successfully')
        
    except Exception as e:
        print(f'[ERROR] Failed to ensure SECRET_KEY: {e}')

def get_app_url():
    """Get the application URL for browser opening"""
    port = int(os.getenv('APP_PORT', 10000))
    return f"http://localhost:{port}"

def open_browser_delayed():
    """Open browser after a delay to ensure server is running"""
    time.sleep(2)  # Wait for Flask to start
    try:
        url = get_app_url()
        print(f"\n[INFO] Opening browser to: {url}")
        webbrowser.open(url)
    except Exception as e:
        print(f"[WARN] Failed to open browser: {e}")
        print(f"[INFO] Please manually open: {get_app_url()}")

def setup_browser_opening(is_first_run):
    """Setup browser opening for first run"""
    if is_first_run and os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        print(f"\n[INFO] First run detected! Setup not complete.")
        print(f"[INFO] Server will start and browser will open automatically.")
        browser_thread = threading.Thread(target=open_browser_delayed, daemon=True)
        browser_thread.start()

# Update .env with missing variables on startup
update_env_with_missing_variables()

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

# Before request handler for setup completion and route protection
@app.before_request
def check_setup():
    """Check setup completion and handle route protection."""
    allowed_endpoints = {
        "setup", "setup_complete", "fetch_libraries_csrf_exempt", "static", 
        "ajax_check_rate_limit", "ajax_ip_management", "ajax_get_ip_lists", 
        "ajax_rate_limit_settings", "ajax_get_rate_limit_settings",
        "setup_poster_downloads_csrf_exempt", "setup_ip_management_csrf_exempt", 
        "setup_get_ip_lists_csrf_exempt", "clear_rate_limit"
    }
    
    # Cache setup completion check to avoid repeated config calls
    if not hasattr(check_setup, '_setup_complete_cache'):
        check_setup._setup_complete_cache = None
        check_setup._setup_cache_timestamp = 0
    
    current_time = time.time()
    # Cache setup completion for 30 seconds
    if (check_setup._setup_complete_cache is None or 
        current_time - check_setup._setup_cache_timestamp > 30):
        config = get_config()
        check_setup._setup_complete_cache = config.is_setup_complete()
        check_setup._setup_cache_timestamp = current_time
    
    if not check_setup._setup_complete_cache:
        if request.endpoint not in allowed_endpoints and not request.path.startswith("/static"):
            return redirect(url_for("setup"))

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
    
    # Exempt setup poster downloads from CSRF and rate limiting
    @app.route("/ajax/setup-poster-downloads", methods=["POST"])
    @csrf.exempt
    @limiter.exempt
    def setup_poster_downloads_csrf_exempt():
        """CSRF exempt version of setup poster downloads"""
        from routes.setup import setup_poster_downloads
        return setup_poster_downloads()
    
    # Exempt setup IP management from CSRF and rate limiting
    @app.route("/ajax/setup-ip-management", methods=["POST"])
    @csrf.exempt
    @limiter.exempt
    def setup_ip_management_csrf_exempt():
        """CSRF exempt version of setup IP management"""
        from routes.setup import setup_ip_management
        return setup_ip_management()
    
    # Exempt setup get IP lists from CSRF and rate limiting
    @app.route("/ajax/setup-get-ip-lists", methods=["GET"])
    @csrf.exempt
    @limiter.exempt
    def setup_get_ip_lists_csrf_exempt():
        """CSRF exempt version of setup get IP lists"""
        from routes.setup import setup_get_ip_lists
        return setup_get_ip_lists()
    
    # Exempt fetch-libraries from CSRF and rate limiting (used during setup)
    @app.route("/fetch-libraries", methods=["POST"])
    @csrf.exempt
    @limiter.exempt
    def fetch_libraries_csrf_exempt():
        """CSRF exempt version of fetch libraries"""
        try:
            data = request.get_json()
            plex_token = data.get("plex_token")
            plex_url = data.get("plex_url")
            
            if not plex_token or not plex_url:
                return jsonify({"error": "Plex token and URL are required"}), 400
            
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
            print(f"[ERROR] Error in fetch-libraries: {e}")
            return jsonify({"error": str(e)}), 500
    
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
    
    # Exempt poster endpoints from CSRF (for carousel functionality)
    @app.route("/ajax/get-random-posters", methods=["POST"])
    @csrf.exempt
    def get_random_posters_csrf_exempt():
        """CSRF exempt version of get random posters"""
        from routes.posters import get_random_posters
        return get_random_posters()
    
    @app.route("/ajax/get-random-posters-all", methods=["POST"])
    @csrf.exempt
    def get_random_posters_all_csrf_exempt():
        """CSRF exempt version of get random posters all"""
        from routes.posters import get_random_posters_all
        return get_random_posters_all()
    
    @app.route("/ajax/get-random-audiobook-posters", methods=["POST"])
    @csrf.exempt
    def get_random_audiobook_posters_csrf_exempt():
        """CSRF exempt version of get random audiobook posters"""
        from routes.posters import get_random_audiobook_posters
        return get_random_audiobook_posters()
    
    # Register admin routes
    register_admin_routes(app)
    

    
    print("[INFO] Successfully loaded ALL refactored routes - Phase 6 COMPLETED")
    
except ImportError as e:
    print(f"[ERROR] Failed to load refactored modules: {e}")
    print("[ERROR] Application cannot start without refactored modules")
    raise e

print("[INFO] All routes successfully loaded from refactored modules")
print("[INFO] No fallback to old_app.py needed - all functionality is now modularized")



if __name__ == '__main__':
    # Get port from environment (default to 10000 if not set)
    port = int(os.getenv('APP_PORT', 10000))
    
    # Check if this is the first run (setup not complete) - cache this check
    config = get_config()
    is_first_run = not config.is_setup_complete()
    
    # Setup browser opening for first run
    setup_browser_opening(is_first_run)
    
    print(f"[INFO] Starting Onboarderr on port {port}")
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