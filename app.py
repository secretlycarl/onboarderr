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
    

    
    print("[INFO] Successfully loaded ALL refactored routes - Phase 6 COMPLETED")
    
except ImportError as e:
    print(f"[ERROR] Failed to load refactored modules: {e}")
    print("[ERROR] Application cannot start without refactored modules")
    raise e

print("[INFO] All routes successfully loaded from refactored modules")
print("[INFO] No fallback to old_app.py needed - all functionality is now modularized")



if __name__ == '__main__':
    # Get port from environment (default to 42069 if not set)
    port = 42069
#        port = int(os.getenv('APP_PORT', 42069))
    
    print(f"[INFO] Starting Onboarderr on port {port}")
    print(f"[INFO] Phase 6: Final Route Extraction - COMPLETED")
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