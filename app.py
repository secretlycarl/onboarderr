# app.py
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, g
import json
from datetime import datetime
import requests
import xml.etree.ElementTree as ET
import os
from dotenv import load_dotenv, set_key
import random
import psutil
import time
from collections import defaultdict
import string
import re
from collections import defaultdict, OrderedDict
from flask_wtf.csrf import generate_csrf
from flask_wtf import CSRFProtect
import platform
import subprocess
import os
import signal
import threading
import time
import shutil
import secrets
import tempfile
import sys
from PIL import Image
import io
import webbrowser
from plexapi.server import PlexServer
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import queue
import hashlib
import base64
import hmac
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import yaml

# Before load_dotenv()
if not os.path.exists('.env') and os.path.exists('empty.env'):
    print('\n[WARN] .env file not found. Copying empty.env to .env for you.\n')
    shutil.copyfile('empty.env', '.env')

# Global poster download state
poster_download_queue = queue.Queue()
poster_download_lock = Lock()
poster_download_running = False
poster_download_progress = {}

def is_running_in_docker():
    """Detect if the application is running inside a Docker container"""
    try:
        with open('/proc/1/cgroup', 'r') as f:
            return any('docker' in line for line in f)
    except (FileNotFoundError, PermissionError):
        # Check for Docker environment variables
        return any(var in os.environ for var in ['DOCKER_CONTAINER', 'KUBERNETES_SERVICE_HOST'])

def load_locale(lang="en"):
    path = os.path.join("locales", f"{lang}.yaml")
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)

# Application configuration
APP_PORT = 10010

def get_app_url():
    """Determine the correct URL to open in browser"""
    port = APP_PORT
    
    # Check if we're in Docker
    if is_running_in_docker():
        # In Docker, we need to determine the external URL
        # This could be localhost if port is mapped, or a different host
        # For now, we'll use localhost as the most common case
        return f"http://localhost:{port}"
    else:
        # Native installation
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

# Ensure SECRET_KEY is set
def ensure_secret_key():
    env_path = '.env'
    with open(env_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    found = False
    for i, line in enumerate(lines):
        if line.strip().startswith('SECRET_KEY='):
            found = True
            if line.strip() == 'SECRET_KEY=' or line.strip() == 'SECRET_KEY=""':
                # Generate and set a new key
                new_key = secrets.token_urlsafe(48)
                lines[i] = f'SECRET_KEY={new_key}\n'
            break
    if not found:
        new_key = secrets.token_urlsafe(48)
        lines.append(f'SECRET_KEY={new_key}\n')
    with open(env_path, 'w', encoding='utf-8') as f:
        f.writelines(lines)

ensure_secret_key()
load_dotenv()
debug_mode = os.getenv("FLASK_DEBUG", "0") == "1"

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY") or os.urandom(24)
csrf = CSRFProtect(app)


# Plex details
PLEX_TOKEN = os.getenv("PLEX_TOKEN")
PLEX_URL = os.getenv("PLEX_URL")

@app.context_processor
def inject_server_name():
    return dict(
        SERVER_NAME=os.getenv("SERVER_NAME", "DefaultName"),
        ABS_ENABLED=os.getenv("ABS_ENABLED", "yes"),
        AUDIOBOOKSHELF_URL=os.getenv("AUDIOBOOKSHELF_URL", ""),
        ACCENT_COLOR=os.getenv("ACCENT_COLOR", "#d33fbc")
    )

@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)

@app.context_processor
def inject_admin_status():
    # Make sure session is available in context
    from flask import session
    return dict(
        is_admin=session.get("admin_authenticated", False),
        logo_filename=get_logo_filename(),
        wordmark_filename=get_wordmark_filename()
    )

@app.context_processor
def inject_favicon_timestamp():
    """Inject favicon timestamp to force browser cache updates"""
    favicon_path = os.path.join('static', 'favicon.webp')
    try:
        # Get file modification time as timestamp
        favicon_timestamp = int(os.path.getmtime(favicon_path))
    except (OSError, FileNotFoundError):
        # If favicon doesn't exist, use current time
        favicon_timestamp = int(time.time())
    return dict(favicon_timestamp=favicon_timestamp)

def get_plex_libraries():
    if debug_mode:
        print("DEBUG: PLEX_URL =", PLEX_URL)
    headers = {"X-Plex-Token": PLEX_TOKEN}
    url = f"{PLEX_URL}/library/sections"
    if debug_mode:
        print("DEBUG: url =", url)
    response = requests.get(url, headers=headers, timeout=5)
    response.raise_for_status()
    root = ET.fromstring(response.text)
    libraries = []
    for directory in root.findall(".//Directory"):
        title = directory.attrib.get("title")
        key = directory.attrib.get("key")
        media_type = directory.attrib.get("type")  # Get the media type (movie, show, artist, etc.)
        if title and key:
            libraries.append({
                "title": title, 
                "key": key, 
                "media_type": media_type
            })
    return libraries

# --- File read/write: always use utf-8 encoding and os.path.join ---
def load_library_notes():
    notes = load_json_file("library_notes.json", {})
    if debug_mode:
        print(f"[DEBUG] Loaded {len(notes)} library notes from file")
    return notes
    
    # Check if we need to fetch missing library titles
    library_ids = os.getenv("LIBRARY_IDS", "")
    if library_ids:
        selected_ids = [i.strip() for i in library_ids.split(",") if i.strip()]
        missing_titles = []
        
        for lib_id in selected_ids:
            if lib_id not in notes or not notes[lib_id].get('title') or notes[lib_id].get('title') == f"Unknown ({lib_id})":
                missing_titles.append(lib_id)
        
        if missing_titles:
            if debug_mode:
                print(f"[DEBUG] Found {len(missing_titles)} libraries with missing titles: {missing_titles}")
            # Try to fetch missing titles from Plex
            try:
                plex_token = os.getenv("PLEX_TOKEN")
                plex_url = os.getenv("PLEX_URL")
                if plex_token and plex_url:
                    headers = {"X-Plex-Token": plex_token}
                    url = f"{plex_url}/library/sections"
                    response = requests.get(url, headers=headers, timeout=5)
                    response.raise_for_status()
                    root = ET.fromstring(response.text)
                    id_to_title = {d.attrib.get("key"): d.attrib.get("title") for d in root.findall(".//Directory")}
                    
                    if debug_mode:
                        print(f"[DEBUG] Fetched {len(id_to_title)} libraries from Plex")
                    
                    # Update missing titles and media types
                    updated = False
                    for lib_id in missing_titles:
                        title = id_to_title.get(lib_id)
                        if title:
                            if lib_id not in notes:
                                notes[lib_id] = {}
                            notes[lib_id]['title'] = title
                            
                            # Also get the media type for this library
                            try:
                                # Get detailed info for this specific library
                                lib_url = f"{plex_url}/library/sections/{lib_id}"
                                lib_response = requests.get(lib_url, headers=headers, timeout=5)
                                if lib_response.status_code == 200:
                                    lib_root = ET.fromstring(lib_response.text)
                                    directory = lib_root.find(".//Directory")
                                    if directory is not None:
                                        media_type = directory.attrib.get("type")
                                        if media_type:
                                            notes[lib_id]['media_type'] = media_type
                                            if debug_mode:
                                                print(f"[DEBUG] Updated media type for library {lib_id}: {media_type}")
                            except Exception as e:
                                if debug_mode:
                                    print(f"[DEBUG] Failed to get media type for library {lib_id}: {e}")
                            
                            updated = True
                            if debug_mode:
                                print(f"[DEBUG] Updated title for library {lib_id}: {title}")
                    
                    # Save updated notes if we found any titles
                    if updated:
                        save_library_notes(notes)
                        if debug_mode:
                            print(f"[INFO] Updated {len([lib_id for lib_id in missing_titles if notes.get(lib_id, {}).get('title')])} library titles")
                    else:
                        if debug_mode:
                            print(f"[DEBUG] No library titles were found for the missing IDs")
                else:
                    if debug_mode:
                        print(f"[DEBUG] Plex token or URL not configured, cannot fetch titles")
            except Exception as e:
                if debug_mode:
                    print(f"[WARN] Failed to fetch missing library titles: {e}")
    
    return notes

def save_library_notes(notes):
    save_json_file("library_notes.json", notes)

def recreate_library_notes():
    """Update library notes on startup by fetching current library information from Plex, preserving existing descriptions"""
    try:
        plex_token = os.getenv("PLEX_TOKEN")
        plex_url = os.getenv("PLEX_URL")
        
        if not plex_token or not plex_url:
            if debug_mode:
                print("[DEBUG] Plex token or URL not configured, skipping library notes update")
            return
        
        if debug_mode:
            print("[INFO] Updating library notes from Plex API...")
        
        # Load existing library notes to preserve descriptions
        existing_notes = load_library_notes()
        
        headers = {"X-Plex-Token": plex_token}
        url = f"{plex_url}/library/sections"
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()
        root = ET.fromstring(response.text)
        
        updated_count = 0
        for directory in root.findall(".//Directory"):
            title = directory.attrib.get("title")
            key = directory.attrib.get("key")
            media_type = directory.attrib.get("type")
            
            if title and key:
                # Check if this library exists in our notes
                if key in existing_notes:
                    # Update existing entry, preserving description
                    existing_entry = existing_notes[key]
                    existing_entry["title"] = title
                    existing_entry["media_type"] = media_type
                    # Keep existing description if it exists
                    if debug_mode:
                        print(f"[DEBUG] Updated existing library: {title} (ID: {key}, Type: {media_type})")
                else:
                    # Create new entry
                    existing_notes[key] = {
                        "title": title,
                        "media_type": media_type
                    }
                    if debug_mode:
                        print(f"[DEBUG] Added new library: {title} (ID: {key}, Type: {media_type})")
                
                updated_count += 1
        
        # Save the updated library notes
        save_library_notes(existing_notes)
        
        if debug_mode:
            print(f"[INFO] Successfully updated library notes for {updated_count} libraries")
            
    except Exception as e:
        if debug_mode:
            print(f"[WARN] Failed to update library notes: {e}")

def safe_set_key(env_path, key, value):
    set_key(env_path, key, value, quote_mode="never")

def process_uploaded_logo(file):
    """Process uploaded logo file and create favicon"""
    if not file or file.filename == '':
        return False
    
    # Check file extension
    allowed_extensions = {'.png', '.webp', '.jpg', '.jpeg'}
    file_ext = os.path.splitext(file.filename)[1].lower()
    if file_ext not in allowed_extensions:
        return False
    
    try:
        # Open image with PIL
        img = Image.open(file.stream)
        
        # Handle different image modes properly
        if img.mode == 'P':
            # Convert palette images to RGBA to preserve transparency
            img = img.convert('RGBA')
        elif img.mode == 'LA':
            # Convert grayscale with alpha to RGBA
            img = img.convert('RGBA')
        elif img.mode == 'L':
            # Convert grayscale to RGB (no transparency)
            img = img.convert('RGB')
        elif img.mode == 'RGB':
            # RGB is fine as-is
            pass
        elif img.mode == 'RGBA':
            # RGBA is fine as-is (preserves transparency)
            pass
        else:
            # Convert any other modes to RGB
            img = img.convert('RGB')
        
        # Save logo based on original format
        logo_path = os.path.join('static', 'clearlogo.webp')
        if file_ext in ['.png', '.webp']:
            # For PNG and WebP, preserve original format and transparency
            if file_ext == '.png':
                logo_path = os.path.join('static', 'clearlogo.png')
                # Preserve transparency for PNG
                if img.mode == 'RGBA':
                    img.save(logo_path, 'PNG')
                else:
                    img.save(logo_path, 'PNG')
            else:  # .webp
                # Preserve transparency for WebP
                if img.mode == 'RGBA':
                    img.save(logo_path, 'WEBP', lossless=True)
                else:
                    img.save(logo_path, 'WEBP', quality=95)
        else:
            # For JPG/JPEG, convert to WebP (no transparency support)
            if img.mode == 'RGBA':
                # Convert RGBA to RGB for JPEG compatibility
                rgb_img = Image.new('RGB', img.size, (255, 255, 255))
                rgb_img.paste(img, mask=img.split()[-1])  # Use alpha channel as mask
                rgb_img.save(logo_path, 'WEBP', quality=95)
            else:
                img.save(logo_path, 'WEBP', quality=95)
        
        # Create favicon (32x32) - preserve transparency if available
        favicon = img.resize((32, 32), Image.Resampling.LANCZOS)
        favicon_path = os.path.join('static', 'favicon.webp')
        if favicon.mode == 'RGBA':
            favicon.save(favicon_path, 'WEBP', lossless=True)
        else:
            favicon.save(favicon_path, 'WEBP', quality=95)
        
        return True
    except Exception as e:
        if debug_mode:
            print(f"Error processing logo: {e}")
        return False

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

def process_uploaded_wordmark(file):
    """Process uploaded wordmark file"""
    if not file or file.filename == '':
        return False
    
    # Check file extension
    allowed_extensions = {'.png', '.webp', '.jpg', '.jpeg'}
    file_ext = os.path.splitext(file.filename)[1].lower()
    if file_ext not in allowed_extensions:
        return False
    
    try:
        # Open image with PIL
        img = Image.open(file.stream)
        
        # Handle different image modes properly
        if img.mode == 'P':
            # Convert palette images to RGBA to preserve transparency
            img = img.convert('RGBA')
        elif img.mode == 'LA':
            # Convert grayscale with alpha to RGBA
            img = img.convert('RGBA')
        elif img.mode == 'L':
            # Convert grayscale to RGB (no transparency)
            img = img.convert('RGB')
        elif img.mode == 'RGB':
            # RGB is fine as-is
            pass
        elif img.mode == 'RGBA':
            # RGBA is fine as-is (preserves transparency)
            pass
        else:
            # Convert any other modes to RGB
            img = img.convert('RGB')
        
        # Save wordmark based on original format
        wordmark_path = os.path.join('static', 'wordmark.webp')
        if file_ext in ['.png', '.webp']:
            # For PNG and WebP, preserve original format and transparency
            if file_ext == '.png':
                wordmark_path = os.path.join('static', 'wordmark.png')
                # Preserve transparency for PNG
                if img.mode == 'RGBA':
                    img.save(wordmark_path, 'PNG')
                else:
                    img.save(wordmark_path, 'PNG')
            else:  # .webp
                # Preserve transparency for WebP
                if img.mode == 'RGBA':
                    img.save(wordmark_path, 'WEBP', lossless=True)
                else:
                    img.save(wordmark_path, 'WEBP', quality=95)
        else:
            # For JPG/JPEG, convert to WebP (no transparency support)
            if img.mode == 'RGBA':
                # Convert RGBA to RGB for JPEG compatibility
                rgb_img = Image.new('RGB', img.size, (255, 255, 255))
                rgb_img.paste(img, mask=img.split()[-1])  # Use alpha channel as mask
                rgb_img.save(wordmark_path, 'WEBP', quality=95)
            else:
                img.save(wordmark_path, 'WEBP', quality=95)
        
        return True
    except Exception as e:
        if debug_mode:
            print(f"Error processing wordmark: {e}")
        return False


def send_discord_notification(email, service_type, event_type=None):
    """Send Discord notification for form submissions, respecting notification toggles"""
    # Notification toggles
    if event_type == "plex" and os.getenv("DISCORD_NOTIFY_PLEX", "1") != "1":
        return
    if event_type == "abs" and os.getenv("DISCORD_NOTIFY_ABS", "1") != "1":
        return
    webhook_url = os.getenv("DISCORD_WEBHOOK")
    if not webhook_url:
        return
    username = os.getenv("DISCORD_USERNAME", "Onboarderr")
    avatar_url = os.getenv("DISCORD_AVATAR", url_for('static', filename=get_logo_filename(), _external=True))
    color = os.getenv("DISCORD_COLOR", "#000000")
    payload = {
        "username": username,
        "embeds": [{
            "description": f"{email} has requested access to {service_type}",
            "color": int(color.lstrip('#'), 16) if color.startswith('#') else 0
        }]
    }
    if avatar_url:
        payload["avatar_url"] = avatar_url
    try:
        requests.post(webhook_url, json=payload, timeout=5)
    except Exception as e:
        if debug_mode:
            print(f"Failed to send Discord notification: {e}")

def create_abs_user(username, password, user_type="user", permissions=None):
    """Create a user in Audiobookshelf using the API"""
    abs_url = os.getenv("AUDIOBOOKSHELF_URL")
    abs_token = os.getenv("AUDIOBOOKSHELF_TOKEN")
    
    if not abs_url:
        return {"success": False, "error": "Audiobookshelf URL not configured"}
    
    if not abs_token:
        return {"success": False, "error": "Audiobookshelf API token not configured"}
    
    # Validate inputs
    if not username or not password:
        return {"success": False, "error": "Username and password are required"}
    
    if user_type not in ["user", "admin", "guest"]:
        return {"success": False, "error": "Invalid user type. Must be 'user', 'admin', or 'guest'"}
    
    # Default permissions based on user type
    if permissions is None:
        if user_type == "admin":
            permissions = {
                "download": True,
                "update": True,
                "delete": True,
                "upload": True,
                "accessAllLibraries": True,
                "accessAllTags": True,
                "accessExplicitContent": True
            }
        elif user_type == "user":
            permissions = {
                "download": True,
                "update": True,
                "delete": False,
                "upload": False,
                "accessAllLibraries": True,
                "accessAllTags": True,
                "accessExplicitContent": True
            }
        else:  # guest
            permissions = {
                "download": False,
                "update": False,
                "delete": False,
                "upload": False,
                "accessAllLibraries": True,
                "accessAllTags": True,
                "accessExplicitContent": False
            }
    
    # Prepare the user data
    user_data = {
        "username": username,
        "password": password,
        "type": user_type,
        "permissions": permissions,
        "librariesAccessible": [],
        "itemTagsAccessible": [],
        "isActive": True,
        "isLocked": False
    }
    
    try:
        headers = {
            "Authorization": f"Bearer {abs_token}",
            "Content-Type": "application/json"
        }
        
        response = requests.post(
            f"{abs_url}/api/users",
            headers=headers,
            json=user_data,
            timeout=10
        )
        
        if response.status_code == 200:
            user_info = response.json()
            return {
                "success": True,
                "user_id": user_info.get("id"),
                "username": username,
                "email": "",  # Will be filled by caller
                "message": "User created successfully"
            }
        elif response.status_code == 500:
            # Check if it's a username already taken error
            try:
                error_data = response.json()
                if "username" in error_data.get("error", "").lower():
                    return {
                        "success": False,
                        "username": username,
                        "email": "",  # Will be filled by caller
                        "error": "Username already exists"
                    }
            except:
                pass
            return {
                "success": False,
                "username": username,
                "email": "",  # Will be filled by caller
                "error": f"Server error: {response.text}"
            }
        else:
            error_msg = "Unknown error"
            try:
                error_data = response.json()
                error_msg = error_data.get("error", error_data.get("message", "Unknown error"))
            except:
                error_msg = f"HTTP {response.status_code}: {response.text}"
            
            return {
                "success": False,
                "username": username,
                "email": "",  # Will be filled by caller
                "error": error_msg
            }
            
    except requests.exceptions.RequestException as e:
        return {
            "success": False,
            "username": username,
            "email": "",  # Will be filled by caller
            "error": f"Connection error: {str(e)}"
        }
    except Exception as e:
        return {
            "success": False,
            "username": username,
            "email": "",  # Will be filled by caller
            "error": f"Unexpected error: {str(e)}"
        }

@app.route("/onboarding", methods=["GET", "POST"])
def onboarding():
    if not session.get("authenticated"):
        return redirect(url_for("login"))
    
    lang = request.args.get("lang") or session.get("lang", "en")
    session["lang"] = lang

    # 2. Carica il file YAML della lingua scelta
    t = load_locale(lang)
    
    submitted = False
    library_notes = load_library_notes()
    selected_ids = os.getenv("LIBRARY_IDS", "").split(",") if os.getenv("LIBRARY_IDS") else []

    if request.method == "POST":
        email = request.form.get("email")
        selected_keys = request.form.getlist("libraries")
        explicit_content = request.form.get("explicit_content") == "yes"

        if email and selected_keys:
            all_libraries = get_plex_libraries()
            key_to_title = {lib["key"]: lib["title"] for lib in all_libraries}
            selected_titles = [key_to_title.get(key, f"Unknown ({key})") for key in selected_keys]
            submission_entry = {
                "email": email,
                "libraries_keys": selected_keys,
                "libraries_titles": selected_titles,
                "explicit_content": explicit_content,
                "submitted_at": datetime.utcnow().isoformat() + "Z"
            }
            submissions = load_json_file("plex_submissions.json", [])
            submissions.append(submission_entry)
            save_json_file("plex_submissions.json", submissions)
            submitted = True
            send_discord_notification(email, "Plex", event_type="plex")
            # AJAX response
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"success": True})
        # AJAX error response
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": False, "error": "Missing required fields."})

    try:
        libraries = [lib for lib in get_plex_libraries() if lib["key"] in selected_ids]
    except Exception as e:
        if debug_mode:
            print(f"Failed to get Plex libraries: {e}")
        libraries = []

    # Build static poster URLs for each library (limit to 10 per library)
    library_posters = {}
    poster_imdb_ids = {}
    for lib in libraries:
        section_id = lib["key"]
        name = lib["title"]
        poster_dir = os.path.join("static", "posters", section_id)
        posters = []
        imdb_ids = []
        
        try:
            if os.path.exists(poster_dir):
                # Get all image files efficiently
                all_files = [f for f in os.listdir(poster_dir) if f.lower().endswith(('.webp', '.jpg', '.jpeg', '.png'))]
                
                # Sort by modification time to get most recent first
                all_files.sort(key=lambda f: os.path.getmtime(os.path.join(poster_dir, f)), reverse=True)
                
                # Limit to 10 random posters per library for initial load
                if len(all_files) > 10:
                    limited_files = random.sample(all_files, 10)
                else:
                    limited_files = all_files
                
                for fname in limited_files:
                    posters.append(f"/static/posters/{section_id}/{fname}")
                    
                    # Load metadata efficiently
                    json_path = os.path.join(poster_dir, fname.rsplit('.', 1)[0] + '.json')
                    imdb_id = None
                    try:
                        if os.path.exists(json_path):
                            with open(json_path, 'r', encoding='utf-8') as f:
                                meta = json.load(f)
                                imdb_id = meta.get('imdb')
                    except (IOError, json.JSONDecodeError):
                        # Skip corrupted metadata files
                        pass
                    
                    imdb_ids.append(imdb_id)
        except OSError as e:
            if debug_mode:
                print(f"Error loading posters for library {name}: {e}")
            # Continue with empty posters list
        
        library_posters[name] = posters
        poster_imdb_ids[name] = imdb_ids

    pulsarr_enabled = bool(os.getenv("PULSARR"))
    overseerr_enabled = bool(os.getenv("OVERSEERR"))
    overseerr_url = os.getenv("OVERSEERR", "")
    tautulli_enabled = bool(os.getenv("TAUTULLI"))
    
    # Get default library setting
    default_library = os.getenv("DEFAULT_LIBRARY", "all")
    
    # Get all libraries to map numbers to names
    all_libraries = get_plex_libraries()
    library_map = {lib["key"]: lib["title"] for lib in all_libraries}
    
    # Check if any library has media_type of "artist" (music)
    # Only check currently available libraries that are actually shown in the UI
    has_music_library = any(lib.get("media_type") == "artist" for lib in libraries)
    
    if debug_mode:
        print(f"[DEBUG] Music library check: {has_music_library}")
        print(f"[DEBUG] Total libraries from Plex API: {len(all_libraries)}")
        print(f"[DEBUG] Libraries shown in UI: {len(libraries)}")
        print(f"[DEBUG] All libraries from Plex API:")
        for lib in all_libraries:
            print(f"[DEBUG]   - {lib['title']} (ID: {lib['key']}, type: {lib.get('media_type', 'unknown')})")
        print(f"[DEBUG] Libraries shown in UI:")
        for lib in libraries:
            print(f"[DEBUG]   - {lib['title']} (ID: {lib['key']}, type: {lib.get('media_type', 'unknown')})")
            if lib.get("media_type") == "artist":
                print(f"[DEBUG] Found music library in UI: {lib['title']} (ID: {lib['key']})")
        # Also check library_notes.json for comparison
        library_notes = load_library_notes()
        music_in_notes = [lib_id for lib_id, note in library_notes.items() 
                         if note.get('media_type') == 'artist']
        if music_in_notes:
            print(f"[DEBUG] Music libraries in library_notes.json: {music_in_notes}")
            for lib_id in music_in_notes:
                if lib_id not in [lib['key'] for lib in all_libraries]:
                    print(f"[DEBUG] Music library {lib_id} exists in notes but not in current Plex API")
    
    # Determine which library should be default
    default_library_name = "random-all"  # Default to random-all
    if default_library != "all":
        try:
            # Parse comma-separated library numbers
            library_numbers = [num.strip() for num in default_library.split(",")]
            # Use the first valid library number
            for lib_num in library_numbers:
                if lib_num in library_map:
                    default_library_name = library_map[lib_num]
                    break
        except Exception as e:
            if debug_mode:
                print(f"Error parsing DEFAULT_LIBRARY: {e}")

    # Get public services data for icons (end user services only)
    services = build_public_services_data()
    
    return render_template(
        "onboarding.html",
        libraries=libraries,
        submitted=submitted,
        library_notes=library_notes,
        pulsarr_enabled=pulsarr_enabled,
        overseerr_enabled=overseerr_enabled,
        overseerr_url=overseerr_url,
        tautulli_enabled=tautulli_enabled,
        library_posters=library_posters,
        poster_imdb_ids=poster_imdb_ids,
        default_library=default_library_name,
        has_music_library=has_music_library,
        services=services,
        t=t,
    	lang=lang
    )

@app.route("/audiobookshelf", methods=["GET", "POST"])
def audiobookshelf():
    if os.getenv("ABS_ENABLED", "yes") != "yes":
        return ("Not Found", 404)
    if not session.get("authenticated"):
        return redirect(url_for("login"))

    submitted = False

    if request.method == "POST":
        email = request.form.get("email")
        username = request.form.get("username")
        password = request.form.get("password")

        if email and username and password:
            submission_entry = {
                "email": email,
                "username": username,
                "password": password,
                "submitted_at": datetime.utcnow().isoformat() + "Z"
            }
            submissions = load_json_file("audiobookshelf_submissions.json", [])
            submissions.append(submission_entry)
            save_json_file("audiobookshelf_submissions.json", submissions)
            submitted = True
            send_discord_notification(email, "Audiobookshelf", event_type="abs")
            # AJAX response
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"success": True})
        # AJAX error response
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": False, "error": "Missing required fields."})

    # List all covers in static/posters/audiobooks/
    abs_covers = []
    audiobook_dir = os.path.join("static", "posters", "audiobooks")
    if os.path.exists(audiobook_dir):
        for fname in sorted(os.listdir(audiobook_dir)):
            if fname.lower().endswith(('.webp', '.jpg', '.jpeg', '.png')):
                abs_covers.append(f"/static/posters/audiobooks/{fname}")

    tautulli_enabled = bool(os.getenv("TAUTULLI"))
    
    return render_template(
        "audiobookshelf.html",
        submitted=submitted,
        abs_covers=abs_covers,
        tautulli_enabled=tautulli_enabled,
    )

# Add this helper at the top (after imports)
def is_setup_complete():
    return os.getenv("SETUP_COMPLETE", "0") == "1"

# Update login route to check setup status
@app.route("/login", methods=["GET", "POST"])
def login():
    if not is_setup_complete():
        return redirect(url_for("setup"))
    if request.method == "POST":
        entered_password = request.form.get("password")
        # Always reload from .env
        from dotenv import load_dotenv
        load_dotenv(override=True)
        
        # Get hashed passwords and salts
        admin_password_hash = os.getenv("ADMIN_PASSWORD_HASH")
        admin_password_salt = os.getenv("ADMIN_PASSWORD_SALT")
        site_password_hash = os.getenv("SITE_PASSWORD_HASH")
        site_password_salt = os.getenv("SITE_PASSWORD_SALT")
        
        # For backward compatibility, check plain text passwords if hashes don't exist
        admin_password_plain = os.getenv("ADMIN_PASSWORD")
        site_password_plain = os.getenv("SITE_PASSWORD")
        
        # Check admin password
        admin_authenticated = False
        if admin_password_hash and admin_password_salt:
            admin_authenticated = verify_password(entered_password, admin_password_salt, admin_password_hash)
        elif admin_password_plain:
            # Fallback to plain text for backward compatibility
            admin_authenticated = (entered_password == admin_password_plain)
        
        # Check site password
        site_authenticated = False
        if site_password_hash and site_password_salt:
            site_authenticated = verify_password(entered_password, site_password_salt, site_password_hash)
        elif site_password_plain:
            # Fallback to plain text for backward compatibility
            site_authenticated = (entered_password == site_password_plain)

        if admin_authenticated:
            session["authenticated"] = True
            session["admin_authenticated"] = True
            return redirect(url_for("services"))
        elif site_authenticated:
            session["authenticated"] = True
            session["admin_authenticated"] = False
            return redirect(url_for("onboarding"))
        else:
            return render_template("login.html", error="Incorrect password")

    return render_template("login.html")

@app.route("/services", methods=["GET", "POST"])
def services():
    if not session.get("admin_authenticated"):
        return redirect(url_for("login"))

    # Handle admin settings form POST
    if request.method == "POST" and (
        "server_name" in request.form or
        "plex_token" in request.form or
        "plex_url" in request.form or
        "audiobooks_id" in request.form or
        "abs_enabled" in request.form or
        "discord_webhook" in request.form or
        "discord_notify_plex" in request.form or
        "discord_notify_abs" in request.form or
        "library_ids" in request.form or
        "audiobookshelf_url" in request.form or
        "accent_color" in request.form or
        "logo_file" in request.files or
        "wordmark_file" in request.files
    ):
        env_path = os.path.join(os.getcwd(), ".env")
        
        # Handle file uploads
        logo_file = request.files.get('logo_file')
        wordmark_file = request.files.get('wordmark_file')
        
        if logo_file and logo_file.filename:
            if not process_uploaded_logo(logo_file):
                # Get all the necessary data for the template
                context = get_template_context()
                
                context["error_message"] = "Failed to process logo file. Please ensure it's a valid image file (.png, .webp, .jpg, .jpeg)."
                return render_template("services.html", **context)
        
        if wordmark_file and wordmark_file.filename:
            if not process_uploaded_wordmark(wordmark_file):
                # Similar error handling for wordmark
                context = get_template_context()
                context["error_message"] = "Failed to process wordmark file. Please ensure it's a valid image file (.png, .webp, .jpg, .jpeg)."
                return render_template("services.html", **context)
        
        # Update .env with any non-empty fields (only if they changed)
        for field in ["server_name", "plex_url", "audiobooks_id"]:
            value = request.form.get(field, "").strip()
            current_value = os.getenv(field.upper(), "")
            if value != current_value:
                safe_set_key(env_path, field.upper(), value)
        
        # Handle Plex token with hashing
        plex_token = request.form.get("plex_token", "").strip()
        if plex_token:
            save_api_key_with_hash(env_path, "PLEX_TOKEN", plex_token)

        # Handle Audiobookshelf fields
        audiobooks_id = request.form.get("audiobooks_id", "").strip()
        audiobookshelf_url = request.form.get("audiobookshelf_url", "").strip()
        audiobookshelf_token = request.form.get("audiobookshelf_token", "").strip()

        abs_enabled = request.form.get("abs_enabled")
        current_abs = os.getenv("ABS_ENABLED", "no")

        if not audiobooks_id and not audiobookshelf_url and not audiobookshelf_token:
            # If all Audiobookshelf fields are empty, set ABS_ENABLED to 'no' and clear other ABS fields
            safe_set_key(env_path, "ABS_ENABLED", "no")
            safe_set_key(env_path, "AUDIOBOOKS_ID", "")
            safe_set_key(env_path, "AUDIOBOOKSHELF_URL", "")
            save_api_key_with_hash(env_path, "AUDIOBOOKSHELF_TOKEN", "")
        else:
            # If any Audiobookshelf field is filled, set ABS_ENABLED to 'yes'
            safe_set_key(env_path, "ABS_ENABLED", "yes")
            if audiobooks_id:
                safe_set_key(env_path, "AUDIOBOOKS_ID", audiobooks_id)
            if audiobookshelf_url:
                safe_set_key(env_path, "AUDIOBOOKSHELF_URL", audiobookshelf_url)
            if audiobookshelf_token:
                save_api_key_with_hash(env_path, "AUDIOBOOKSHELF_TOKEN", audiobookshelf_token)

        # ABS enabled/disabled
        if abs_enabled in ["yes", "no"] and abs_enabled != current_abs:
            safe_set_key(env_path, "ABS_ENABLED", "yes" if abs_enabled == "yes" else "no")
        # Library IDs (checkboxes)
        library_ids = request.form.getlist("library_ids")
        current_library_ids = os.getenv("LIBRARY_IDS", "")
        if library_ids and ",".join(library_ids) != current_library_ids:
            safe_set_key(env_path, "LIBRARY_IDS", ",".join(library_ids))
        # Library descriptions (optional)
        library_notes = {}
        for lib_id in library_ids:
            desc = request.form.get(f"library_desc_{lib_id}", "").strip()
            if desc:
                library_notes[lib_id] = {"description": desc}
        if library_notes:
            with open(os.path.join(os.getcwd(), "library_notes.json"), "w", encoding="utf-8") as f:
                json.dump(library_notes, f, indent=2)
        # Discord settings
        discord_webhook = request.form.get("discord_webhook", "").strip()
        current_webhook = os.getenv("DISCORD_WEBHOOK", "")
        if discord_webhook != current_webhook:
            safe_set_key(env_path, "DISCORD_WEBHOOK", discord_webhook)
        
        discord_username = request.form.get("discord_username", "").strip()
        current_username = os.getenv("DISCORD_USERNAME", "")
        if discord_username != current_username:
            safe_set_key(env_path, "DISCORD_USERNAME", discord_username)
        
        discord_avatar = request.form.get("discord_avatar", "").strip()
        current_avatar = os.getenv("DISCORD_AVATAR", "")
        if discord_avatar != current_avatar:
            safe_set_key(env_path, "DISCORD_AVATAR", discord_avatar)
        
        discord_color = request.form.get("discord_color", "").strip()
        current_color = os.getenv("DISCORD_COLOR", "")
        if discord_color != current_color:
            safe_set_key(env_path, "DISCORD_COLOR", discord_color)
        
        # Update service URLs if changed
        service_defs = get_service_definitions()
        for name, env, logo in service_defs:
            url = request.form.get(env, None)
            if url is not None:
                url = url.strip()
                current_url = os.getenv(env, "")
                if url != current_url:
                    safe_set_key(env_path, env, url)

        # Read new notification toggles
        discord_notify_plex = request.form.get("discord_notify_plex")
        # If checkbox is unchecked, it won't be in form data, so treat as "0"
        if discord_notify_plex is None:
            discord_notify_plex = "0"
        current_discord_notify_plex = os.getenv("DISCORD_NOTIFY_PLEX", "1")
        if discord_notify_plex in ["1", "0"] and discord_notify_plex != current_discord_notify_plex:
            safe_set_key(env_path, "DISCORD_NOTIFY_PLEX", discord_notify_plex)

        discord_notify_abs = request.form.get("discord_notify_abs")
        # If checkbox is unchecked, it won't be in form data, so treat as "0"
        if discord_notify_abs is None:
            discord_notify_abs = "0"
        current_discord_notify_abs = os.getenv("DISCORD_NOTIFY_ABS", "1")
        if discord_notify_abs in ["1", "0"] and discord_notify_abs != current_discord_notify_abs:
            safe_set_key(env_path, "DISCORD_NOTIFY_ABS", discord_notify_abs)

        # Handle password fields
        site_password = request.form.get("site_password", "").strip()
        admin_password = request.form.get("admin_password", "").strip()
        if site_password:
            # Hash the site password
            site_salt, site_hash = hash_password(site_password)
            safe_set_key(env_path, "SITE_PASSWORD_HASH", site_hash)
            safe_set_key(env_path, "SITE_PASSWORD_SALT", site_salt)
            # Keep plain text for backward compatibility
            safe_set_key(env_path, "SITE_PASSWORD", site_password)
        if admin_password:
            # Hash the admin password
            admin_salt, admin_hash = hash_password(admin_password)
            safe_set_key(env_path, "ADMIN_PASSWORD_HASH", admin_hash)
            safe_set_key(env_path, "ADMIN_PASSWORD_SALT", admin_salt)
            # Keep plain text for backward compatibility
            safe_set_key(env_path, "ADMIN_PASSWORD", admin_password)

        # Handle accent color
        accent_color = request.form.get("accent_color_text", "").strip()
        current_accent_color = os.getenv("ACCENT_COLOR", "")
        if accent_color and accent_color != current_accent_color:
            safe_set_key(env_path, "ACCENT_COLOR", accent_color)

        # Trigger background poster refresh if library settings changed
        library_ids = request.form.getlist("library_ids")
        current_library_ids = os.getenv("LIBRARY_IDS", "")
        if library_ids and ",".join(library_ids) != current_library_ids:
            # Library selection changed, trigger poster refresh
            refresh_posters_on_demand()

        return redirect(url_for("setup_complete"))

    # Handle Plex/Audiobookshelf request deletion
    if request.method == "POST":
        delete_index = int(request.form.get("delete_index", -1))
        if delete_index >= 0:
            try:
                submissions = load_json_file("plex_submissions.json", [])
                if 0 <= delete_index < len(submissions):
                    del submissions[delete_index]
                    save_json_file("plex_submissions.json", submissions)
            except Exception as e:
                if debug_mode:
                    print(f"Error deleting submission: {e}")
        audiobookshelf_delete_index = request.form.get("audiobookshelf_delete_index")
        if audiobookshelf_delete_index is not None:
            try:
                audiobookshelf_delete_index = int(audiobookshelf_delete_index)
                audiobookshelf_submissions = load_json_file("audiobookshelf_submissions.json", [])
                if 0 <= audiobookshelf_delete_index < len(audiobookshelf_submissions):
                    del audiobookshelf_submissions[audiobookshelf_delete_index]
                    save_json_file("audiobookshelf_submissions.json", audiobookshelf_submissions)
            except Exception as e:
                if debug_mode:
                    print(f"Error deleting audiobookshelf submission: {e}")

        # Handle ABS user creation
        if "create_abs_users" in request.form:
            try:
                # Load current submissions
                audiobookshelf_submissions = load_json_file("audiobookshelf_submissions.json", [])
                
                # Get form data
                selected_indices = request.form.getlist("create_users")
                user_type = request.form.get("user_type", "user")
                selected_permissions = request.form.getlist("permissions")
                
                # Build permissions object
                permissions = {
                    "download": "download" in selected_permissions,
                    "update": "update" in selected_permissions,
                    "delete": "delete" in selected_permissions,
                    "upload": "upload" in selected_permissions,
                    "accessAllLibraries": "accessAllLibraries" in selected_permissions,
                    "accessAllTags": "accessAllTags" in selected_permissions,
                    "accessExplicitContent": "accessExplicitContent" in selected_permissions
                }
                
                # Create users
                creation_results = []
                for index_str in selected_indices:
                    try:
                        index = int(index_str)
                        if 0 <= index < len(audiobookshelf_submissions):
                            submission = audiobookshelf_submissions[index]
                            result = create_abs_user(
                                username=submission["username"],
                                password=submission["password"],
                                user_type=user_type,
                                permissions=permissions
                            )
                            result["email"] = submission["email"]
                            creation_results.append(result)
                            
                            # If successful, remove from submissions
                            if result["success"]:
                                del audiobookshelf_submissions[index]
                                # Update the file
                                save_json_file("audiobookshelf_submissions.json", audiobookshelf_submissions)
                    except Exception as e:
                        if debug_mode:
                            print(f"Error creating ABS user for index {index_str}: {e}")
                        creation_results.append({
                            "success": False,
                            "username": "Unknown",
                            "email": "Unknown",
                            "error": f"Error processing submission: {str(e)}"
                        })
                
                # Load all necessary data for template
                context = get_template_context()
                
                context["abs_user_creation_results"] = creation_results
                return render_template("services.html", **context)
                
            except Exception as e:
                if debug_mode:
                    print(f"Error in ABS user creation: {e}")
                # Continue to normal template rendering with error

    # Get template context
    context = get_template_context()
    
    # Handle Plex user invitation (parallel to ABS user creation)
    if request.method == "POST" and "invite_plex_users" in request.form:
        try:
            plex_submissions = load_json_file("plex_submissions.json", [])
        except FileNotFoundError:
            plex_submissions = []
        selected_indices = request.form.getlist("invite_users")
        invite_results = []
        # Invite each selected user
        for index_str in selected_indices:
            try:
                index = int(index_str)
                if 0 <= index < len(plex_submissions):
                    submission = plex_submissions[index]
                    email = submission["email"]
                    libraries_titles = submission.get("libraries_titles", [])
                    result = invite_plex_user(email, libraries_titles)
                    invite_results.append(result)
                    # If successful, remove from submissions
                    if result["success"]:
                        del plex_submissions[index]
                        save_json_file("plex_submissions.json", plex_submissions)
            except Exception as e:
                invite_results.append({"success": False, "email": "Unknown", "error": f"Error processing submission: {str(e)}"})
        # Load all necessary data for template
        context = get_template_context()
        context["submissions"] = plex_submissions
        context["plex_invite_results"] = invite_results
        return render_template("services.html", **context)

    context["abs_user_creation_results"] = None  # Will be populated if user creation was attempted
    return render_template("services.html", **context)

@app.route("/fetch-libraries", methods=["POST"])
def fetch_libraries():
    data = request.get_json()
    plex_token = data.get("plex_token")
    plex_url = data.get("plex_url")
    
    if not plex_token or not plex_url:
        return jsonify({"error": "Plex token and URL are required"})
    
    try:
        headers = {"X-Plex-Token": plex_token}
        url = f"{plex_url}/library/sections"
        response = requests.get(url, headers=headers, timeout=5)
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
        return jsonify({"libraries": libraries})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/ajax/delete-plex-request", methods=["POST"])
def ajax_delete_plex_request():
    if not session.get("admin_authenticated"):
        return jsonify({"success": False, "error": "Unauthorized"})
    
    try:
        data = request.get_json()
        delete_index = data.get("delete_index")
        
        if delete_index is None:
            return jsonify({"success": False, "error": "Missing delete_index"})
        
        delete_index = int(delete_index)
        submissions = load_json_file("plex_submissions.json", [])
        
        if 0 <= delete_index < len(submissions):
            del submissions[delete_index]
            save_json_file("plex_submissions.json", submissions)
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": "Invalid index"})
    except Exception as e:
        if debug_mode:
            print(f"Error deleting Plex submission: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route("/ajax/delete-abs-request", methods=["POST"])
def ajax_delete_abs_request():
    if not session.get("admin_authenticated"):
        return jsonify({"success": False, "error": "Unauthorized"})
    
    try:
        data = request.get_json()
        delete_index = data.get("delete_index")
        
        if delete_index is None:
            return jsonify({"success": False, "error": "Missing delete_index"})
        
        delete_index = int(delete_index)
        audiobookshelf_submissions = load_json_file("audiobookshelf_submissions.json", [])
        
        if 0 <= delete_index < len(audiobookshelf_submissions):
            del audiobookshelf_submissions[delete_index]
            save_json_file("audiobookshelf_submissions.json", audiobookshelf_submissions)
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": "Invalid index"})
    except Exception as e:
        if debug_mode:
            print(f"Error deleting Audiobookshelf submission: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route("/ajax/invite-plex-users", methods=["POST"])
def ajax_invite_plex_users():
    if not session.get("admin_authenticated"):
        return jsonify({"success": False, "error": "Unauthorized"})
    
    try:
        data = request.get_json()
        selected_indices = data.get("selected_indices", [])
        
        if not selected_indices:
            return jsonify({"success": False, "error": "No users selected"})
        
        plex_submissions = load_json_file("plex_submissions.json", [])
        invite_results = []
        
        # Sort indices in descending order to avoid index shifting issues
        selected_indices.sort(reverse=True)
        
        for index in selected_indices:
            try:
                if 0 <= index < len(plex_submissions):
                    submission = plex_submissions[index]
                    email = submission["email"]
                    libraries_titles = submission.get("libraries_titles", [])
                    result = invite_plex_user(email, libraries_titles)
                    result["email"] = email
                    invite_results.append(result)
                    
                    # If successful, remove from submissions
                    if result["success"]:
                        del plex_submissions[index]
                else:
                    invite_results.append({
                        "success": False, 
                        "email": "Unknown", 
                        "error": "Invalid index"
                    })
            except Exception as e:
                invite_results.append({
                    "success": False, 
                    "email": "Unknown", 
                    "error": f"Error processing submission: {str(e)}"
                })
        
        # Save updated submissions
        save_json_file("plex_submissions.json", plex_submissions)
        
        return jsonify({
            "success": True,
            "results": invite_results
        })
        
    except Exception as e:
        if debug_mode:
            print(f"Error in Plex user invitation: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route("/ajax/create-abs-users", methods=["POST"])
def ajax_create_abs_users():
    if not session.get("admin_authenticated"):
        return jsonify({"success": False, "error": "Unauthorized"})
    
    try:
        data = request.get_json()
        selected_indices = data.get("selected_indices", [])
        user_type = data.get("user_type", "user")
        selected_permissions = data.get("permissions", [])
        
        if not selected_indices:
            return jsonify({"success": False, "error": "No users selected"})
        
        # Build permissions object
        permissions = {
            "download": "download" in selected_permissions,
            "update": "update" in selected_permissions,
            "delete": "delete" in selected_permissions,
            "upload": "upload" in selected_permissions,
            "accessAllLibraries": "accessAllLibraries" in selected_permissions,
            "accessAllTags": "accessAllTags" in selected_permissions,
            "accessExplicitContent": "accessExplicitContent" in selected_permissions
        }
        
        audiobookshelf_submissions = load_json_file("audiobookshelf_submissions.json", [])
        creation_results = []
        
        # Sort indices in descending order to avoid index shifting issues
        selected_indices.sort(reverse=True)
        
        for index in selected_indices:
            try:
                if 0 <= index < len(audiobookshelf_submissions):
                    submission = audiobookshelf_submissions[index]
                    result = create_abs_user(
                        username=submission["username"],
                        password=submission["password"],
                        user_type=user_type,
                        permissions=permissions
                    )
                    result["email"] = submission["email"]
                    creation_results.append(result)
                    
                    # If successful, remove from submissions
                    if result["success"]:
                        del audiobookshelf_submissions[index]
                else:
                    creation_results.append({
                        "success": False,
                        "username": "Unknown",
                        "email": "Unknown",
                        "error": "Invalid index"
                    })
            except Exception as e:
                creation_results.append({
                    "success": False,
                    "username": "Unknown",
                    "email": "Unknown",
                    "error": f"Error processing submission: {str(e)}"
                })
        
        # Save updated submissions
        save_json_file("audiobookshelf_submissions.json", audiobookshelf_submissions)
        
        return jsonify({
            "success": True,
            "results": creation_results
        })
        
    except Exception as e:
        if debug_mode:
            print(f"Error in ABS user creation: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route("/ajax/poster-progress", methods=["GET"])
def ajax_poster_progress():
    """Get poster download progress for admin interface"""
    if not session.get("admin_authenticated"):
        return jsonify({"success": False, "error": "Unauthorized"})
    
    try:
        progress = get_poster_download_progress()
        return jsonify({
            "success": True,
            "progress": progress,
            "worker_running": poster_download_running
        })
    except Exception as e:
        if debug_mode:
            print(f"Error getting poster progress: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route("/refresh-library-titles", methods=["POST"])
def refresh_library_titles():
    if not session.get("admin_authenticated"):
        return jsonify({"success": False, "error": "Unauthorized"})
    
    try:
        # Get current library notes
        library_notes = load_library_notes()
        
        # Get selected library IDs
        library_ids = os.getenv("LIBRARY_IDS", "")
        if not library_ids:
            return jsonify({"success": False, "error": "No libraries selected"})
        
        selected_ids = [i.strip() for i in library_ids.split(",") if i.strip()]
        
        # Fetch current titles from Plex
        plex_token = os.getenv("PLEX_TOKEN")
        plex_url = os.getenv("PLEX_URL")
        
        if not plex_token or not plex_url:
            return jsonify({"success": False, "error": "Plex token or URL not configured"})
        
        headers = {"X-Plex-Token": plex_token}
        url = f"{plex_url}/library/sections"
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()
        root = ET.fromstring(response.text)
        id_to_title = {d.attrib.get("key"): d.attrib.get("title") for d in root.findall(".//Directory")}
        
        # Update library notes with current titles
        updated = False
        for lib_id in selected_ids:
            title = id_to_title.get(lib_id)
            if title:
                if lib_id not in library_notes:
                    library_notes[lib_id] = {}
                library_notes[lib_id]['title'] = title
                updated = True
        
        if updated:
            save_library_notes(library_notes)
            if debug_mode:
                print(f"[INFO] Refreshed {len([lib_id for lib_id in selected_ids if library_notes.get(lib_id, {}).get('title')])} library titles")
        
        return jsonify({"success": True})
        
    except Exception as e:
        if debug_mode:
            print(f"[ERROR] Failed to refresh library titles: {e}")
        return jsonify({"success": False, "error": str(e)})

# --- Use os.path.join for all file paths ---
def download_and_cache_posters():
    headers = {'X-Plex-Token': PLEX_TOKEN}
    audiobook_dir = os.path.join("static", "posters", "audiobooks")
    os.makedirs(audiobook_dir, exist_ok=True)

    def save_images(section_id, out_dir, tag, limit):
        url = f"{PLEX_URL}/library/sections/{section_id}/all"
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            if debug_mode:
                print(f"Failed to fetch from section {section_id}")
            return

        root = ET.fromstring(response.content)
        posters = []
        if section_id == AUDIOBOOKS_SECTION_ID:
            if os.getenv("ABS_ENABLED", "yes") != "yes":
                return
            # For audiobooks, fetch all authors, then fetch their children (audiobooks)
            for author in root.findall(".//Directory"):
                author_key = author.attrib.get("key")
                if author_key:
                    author_url = f"{PLEX_URL}{author_key}?X-Plex-Token={PLEX_TOKEN}"
                    author_resp = requests.get(author_url, headers=headers)
                    if author_resp.status_code == 200:
                        author_root = ET.fromstring(author_resp.content)
                        # Each audiobook is a Directory (album/book)
                        for book in author_root.findall(".//Directory"):
                            thumb = book.attrib.get("thumb")
                            if thumb:
                                posters.append(thumb)
        else:
            # Movies: .//Video, Shows: .//Directory
            # (No longer used for movies or shows)
            pass
        random.shuffle(posters)

        for i, rel_path in enumerate(posters[:limit]):
            img_url = f"{PLEX_URL}{rel_path}?X-Plex-Token={PLEX_TOKEN}"
            out_path = os.path.join(out_dir, f"{tag}{i+1}.webp")
            try:
                r = requests.get(img_url, headers=headers)
                with open(out_path, "wb") as f:
                    f.write(r.content)
            except Exception as e:
                if debug_mode:
                    print(f"Error saving {img_url}: {e}")

    # Only audiobooks (if ABS is disabled)
    if os.getenv("ABS_ENABLED", "yes") != "yes":
        if debug_mode:
            print("[INFO] ABS disabled, downloading audiobook posters from Plex")
        save_images(AUDIOBOOKS_SECTION_ID, audiobook_dir, "audiobook", 25)
    else:
        # Download audiobook posters from ABS
        if debug_mode:
            print("[INFO] ABS enabled, downloading audiobook posters from ABS")
        download_abs_audiobook_posters()

def download_abs_audiobook_posters():
    """Download audiobook posters from ABS API"""
    abs_url = os.getenv("AUDIOBOOKSHELF_URL")
    if not abs_url:
        if debug_mode:
            print("[WARN] ABS enabled but AUDIOBOOKSHELF_URL not set")
        return
    
    audiobook_dir = os.path.join("static", "posters", "audiobooks")
    os.makedirs(audiobook_dir, exist_ok=True)
    
    try:
        # Fetch audiobooks from ABS API
        headers = {}
        abs_token = os.getenv("AUDIOBOOKSHELF_TOKEN")
        if abs_token:
            headers["Authorization"] = f"Bearer {abs_token}"
        else:
            if debug_mode:
                print("[INFO] No ABS token provided, trying without authentication")
        
        response = requests.get(f"{abs_url}/api/libraries", headers=headers, timeout=10)
        if response.status_code == 200:
            try:
                response_data = response.json()
                
                # Extract libraries array from response
                libraries = response_data.get("libraries", [])
                
                poster_count = 0
                for library in libraries:
                    if isinstance(library, dict):
                        if library.get("mediaType") == "book":
                            library_id = library.get("id")
                            books_response = requests.get(f"{abs_url}/api/libraries/{library_id}/items", headers=headers, timeout=10)
                            if books_response.status_code == 200:
                                books_data = books_response.json()
                                for book in books_data.get("results", []):
                                    if poster_count >= 25:  # Limit to 25 posters
                                        break
                                    
                                    # Get book details from the nested media structure
                                    media = book.get("media", {})
                                    cover_path = media.get("coverPath")
                                    title = media.get("metadata", {}).get("title", "Unknown")
                                    
                                    if cover_path:
                                        # Use the correct cover URL pattern
                                        item_id = book.get("id")
                                        cover_url = f"{abs_url}/api/items/{item_id}/cover"
                                        cover_response = requests.get(cover_url, headers=headers, timeout=10)
                                        if cover_response.status_code == 200:
                                            out_path = os.path.join(audiobook_dir, f"audiobook{poster_count+1}.webp")
                                            with open(out_path, "wb") as f:
                                                f.write(cover_response.content)
                                            poster_count += 1
                                if poster_count >= 25:
                                    break
                            else:
                                if debug_mode:
                                    print(f"[WARN] Failed to get books from library {library_id}: {books_response.status_code}")
                if debug_mode:
                    print(f"[INFO] Downloaded {poster_count} audiobook posters")
            except Exception as e:
                if debug_mode:
                    print(f"[WARN] Error parsing ABS response: {e}")
                print(f"[WARN] Raw response: {response.text}")
        else:
            if debug_mode:
                print(f"[WARN] Failed to connect to ABS API: {response.status_code}")
                print(f"[WARN] Response content: {response.text[:200]}...")
    except Exception as e:
        if debug_mode:
            print(f"[WARN] Error downloading ABS audiobook posters: {e}")
            import traceback
            traceback.print_exc()

def download_single_poster_with_metadata(item, lib_dir, index, headers):
    """Download a single poster with metadata, with rate limiting and thread safety"""
    # Use a unique filename based on ratingKey to prevent race conditions
    rating_key = item.get('ratingKey', str(index))
    safe_filename = f"poster_{rating_key}"
    out_path = os.path.join(lib_dir, f"{safe_filename}.webp")
    meta_path = os.path.join(lib_dir, f"{safe_filename}.json")
    
    # Skip if already cached and recent (less than 24 hours old)
    if os.path.exists(out_path) and os.path.exists(meta_path):
        file_age = time.time() - os.path.getmtime(out_path)
        if file_age < 86400:  # 24 hours
            return True
    
    try:
        # Download poster
        img_url = f"{PLEX_URL}{item['thumb']}?X-Plex-Token={PLEX_TOKEN}"
        r = requests.get(img_url, headers=headers, timeout=10)
        if r.status_code == 200:
            with open(out_path, "wb") as f:
                f.write(r.content)
        else:
            return False
        
        # Rate limiting - small delay between requests
        time.sleep(0.1)
        
        # Fetch metadata
        guids = {"imdb": None, "tmdb": None, "tvdb": None}
        try:
            meta_url = f"{PLEX_URL}/library/metadata/{item['ratingKey']}"
            meta_resp = requests.get(meta_url, headers=headers, timeout=10)
            if meta_resp.status_code == 200:
                meta_root = ET.fromstring(meta_resp.content)
                for guid in meta_root.findall(".//Guid"):
                    gid = guid.attrib.get("id", "")
                    if gid.startswith("imdb://"):
                        guids["imdb"] = gid.replace("imdb://", "")
                    elif gid.startswith("tmdb://"):
                        guids["tmdb"] = gid.replace("tmdb://", "")
                    elif gid.startswith("tvdb://"):
                        guids["tvdb"] = gid.replace("tvdb://", "")
        except Exception as e:
            if debug_mode:
                print(f"Error fetching GUIDs for {item['ratingKey']}: {e}")
        
        # Save metadata with thread-safe writing
        meta = {
            "title": item["title"],
            "ratingKey": item["ratingKey"],
            "year": item.get("year"),
            "imdb": guids["imdb"],
            "tmdb": guids["tmdb"],
            "tvdb": guids["tvdb"],
            "poster": f"{safe_filename}.webp"
        }
        
        # Write to temporary file first, then rename to prevent corruption
        temp_meta_path = meta_path + ".tmp"
        with open(temp_meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
        
        # Atomic rename (this is atomic on most filesystems)
        if os.path.exists(meta_path):
            os.remove(meta_path)
        os.rename(temp_meta_path, meta_path)
        
        return True
    except Exception as e:
        if debug_mode:
            print(f"Error downloading poster for {item.get('title', 'Unknown')}: {e}")
        return False

def download_and_cache_posters_for_libraries(libraries, limit=None, background=False):
    """Optimized poster downloading with background processing and rate limiting"""
    if not libraries:
        return
    
    if debug_mode:
        print(f"[DEBUG] download_and_cache_posters_for_libraries called with {len(libraries)} libraries, background={background}")
    
    headers = {"X-Plex-Token": PLEX_TOKEN}
    
    def process_library(lib):
        section_id = lib["key"]
        lib_dir = os.path.join("static", "posters", section_id)
        os.makedirs(lib_dir, exist_ok=True)
        
        try:
            # Fetch library items
            url = f"{PLEX_URL}/library/sections/{section_id}/all"
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            root = ET.fromstring(response.content)
            
            # Collect items
            items = []
            for el in root.findall(".//Video"):
                thumb = el.attrib.get("thumb")
                rating_key = el.attrib.get("ratingKey")
                title = el.attrib.get("title")
                year = el.attrib.get("year")
                if thumb and rating_key:
                    items.append({"thumb": thumb, "ratingKey": rating_key, "title": title, "year": year})
            
            for el in root.findall(".//Directory"):
                thumb = el.attrib.get("thumb")
                rating_key = el.attrib.get("ratingKey")
                title = el.attrib.get("title")
                if thumb and rating_key and not any(i["ratingKey"] == rating_key for i in items):
                    items.append({"thumb": thumb, "ratingKey": rating_key, "title": title})
            
            # Shuffle and limit
            random.shuffle(items)
            if limit is not None:
                items = items[:limit]
            
            if debug_mode:
                print(f"[DEBUG] Processing {len(items)} items for library {lib['title']}")
            
            # Process items with ThreadPoolExecutor for parallel downloads
            successful_downloads = 0
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = []
                for i, item in enumerate(items):
                    future = executor.submit(download_single_poster_with_metadata, item, lib_dir, i, headers)
                    futures.append(future)
                
                # Wait for completion with progress tracking
                for i, future in enumerate(as_completed(futures)):
                    if future.result():
                        successful_downloads += 1
                    if background and i % 5 == 0:  # Update progress every 5 items
                        with poster_download_lock:
                            poster_download_progress[section_id] = {
                                'current': i + 1,
                                'total': len(items),
                                'successful': successful_downloads
                            }
            
            if debug_mode:
                print(f"[INFO] Downloaded {successful_downloads}/{len(items)} posters for library {lib['title']}")
            
            return successful_downloads
            
        except Exception as e:
            if debug_mode:
                print(f"Error fetching posters for section {section_id}: {e}")
            return 0
    
    if background:
        # Queue for background processing
        poster_download_queue.put(('libraries', libraries, limit))
        if debug_mode:
            print(f"[DEBUG] Queued {len(libraries)} libraries for background processing")
        return True
    else:
        # Process immediately
        total_downloaded = 0
        for lib in libraries:
            downloaded = process_library(lib)
            total_downloaded += downloaded
        return total_downloaded

def background_poster_worker():
    """Background worker for poster downloads"""
    global poster_download_running
    poster_download_running = True
    
    if debug_mode:
        print("[INFO] Background poster worker started")
    
    while poster_download_running:
        try:
            # Wait for work with timeout
            work_item = poster_download_queue.get(timeout=1)
            if work_item is None:  # Shutdown signal
                break
            
            work_type, data, limit = work_item
            
            if debug_mode:
                print(f"[INFO] Processing work item: {work_type}")
            
            if work_type == 'libraries':
                download_and_cache_posters_for_libraries(data, limit, background=False)
                if debug_mode:
                    print(f"[INFO] Completed library poster download for {len(data)} libraries")
            elif work_type == 'abs':
                download_abs_audiobook_posters()
                if debug_mode:
                    print("[INFO] Completed ABS poster download")
            
            poster_download_queue.task_done()
            
        except queue.Empty:
            continue
        except Exception as e:
            if debug_mode:
                print(f"Error in background poster worker: {e}")
    
    if debug_mode:
        print("[INFO] Background poster worker stopped")

def start_background_poster_worker():
    """Start the background poster download worker"""
    global poster_download_running
    if not poster_download_running:
        worker_thread = threading.Thread(target=background_poster_worker, daemon=True)
        worker_thread.start()
        if debug_mode:
            print("[INFO] Started background poster download worker")
        # Small delay to ensure worker is ready
        time.sleep(0.5)

def get_poster_download_progress():
    """Get current poster download progress"""
    with poster_download_lock:
        return poster_download_progress.copy()

def is_poster_download_in_progress():
    """Check if poster downloads are currently in progress"""
    with poster_download_lock:
        return len(poster_download_progress) > 0

def group_titles_by_letter(titles):
    groups = defaultdict(list)
    for title in titles:
        # Check if title starts with a digit
        if title and title[0].isdigit():
            groups['0-9'].append(title)
        else:
            # Find the first ASCII letter in the title
            match = re.search(r'[A-Za-z]', title)
            if match:
                letter = match.group(0).upper()
                groups[letter].append(title)
            elif any(c.isdigit() for c in title):
                groups['0-9'].append(title)
            else:
                groups['Other'].append(title)
    # Sort groups alphabetically, but put 'Other' at the end
    sorted_keys = sorted([k for k in groups if k != 'Other'], key=lambda x: (x != '0-9', x))
    if 'Other' in groups:
        sorted_keys.append('Other')
    return OrderedDict((k, sorted(groups[k], key=str.casefold)) for k in sorted_keys)

def group_posters_by_letter(posters):
    groups = defaultdict(list)
    for poster in posters:
        title = poster.get("title", "")
        match = re.search(r'[A-Za-z]', title)
        if match:
            letter = match.group(0).upper()
            groups[letter].append(poster)
        elif any(c.isdigit() for c in title):
            groups['0-9'].append(poster)
        else:
            groups['Other'].append(poster)
    sorted_keys = sorted([k for k in groups if k != 'Other'], key=lambda x: (x != '0-9', x))
    if 'Other' in groups:
        sorted_keys.append('Other')
    return OrderedDict((k, sorted(groups[k], key=lambda p: p.get("title", "").casefold())) for k in sorted_keys)

def group_books_by_letter(books):
    groups = defaultdict(list)
    for book in books:
        title = book.get("title", "")
        match = re.search(r'[A-Za-z]', title)
        if match:
            letter = match.group(0).upper()
            groups[letter].append(book)
        elif any(c.isdigit() for c in title):
            groups['0-9'].append(book)
        else:
            groups['Other'].append(book)
    sorted_keys = sorted([k for k in groups if k != 'Other'], key=lambda x: (x != '0-9', x))
    if 'Other' in groups:
        sorted_keys.append('Other')
    return OrderedDict((k, sorted(groups[k], key=lambda b: b.get("title", "").casefold())) for k in sorted_keys)

@app.route("/medialists")
def medialists():
    if not session.get("authenticated"):
        return redirect(url_for("login"))

    def fetch_titles_for_library(section_id):
        titles = []
        if not section_id:
            return titles
        headers = {"X-Plex-Token": PLEX_TOKEN}
        url = f"{PLEX_URL}/library/sections/{section_id}/all"
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            root = ET.fromstring(response.content)
            for el in root.findall(".//Video"):
                title = el.attrib.get("title")
                if title:
                    titles.append(title)
            for el in root.findall(".//Directory"):
                title = el.attrib.get("title")
                if title and title not in titles:
                    titles.append(title)
        except Exception as e:
            if debug_mode:
                print(f"Error fetching titles for section {section_id}: {e}")
        return titles

    def fetch_audiobooks(section_id):
        books = {}
        abs_enabled = os.getenv("ABS_ENABLED", "yes") == "yes"
        
        if abs_enabled:
            # Fetch from ABS API
            abs_url = os.getenv("AUDIOBOOKSHELF_URL")
            if not abs_url:
                if debug_mode:
                    print("[WARN] ABS enabled but AUDIOBOOKSHELF_URL not set")
                return books
            
            try:
                # Fetch audiobooks from ABS API
                # Note: This is a basic implementation - you may need to adjust based on your ABS API
                headers = {}
                abs_token = os.getenv("AUDIOBOOKSHELF_TOKEN")
                if abs_token:
                    headers["Authorization"] = f"Bearer {abs_token}"
                
                response = requests.get(f"{abs_url}/api/libraries", headers=headers, timeout=10)
                if response.status_code == 200:
                    try:
                        libraries_data = response.json()
                    except ValueError as json_error:
                        if debug_mode:
                            print(f"[WARN] Invalid JSON response from ABS API: {json_error}")
                            print(f"[WARN] Response content: {response.text[:200]}...")
                        return books
                    
                    libraries = libraries_data.get("libraries", [])
                    for library in libraries:
                        if library.get("mediaType") == "book":
                            # Fetch audiobooks from this library
                            library_id = library.get("id")
                            books_response = requests.get(f"{abs_url}/api/libraries/{library_id}/items", headers=headers, timeout=10)
                            if books_response.status_code == 200:
                                try:
                                    books_data = books_response.json()
                                except ValueError as json_error:
                                    if debug_mode:
                                        print(f"[WARN] Invalid JSON response for library {library_id}: {json_error}")
                                    continue
                                # Group by author
                                for book in books_data.get("results", []):
                                    author = book.get("media", {}).get("metadata", {}).get("author", "Unknown Author")
                                    title = book.get("media", {}).get("metadata", {}).get("title", "Unknown Title")
                                    if author not in books:
                                        books[author] = []
                                    books[author].append(title)
                else:
                    if debug_mode:
                        print(f"[WARN] Failed to connect to ABS API: {response.status_code}")
            except Exception as e:
                if debug_mode:
                    print(f"[WARN] Error connecting to ABS API: {e}")
            return books
        else:
            # Only fetch from Plex if ABS is disabled
            if not section_id:
                return books
            headers = {"X-Plex-Token": PLEX_TOKEN}
            url = f"{PLEX_URL}/library/sections/{section_id}/all"
            try:
                response = requests.get(url, headers=headers, timeout=10)
                response.raise_for_status()
                root = ET.fromstring(response.content)
                for author in root.findall(".//Directory"):
                    author_name = author.attrib.get("title")
                    author_key = author.attrib.get("key")
                    if author_name and author_key:
                        author_url = f"{PLEX_URL}{author_key}?X-Plex-Token={PLEX_TOKEN}"
                        author_resp = requests.get(author_url, headers=headers)
                        if author_resp.status_code == 200:
                            author_root = ET.fromstring(author_resp.content)
                            books[author_name] = []
                            for book in author_root.findall(".//Directory"):
                                book_title = book.attrib.get("title")
                                if book_title:
                                    books[author_name].append(book_title)
            except Exception as e:
                if debug_mode:
                    print(f"Error fetching audiobooks from Plex: {e}")
            return books

    def fetch_abs_books():
        abs_books = []
        abs_enabled = os.getenv("ABS_ENABLED", "yes") == "yes"
        abs_url = os.getenv("AUDIOBOOKSHELF_URL")
        abs_token = os.getenv("AUDIOBOOKSHELF_TOKEN")
        if not abs_enabled or not abs_url:
            return abs_books
        headers = {}
        if abs_token:
            headers["Authorization"] = f"Bearer {abs_token}"
        try:
            # Get all libraries
            resp = requests.get(f"{abs_url}/api/libraries", headers=headers, timeout=10)
            resp.raise_for_status()
            
            # Check if response is valid JSON
            try:
                data = resp.json()
            except ValueError as json_error:
                if debug_mode:
                    print(f"[ABS] Invalid JSON response from API: {json_error}")
                    print(f"[ABS] Response content: {resp.text[:200]}...")
                return abs_books
            
            libraries = data.get("libraries", [])
            for library in libraries:
                if library.get("mediaType") == "book":
                    lib_id = library.get("id")
                    # Get all items in this library
                    items_resp = requests.get(f"{abs_url}/api/libraries/{lib_id}/items", headers=headers, timeout=10)
                    items_resp.raise_for_status()
                    
                    try:
                        items_data = items_resp.json()
                    except ValueError as json_error:
                        if debug_mode:
                            print(f"[ABS] Invalid JSON response for library {lib_id}: {json_error}")
                        continue
                    
                    for item in items_data.get("results", []):
                        title = item.get("media", {}).get("metadata", {}).get("title")
                        author = item.get("media", {}).get("metadata", {}).get("author")
                        item_id = item.get("id")
                        cover_url = f"{abs_url}/api/items/{item_id}/cover" if item_id else None
                        abs_books.append({
                            "title": title,
                            "author": author,
                            "cover": cover_url,
                        })
        except Exception as e:
            if debug_mode:
                print(f"[ABS] Error fetching books: {e}")
        return abs_books

    # Get all libraries
    try:
        libraries = get_plex_libraries()
    except Exception as e:
        if debug_mode:
            print(f"Failed to get Plex libraries: {e}")
        libraries = []

    # Only include libraries specified in LIBRARY_IDS
    selected_ids = os.getenv("LIBRARY_IDS", "")
    selected_ids = [i.strip() for i in selected_ids.split(",") if i.strip()]
    filtered_libraries = [lib for lib in libraries if lib["key"] in selected_ids]

    library_media = {}
    # Only load titles for libraries (posters will be loaded on-demand via AJAX)
    for lib in filtered_libraries:
        section_id = lib["key"]
        name = lib["title"]
        titles = fetch_titles_for_library(section_id)
        
        grouped_titles = group_titles_by_letter(titles)
        library_media[name] = grouped_titles

    abs_enabled = os.getenv("ABS_ENABLED", "yes") == "yes"
    audiobooks = {}
    if abs_enabled:
        # If ABS is enabled, we don't need the Plex section ID
        audiobooks = fetch_audiobooks(None)
    elif AUDIOBOOKS_SECTION_ID:
        # Only use Plex section ID if ABS is disabled
        audiobooks = fetch_audiobooks(AUDIOBOOKS_SECTION_ID)

    abs_books = fetch_abs_books() if abs_enabled else []
    abs_book_groups = group_books_by_letter(abs_books) if abs_books else {}

    return render_template(
        "medialists.html",
        library_media=library_media,
        audiobooks=audiobooks,
        abs_enabled=abs_enabled,
        library_posters={},  # Empty - will be loaded on-demand
        library_poster_groups={},  # Empty - will be loaded on-demand
        abs_books=abs_books,
        abs_book_groups=abs_book_groups,
        filtered_libraries=filtered_libraries,  # Pass library info for AJAX
        logo_filename=get_logo_filename(),
    )

@app.route("/audiobook-covers")
def get_random_audiobook_covers():
    if os.getenv("ABS_ENABLED", "yes") != "yes":
        return ("Not Found", 404)
    
    # Check which audiobook poster files actually exist
    audiobook_dir = os.path.join("static", "posters", "audiobooks")
    existing_paths = []
    for i in range(25):
        poster_path = os.path.join(audiobook_dir, f"audiobook{i+1}.webp")
        if os.path.exists(poster_path):
            existing_paths.append(f"/static/posters/audiobooks/audiobook{i+1}.webp")
    
    random.shuffle(existing_paths)
    return jsonify(existing_paths)

def is_setup_complete():
    return os.getenv("SETUP_COMPLETE") == "1"

@app.before_request
def check_setup():
    allowed_endpoints = {"setup", "fetch_libraries", "static"}
    if not is_setup_complete():
        # Allow setup page, fetch-libraries API, and static files
        if request.endpoint not in allowed_endpoints and not request.path.startswith("/static"):
            return redirect(url_for("setup"))

def restart_container_delayed():
    time.sleep(2)  # Give browser time to receive the response
    if platform.system() == "Windows":
        import sys
        import os
        # Re-execute the current script with the same arguments
        os.execv(sys.executable, [sys.executable] + sys.argv)
    else:
        import os
        import signal
        os.kill(os.getpid(), signal.SIGTERM)

@app.route("/trigger_restart", methods=["POST"])
@csrf.exempt
def trigger_restart():
    threading.Thread(target=restart_container_delayed, daemon=True).start()
    return jsonify({"status": "restarting"})

# Update index route to check setup status
@app.route("/", methods=["GET", "POST"])
def index():
    if not is_setup_complete():
        return redirect(url_for("setup"))
    if request.method == "POST":
        entered_password = request.form.get("password")
        # Always reload from .env
        from dotenv import load_dotenv
        load_dotenv(override=True)
        
        # Get hashed passwords and salts
        admin_password_hash = os.getenv("ADMIN_PASSWORD_HASH")
        admin_password_salt = os.getenv("ADMIN_PASSWORD_SALT")
        site_password_hash = os.getenv("SITE_PASSWORD_HASH")
        site_password_salt = os.getenv("SITE_PASSWORD_SALT")
        
        # For backward compatibility, check plain text passwords if hashes don't exist
        admin_password_plain = os.getenv("ADMIN_PASSWORD")
        site_password_plain = os.getenv("SITE_PASSWORD")
        
        # Check admin password
        admin_authenticated = False
        if admin_password_hash and admin_password_salt:
            admin_authenticated = verify_password(entered_password, admin_password_salt, admin_password_hash)
        elif admin_password_plain:
            # Fallback to plain text for backward compatibility
            admin_authenticated = (entered_password == admin_password_plain)
        
        # Check site password
        site_authenticated = False
        if site_password_hash and site_password_salt:
            site_authenticated = verify_password(entered_password, site_password_salt, site_password_hash)
        elif site_password_plain:
            # Fallback to plain text for backward compatibility
            site_authenticated = (entered_password == site_password_plain)

        if admin_authenticated:
            session["authenticated"] = True
            session["admin_authenticated"] = True
            return redirect(url_for("services"))
        elif site_authenticated:
            session["authenticated"] = True
            session["admin_authenticated"] = False
            return redirect(url_for("onboarding"))
        else:
            return render_template("login.html", error="Incorrect password")

    return render_template("login.html")

@app.route("/setup", methods=["GET", "POST"])
def setup():
    # If GET and SETUP_COMPLETE=0, show prompt for SITE_PASSWORD, ADMIN_PASSWORD, DRIVES
    if request.method == "GET" and not is_setup_complete():
        site_password = os.getenv("SITE_PASSWORD", "changeme")
        admin_password = os.getenv("ADMIN_PASSWORD", "changeme2")
        drives = os.getenv("DRIVES", "")
        prompt = False
        if site_password == "changeme" or admin_password == "changeme2" or not drives:
            prompt = True
        service_keys = [
            'PLEX', 'LIDARR', 'RADARR', 'SONARR', 'TAUTULLI', 'QBITTORRENT', 'IMMICH',
            'PROWLARR', 'BAZARR', 'PULSARR', 'AUDIOBOOKSHELF', 'OVERSEERR'
        ]
        service_urls = {key: os.getenv(key, "") for key in service_keys}
        return render_template(
            "setup.html",
            prompt_passwords=prompt,
            site_password=site_password,
            admin_password=admin_password,
            drives=drives,
            service_urls=service_urls
        )
    if is_setup_complete():
        return redirect(url_for("login"))
    error_message = None
    if request.method == "POST":
        from dotenv import set_key
        env_path = os.path.join(os.getcwd(), ".env")
        form = request.form
        
        # Handle file uploads
        logo_file = request.files.get('logo_file')
        wordmark_file = request.files.get('wordmark_file')
        
        if logo_file:
            if not process_uploaded_logo(logo_file):
                error_message = "Failed to process logo file. Please ensure it's a valid image file (.png, .webp, .jpg, .jpeg)."
        
        if wordmark_file:
            if not process_uploaded_wordmark(wordmark_file):
                error_message = "Failed to process wordmark file. Please ensure it's a valid image file (.png, .webp, .jpg, .jpeg)."

        # Save SITE_PASSWORD, ADMIN_PASSWORD, DRIVES from the top entry boxes if present
        site_password = form.get("site_password_box") or form.get("site_password")
        admin_password = form.get("admin_password_box") or form.get("admin_password")
        drives = form.get("drives_box") or form.get("drives")
        if site_password is not None and admin_password is not None and drives is not None:
            if not site_password or not admin_password or not drives:
                error_message = "SITE_PASSWORD, ADMIN_PASSWORD, and DRIVES are required."
                service_keys = [
                    'PLEX', 'LIDARR', 'RADARR', 'SONARR', 'TAUTULLI', 'QBITTORRENT', 'IMMICH',
                    'PROWLARR', 'BAZARR', 'PULSARR', 'AUDIOBOOKSHELF', 'OVERSEERR'
                ]
                service_urls = {key: os.getenv(key, "") for key in service_keys}
                return render_template("setup.html", error_message=error_message, prompt_passwords=True, site_password=site_password, admin_password=admin_password, drives=drives, service_urls=service_urls)
            if site_password == admin_password:
                error_message = "SITE_PASSWORD and ADMIN_PASSWORD must be different."
                service_keys = [
                    'PLEX', 'LIDARR', 'RADARR', 'SONARR', 'TAUTULLI', 'QBITTORRENT', 'IMMICH',
                    'PROWLARR', 'BAZARR', 'PULSARR', 'AUDIOBOOKSHELF', 'OVERSEERR'
                ]
                service_urls = {key: os.getenv(key, "") for key in service_keys}
                return render_template("setup.html", error_message=error_message, prompt_passwords=True, site_password=site_password, admin_password=admin_password, drives=drives, service_urls=service_urls)
            
            # Hash passwords before saving
            site_salt, site_hash = hash_password(site_password)
            admin_salt, admin_hash = hash_password(admin_password)
            
            # Save hashed passwords and salts
            safe_set_key(env_path, "SITE_PASSWORD_HASH", site_hash)
            safe_set_key(env_path, "SITE_PASSWORD_SALT", site_salt)
            safe_set_key(env_path, "ADMIN_PASSWORD_HASH", admin_hash)
            safe_set_key(env_path, "ADMIN_PASSWORD_SALT", admin_salt)
            
            # Keep plain text passwords for backward compatibility during transition
            safe_set_key(env_path, "SITE_PASSWORD", site_password)
            safe_set_key(env_path, "ADMIN_PASSWORD", admin_password)
            safe_set_key(env_path, "DRIVES", drives)

        abs_enabled = form.get("abs_enabled", "")
        audiobooks_id = form.get("audiobooks_id", "").strip()
        audiobookshelf_url = form.get("audiobookshelf_url", "").strip()
        discord_enabled = form.get("discord_enabled", "")
        discord_webhook = form.get("discord_webhook", "").strip()
        discord_username = form.get("discord_username", "").strip()
        discord_avatar = form.get("discord_avatar", "").strip()
        discord_color = form.get("discord_color", "").strip()



        safe_set_key(env_path, "SERVER_NAME", form.get("server_name", ""))
        safe_set_key(env_path, "ACCENT_COLOR", form.get("accent_color_text", "#d33fbc"))
        
        # Handle API keys with hashing
        plex_token = form.get("plex_token", "").strip()
        if plex_token:
            save_api_key_with_hash(env_path, "PLEX_TOKEN", plex_token)
        
        safe_set_key(env_path, "PLEX_URL", form.get("plex_url", ""))
        safe_set_key(env_path, "ABS_ENABLED", abs_enabled)
        if abs_enabled == "yes":
            safe_set_key(env_path, "AUDIOBOOKS_ID", audiobooks_id)
            safe_set_key(env_path, "AUDIOBOOKSHELF_URL", audiobookshelf_url)
            audiobookshelf_token = form.get("audiobookshelf_token", "").strip()
            if audiobookshelf_token:
                save_api_key_with_hash(env_path, "AUDIOBOOKSHELF_TOKEN", audiobookshelf_token)
        # Save Discord settings
        safe_set_key(env_path, "DISCORD_WEBHOOK", discord_webhook)
        if discord_webhook:
            if discord_username:
                safe_set_key(env_path, "DISCORD_USERNAME", discord_username)
            if discord_avatar:
                safe_set_key(env_path, "DISCORD_AVATAR", discord_avatar)
            if discord_color:
                safe_set_key(env_path, "DISCORD_COLOR", discord_color)
        # Save selected library IDs and names
        library_ids = request.form.getlist("library_ids")
        library_notes = {}
        if library_ids:
            plex_token = form.get("plex_token", "")
            plex_url = form.get("plex_url", "")
            headers = {"X-Plex-Token": plex_token}
            url = f"{plex_url}/library/sections"
            try:
                response = requests.get(url, headers=headers, timeout=5)
                response.raise_for_status()
                import xml.etree.ElementTree as ET
                root = ET.fromstring(response.text)
                id_to_title = {d.attrib.get("key"): d.attrib.get("title") for d in root.findall(".//Directory")}
                selected_titles = [id_to_title.get(i, f"Unknown ({i})") for i in library_ids]
                safe_set_key(env_path, "LIBRARY_IDS", ",".join(library_ids))
                safe_set_key(env_path, "LIBRARY_NAMES", ",".join([t or "" for t in selected_titles]))
                # Save library notes with title and description
                for lib_id in library_ids:
                    desc = form.get(f"library_desc_{lib_id}", "")
                    library_notes[lib_id] = {
                        "title": id_to_title.get(lib_id, f"Unknown ({lib_id})"),
                        "description": desc
                    }
                save_library_notes(library_notes)
            except Exception as e:
                safe_set_key(env_path, "LIBRARY_IDS", ",".join(library_ids))
                safe_set_key(env_path, "LIBRARY_NAMES", "")
        # Save service URLs
        service_keys = [
            'PLEX', 'LIDARR', 'RADARR', 'SONARR', 'TAUTULLI', 'QBITTORRENT', 'IMMICH',
            'PROWLARR', 'BAZARR', 'PULSARR', 'AUDIOBOOKSHELF', 'OVERSEERR'
        ]
        for key in service_keys:
            url_val = form.get(key, "").strip()
            safe_set_key(env_path, key, url_val)
        safe_set_key(env_path, "SETUP_COMPLETE", "1")
        load_dotenv(override=True)
        return redirect(url_for("setup_complete"))
    return render_template("setup.html", error_message=error_message)

def ensure_worker_running():
    """Ensure the background poster worker is running"""
    global poster_download_running
    if not poster_download_running:
        if debug_mode:
            print("[INFO] Restarting background poster worker")
        start_background_poster_worker()

def trigger_poster_downloads():
    """Manually trigger poster downloads - used as backup after setup"""
    try:
        # Ensure worker is running
        ensure_worker_running()
        
        if os.getenv("SETUP_COMPLETE") == "1" and PLEX_TOKEN:
            # Get selected libraries
            selected_ids = os.getenv("LIBRARY_IDS", "")
            selected_ids = [i.strip() for i in selected_ids.split(",") if i.strip()]
            all_libraries = get_plex_libraries()
            libraries = [lib for lib in all_libraries if lib["key"] in selected_ids]
            
            if libraries:
                # Queue poster downloads
                download_and_cache_posters_for_libraries(libraries, background=True)
                if debug_mode:
                    print(f"[INFO] Manually triggered poster download for {len(libraries)} libraries")
            
            # Queue ABS poster download if enabled
            if os.getenv("ABS_ENABLED", "yes") == "yes":
                poster_download_queue.put(('abs', None, None))
                if debug_mode:
                    print("[INFO] Manually triggered ABS poster download")
    except Exception as e:
        if debug_mode:
            print(f"Warning: Could not trigger poster downloads: {e}")

@app.route("/setup_complete")
def setup_complete():
    # Trigger poster downloads immediately after setup completion
    try:
        if os.getenv("SETUP_COMPLETE") == "1" and PLEX_TOKEN:
            # Ensure worker is running
            ensure_worker_running()
            
            # Get selected libraries
            selected_ids = os.getenv("LIBRARY_IDS", "")
            selected_ids = [i.strip() for i in selected_ids.split(",") if i.strip()]
            all_libraries = get_plex_libraries()
            libraries = [lib for lib in all_libraries if lib["key"] in selected_ids]
            
            if libraries:
                # Queue poster downloads with a small delay to ensure worker is ready
                def queue_posters_delayed():
                    time.sleep(1)  # Small delay to ensure worker is ready
                    download_and_cache_posters_for_libraries(libraries, background=True)
                    if debug_mode:
                        print(f"[INFO] Queued poster download for {len(libraries)} libraries after setup")
                
                threading.Thread(target=queue_posters_delayed, daemon=True).start()
            
            # Queue ABS poster download if enabled
            if os.getenv("ABS_ENABLED", "yes") == "yes":
                def queue_abs_posters_delayed():
                    time.sleep(1)  # Small delay to ensure worker is ready
                    poster_download_queue.put(('abs', None, None))
                    if debug_mode:
                        print("[INFO] Queued ABS poster download after setup")
                
                threading.Thread(target=queue_abs_posters_delayed, daemon=True).start()
    except Exception as e:
        if debug_mode:
            print(f"Warning: Could not queue poster downloads after setup: {e}")
    
    return render_template("setup_complete.html")

def periodic_poster_refresh(libraries, interval_hours=6):
    def refresh():
        while True:
            if debug_mode:
                print("[INFO] Refreshing library posters...")
            # Use background processing for periodic refresh
            download_and_cache_posters_for_libraries(libraries, background=True)
            time.sleep(interval_hours * 3600)
    t = threading.Thread(target=refresh, daemon=True)
    t.start()

def refresh_posters_on_demand(libraries=None):
    """Refresh posters in background when settings are applied"""
    if libraries is None:
        selected_ids = os.getenv("LIBRARY_IDS", "")
        selected_ids = [i.strip() for i in selected_ids.split(",") if i.strip()]
        all_libraries = get_plex_libraries()
        libraries = [lib for lib in all_libraries if lib["key"] in selected_ids]
    
    if libraries:
        # Queue for background processing
        download_and_cache_posters_for_libraries(libraries, background=True)
        if debug_mode:
            print(f"[INFO] Queued poster refresh for {len(libraries)} libraries")
        return True
    return False

def invite_plex_user(email, libraries_titles):
    """Invite/share Plex libraries with a user via the Plex API."""
    plex_url = os.getenv("PLEX_URL")
    plex_token = os.getenv("PLEX_TOKEN")
    if not plex_url or not plex_token:
        return {"success": False, "email": email, "error": "Plex URL or token not configured"}
    try:
        plex = PlexServer(plex_url, plex_token)
        account = plex.myPlexAccount()
        # Check if user already exists as a friend
        for user in account.users():
            if user.email and user.email.lower() == email.lower():
                # Update libraries for existing user
                account.updateFriend(user=user, server=plex, sections=libraries_titles)
                return {"success": True, "email": email, "message": "Updated existing Plex friend with new libraries."}
        # If not, invite as new friend
        account.inviteFriend(user=email, server=plex, sections=libraries_titles)
        return {"success": True, "email": email, "message": "Invited new Plex user."}
    except Exception as e:
        return {"success": False, "email": email, "error": str(e)}

# --- Utility Functions for DRY Code ---

def get_service_definitions():
    """Centralized service definitions to avoid repetition"""
    return [
        ("Plex", "PLEX", "plex.webp"),
        ("Tautulli", "TAUTULLI", "tautulli.webp"),
        ("Audiobookshelf", "AUDIOBOOKSHELF", "abs.webp"),
        ("qbittorrent", "QBITTORRENT", "qbit.webp"),
        ("Immich", "IMMICH", "immich.webp"),
        ("Sonarr", "SONARR", "sonarr.webp"),
        ("Radarr", "RADARR", "radarr.webp"),
        ("Lidarr", "LIDARR", "lidarr.webp"),
        ("Prowlarr", "PROWLARR", "prowlarr.webp"),
        ("Bazarr", "BAZARR", "bazarr.webp"),
        ("Pulsarr", "PULSARR", "pulsarr.webp"),
        ("Overseerr", "OVERSEERR", "overseerr.webp"),
    ]

def get_public_service_definitions():
    """Service definitions for end users (non-admin services)"""
    return [
        ("Plex", "PLEX", "plex.webp"),
        ("Audiobookshelf", "AUDIOBOOKSHELF", "abs.webp"),
        ("Tautulli", "TAUTULLI", "tautulli.webp"),
        ("Overseerr", "OVERSEERR", "overseerr.webp"),
    ]

def load_json_file(filename, default=None):
    """Utility function to load JSON files with consistent error handling"""
    if default is None:
        default = []
    
    try:
        with open(os.path.join(os.getcwd(), filename), "r", encoding="utf-8") as f:
            data = json.load(f)
        if debug_mode:
            print(f"[DEBUG] Loaded {len(data)} entries from {filename}")
        return data
    except FileNotFoundError:
        if debug_mode:
            print(f"[DEBUG] No {filename} file found, using default")
        return default
    except Exception as e:
        if debug_mode:
            print(f"[DEBUG] Error reading {filename}: {e}")
        return default

def save_json_file(filename, data):
    """Utility function to save JSON files with consistent formatting"""
    try:
        with open(os.path.join(os.getcwd(), filename), "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        if debug_mode:
            print(f"[DEBUG] Saved {len(data)} entries to {filename}")
        return True
    except Exception as e:
        if debug_mode:
            print(f"[DEBUG] Error writing {filename}: {e}")
        return False

def build_services_data():
    """Build services data for templates, avoiding repetition"""
    service_defs = get_service_definitions()
    services = []
    all_services = []
    
    for name, env, logo in service_defs:
        url = os.getenv(env, "")
        all_services.append({"name": name, "env": env, "url": url, "logo": logo})
        if url:
            services.append({"name": name, "url": url, "logo": logo})
    
    return services, all_services

def build_public_services_data():
    """Build public services data for end users (non-admin services)"""
    service_defs = get_public_service_definitions()
    services = []
    
    for name, env, logo in service_defs:
        url = os.getenv(env, "")
        if url:
            services.append({"name": name, "url": url, "logo": logo})
    
    return services

def get_storage_info():
    """Get storage information for templates"""
    drives_env = os.getenv("DRIVES")
    if not drives_env:
        if platform.system() == "Windows":
            drives = ["C:\\"]
        else:
            drives = ["/"]
    else:
        drives = [d.strip() for d in drives_env.split(",") if d.strip()]
    
    storage_info = []
    for drive in drives:
        try:
            usage = psutil.disk_usage(drive)
            storage_info.append({
                "mount": drive,
                "used": round(usage.used / (1024**3), 1),
                "total": round(usage.total / (1024**3), 1),
                "percent": int(usage.percent)
            })
        except Exception as e:
            if debug_mode:
                print(f"Error reading {drive}: {e}")
    
    return storage_info

def get_lastfm_url(artist_name):
    """Generate Last.fm URL for an artist"""
    if not artist_name:
        return None
    
    # Clean the artist name for URL
    import urllib.parse
    # Replace spaces with + for Last.fm URL format
    clean_name = artist_name.replace(' ', '+')
    # URL encode for special characters
    encoded_name = urllib.parse.quote(clean_name)
    
    return f"https://www.last.fm/music/{encoded_name}"

def is_music_artist(poster_data):
    """Check if a poster represents a music artist"""
    if not poster_data:
        return False
    
    # Check if this is from a music library (artist type)
    # We'll need to check the library context or metadata
    # For now, we'll check if it has a title but no year (typical for artists)
    title = poster_data.get("title")
    year = poster_data.get("year")
    
    # If it has a title but no year, it's likely an artist
    # Also check if the title doesn't look like a movie/show title
    if title and year is None:
        # Additional checks could be added here
        return True
    
    return False

def get_template_context():
    """Get common template context data to avoid repetition"""
    services, all_services = build_services_data()
    storage_info = get_storage_info()
    library_notes = load_library_notes()
    
    # Load submissions
    submissions = load_json_file("plex_submissions.json", [])
    audiobookshelf_submissions = load_json_file("audiobookshelf_submissions.json", [])
    
    return {
        "services": services,
        "all_services": all_services,
        "submissions": submissions,
        "storage_info": storage_info,
        "audiobookshelf_submissions": audiobookshelf_submissions,
        "library_notes": library_notes,
        "SERVER_NAME": os.getenv("SERVER_NAME", ""),
        "ACCENT_COLOR": os.getenv("ACCENT_COLOR", "#d33fbc"),
        "PLEX_TOKEN": os.getenv("PLEX_TOKEN", ""),
        "PLEX_URL": os.getenv("PLEX_URL", ""),
        "AUDIOBOOKS_ID": os.getenv("AUDIOBOOKS_ID", ""),
        "ABS_ENABLED": os.getenv("ABS_ENABLED", "no"),
        "LIBRARY_IDS": os.getenv("LIBRARY_IDS", ""),
        "DISCORD_WEBHOOK": os.getenv("DISCORD_WEBHOOK", ""),
        "DISCORD_USERNAME": os.getenv("DISCORD_USERNAME", ""),
        "DISCORD_AVATAR": os.getenv("DISCORD_AVATAR", ""),
        "DISCORD_COLOR": os.getenv("DISCORD_COLOR", ""),
        "AUDIOBOOKSHELF_URL": os.getenv("AUDIOBOOKSHELF_URL", ""),
        "AUDIOBOOKSHELF_TOKEN": os.getenv("AUDIOBOOKSHELF_TOKEN", ""),
        "show_services": os.getenv("SHOW_SERVICES", "yes").lower() == "yes",
        "custom_services_url": os.getenv("CUSTOM_SERVICES_URL", "").strip(),
        "DISCORD_NOTIFY_PLEX": os.getenv("DISCORD_NOTIFY_PLEX", "1"),
        "DISCORD_NOTIFY_ABS": os.getenv("DISCORD_NOTIFY_ABS", "1")
    }

@app.route("/ajax/load-library-posters", methods=["POST"])
def ajax_load_library_posters():
    """Load poster data for a specific library on-demand"""
    if not session.get("authenticated"):
        return jsonify({"success": False, "error": "Unauthorized"})
    
    try:
        data = request.get_json()
        library_index = data.get("library_index")
        
        if library_index is None:
            return jsonify({"success": False, "error": "Library index required"})
        
        # Get the library info
        libraries = get_plex_libraries()
        selected_ids = os.getenv("LIBRARY_IDS", "")
        selected_ids = [i.strip() for i in selected_ids.split(",") if i.strip()]
        filtered_libraries = [lib for lib in libraries if lib["key"] in selected_ids]
        
        if library_index >= len(filtered_libraries):
            return jsonify({"success": False, "error": "Invalid library index"})
        
        library = filtered_libraries[library_index]
        section_id = library["key"]
        name = library["title"]
        
        # First, get ALL titles from the library (same as fetch_titles_for_library)
        all_titles = []
        headers = {"X-Plex-Token": PLEX_TOKEN}
        url = f"{PLEX_URL}/library/sections/{section_id}/all"
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            root = ET.fromstring(response.content)
            for el in root.findall(".//Video"):
                title = el.attrib.get("title")
                if title:
                    all_titles.append(title)
            for el in root.findall(".//Directory"):
                title = el.attrib.get("title")
                if title and title not in all_titles:
                    all_titles.append(title)
        except Exception as e:
            if debug_mode:
                print(f"Error fetching titles for section {section_id}: {e}")
        
        # Create a dictionary to map titles to their poster data
        title_to_poster = {}
        
        # Load poster metadata for this specific library
        poster_dir = os.path.join("static", "posters", section_id)
        if os.path.exists(poster_dir):
            # Get all JSON files and sort by modification time (most recent first)
            json_files = [f for f in os.listdir(poster_dir) if f.endswith(".json")]
            json_files.sort(key=lambda f: os.path.getmtime(os.path.join(poster_dir, f)), reverse=True)
            
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
                        is_artist = is_music_artist(meta)
                        lastfm_url = get_lastfm_url(title) if is_artist else None
                        
                        title_to_poster[title] = {
                            "poster": poster_url,
                            "title": title,
                            "imdb": meta.get("imdb"),
                            "tmdb": meta.get("tmdb"),
                            "tvdb": meta.get("tvdb"),
                            "lastfm_url": lastfm_url,
                            "is_artist": is_artist,
                        }
                except Exception as e:
                    if debug_mode:
                        print(f"Error loading poster metadata: {e}")
                    # Skip corrupted files
                    continue
        
        # Create unified items list - include ALL titles with poster data when available
        unified_items = []
        for title in all_titles:
            if title in title_to_poster:
                # Use poster data if available
                unified_items.append(title_to_poster[title])
            else:
                # Just the title without poster
                # Check if this might be a music artist (no year typically indicates artist)
                is_artist = is_music_artist({"title": title, "year": None})
                lastfm_url = get_lastfm_url(title) if is_artist else None
                
                unified_items.append({
                    "poster": None,
                    "title": title,
                    "imdb": None,
                    "tmdb": None,
                    "tvdb": None,
                    "lastfm_url": lastfm_url,
                    "is_artist": is_artist,
                })
        
        # Group items by letter
        poster_groups = group_posters_by_letter(unified_items)
        
        return jsonify({
            "success": True,
            "library_name": name,
            "poster_groups": poster_groups
        })
        
    except Exception as e:
        if debug_mode:
            print(f"Error loading library posters: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route("/ajax/load-posters-by-letter", methods=["POST"])
def ajax_load_posters_by_letter():
    """Load poster data for a specific library and letter on-demand"""
    if not session.get("authenticated"):
        return jsonify({"success": False, "error": "Unauthorized"})
    
    try:
        data = request.get_json()
        library_index = data.get("library_index")
        letter = data.get("letter")
        
        if library_index is None or letter is None:
            return jsonify({"success": False, "error": "Library index and letter required"})
        
        # Convert library_index to integer
        try:
            library_index = int(library_index)
        except (ValueError, TypeError):
            return jsonify({"success": False, "error": "Invalid library index format"})
        
        # Get the library info
        libraries = get_plex_libraries()
        selected_ids = os.getenv("LIBRARY_IDS", "")
        selected_ids = [i.strip() for i in selected_ids.split(",") if i.strip()]
        filtered_libraries = [lib for lib in libraries if lib["key"] in selected_ids]
        
        if library_index >= len(filtered_libraries):
            return jsonify({"success": False, "error": "Invalid library index"})
        
        library = filtered_libraries[library_index]
        section_id = library["key"]
        name = library["title"]
        
        # Get titles and metadata for this specific letter
        all_items = []
        headers = {"X-Plex-Token": PLEX_TOKEN}
        url = f"{PLEX_URL}/library/sections/{section_id}/all"
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            root = ET.fromstring(response.content)
            for el in root.findall(".//Video"):
                title = el.attrib.get("title")
                rating_key = el.attrib.get("ratingKey")
                year = el.attrib.get("year")
                if title:
                    all_items.append({
                        "title": title,
                        "ratingKey": rating_key,
                        "year": year
                    })
            for el in root.findall(".//Directory"):
                title = el.attrib.get("title")
                rating_key = el.attrib.get("ratingKey")
                year = el.attrib.get("year")
                if title:
                    # Check if this title already exists (avoid duplicates)
                    existing = next((item for item in all_items if item["title"] == title), None)
                    if not existing:
                        all_items.append({
                            "title": title,
                            "ratingKey": rating_key,
                            "year": year
                        })
        except Exception as e:
            if debug_mode:
                print(f"Error fetching titles for section {section_id}: {e}")
        
        # Filter items by letter
        letter_items = []
        for item in all_items:
            title = item["title"]
            if title:
                first_char = title[0].upper()
                if letter == "0-9" and first_char.isdigit():
                    letter_items.append(item)
                elif letter == "Other" and not first_char.isalpha() and not first_char.isdigit():
                    letter_items.append(item)
                elif first_char == letter:
                    letter_items.append(item)
        
        # Create a dictionary to map items to their poster data
        # Use a combination of title and year for better matching
        item_to_poster = {}
        
        # Load poster metadata for this specific library
        poster_dir = os.path.join("static", "posters", section_id)
        if os.path.exists(poster_dir):
            # Get all JSON files (both old format and new format)
            json_files = [f for f in os.listdir(poster_dir) if f.endswith(".json")]
            
            for fname in json_files:
                meta_path = os.path.join(poster_dir, fname)
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                    meta_title = meta.get("title")
                    meta_rating_key = meta.get("ratingKey")
                    meta_year = meta.get("year")
                    
                    if meta_title:
                        poster_file = meta.get("poster")
                        poster_url = f"/static/posters/{section_id}/{poster_file}" if poster_file else None
                        
                        # Create a unique key for this item
                        item_key = f"{meta_title}_{meta_year}" if meta_year else meta_title
                        
                        # Check if this is a music artist and add Last.fm URL
                        is_artist = is_music_artist(meta)
                        lastfm_url = get_lastfm_url(meta_title) if is_artist else None
                        
                        item_to_poster[item_key] = {
                            "poster": poster_url,
                            "title": meta_title,
                            "ratingKey": meta_rating_key,
                            "year": meta_year,
                            "imdb": meta.get("imdb"),
                            "tmdb": meta.get("tmdb"),
                            "tvdb": meta.get("tvdb"),
                            "lastfm_url": lastfm_url,
                            "is_artist": is_artist,
                        }
                except Exception as e:
                    if debug_mode:
                        print(f"Error loading poster metadata: {e}")
                    continue
        
        # Create unified items list for this letter
        unified_items = []
        for item in letter_items:
            title = item["title"]
            year = item["year"]
            rating_key = item["ratingKey"]
            
            # Create the same key format used in item_to_poster
            item_key = f"{title}_{year}" if year else title
            
            # Try to find a matching poster
            poster_found = False
            if item_key in item_to_poster:
                # Use poster data if available
                unified_items.append(item_to_poster[item_key])
                poster_found = True
            elif year and title in item_to_poster:
                # Try matching just the title (without year) if the item has a year
                unified_items.append(item_to_poster[title])
                poster_found = True
            
            if not poster_found:
                # Just the title without poster
                # Check if this might be a music artist (no year typically indicates artist)
                is_artist = is_music_artist({"title": title, "year": year})
                lastfm_url = get_lastfm_url(title) if is_artist else None
                
                unified_items.append({
                    "poster": None,
                    "title": title,
                    "ratingKey": rating_key,
                    "year": year,
                    "imdb": None,
                    "tmdb": None,
                    "tvdb": None,
                    "lastfm_url": lastfm_url,
                    "is_artist": is_artist,
                })
        
        return jsonify({
            "success": True,
            "library_name": name,
            "letter": letter,
            "items": unified_items
        })
        
    except Exception as e:
        if debug_mode:
            print(f"Error loading posters by letter: {e}")
        return jsonify({"success": False, "error": str(e)})

# Hashing and encryption utilities
def generate_salt():
    """Generate a random salt for password hashing"""
    return secrets.token_bytes(32)

def hash_password(password, salt=None):
    """Hash a password using PBKDF2 with SHA256"""
    if salt is None:
        salt = generate_salt()
    
    # Use PBKDF2 with 100,000 iterations for security
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return base64.urlsafe_b64encode(salt).decode(), key.decode()

def verify_password(password, salt, hashed_password):
    """Verify a password against its hash"""
    try:
        salt_bytes = base64.urlsafe_b64decode(salt.encode())
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_bytes,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return hmac.compare_digest(key.decode(), hashed_password)
    except Exception:
        return False

def hash_api_key(api_key):
    """Hash an API key using SHA256"""
    if not api_key:
        return ""
    return hashlib.sha256(api_key.encode()).hexdigest()

def verify_api_key(api_key, hashed_api_key):
    """Verify an API key against its hash"""
    if not api_key and not hashed_api_key:
        return True  # Both empty is valid
    if not api_key or not hashed_api_key:
        return False
    return hmac.compare_digest(hash_api_key(api_key), hashed_api_key)

def encrypt_sensitive_data(data, key=None):
    """Encrypt sensitive data using Fernet"""
    if not data:
        return None, None
    
    if key is None:
        key = Fernet.generate_key()
    
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode())
    return base64.urlsafe_b64encode(key).decode(), encrypted_data.decode()

def decrypt_sensitive_data(encrypted_data, key):
    """Decrypt sensitive data using Fernet"""
    if not encrypted_data or not key:
        return None
    
    try:
        key_bytes = base64.urlsafe_b64decode(key.encode())
        f = Fernet(key_bytes)
        decrypted_data = f.decrypt(encrypted_data.encode())
        return decrypted_data.decode()
    except Exception:
        return None

def get_api_key_with_verification(api_key_name, provided_key=None):
    """Get API key with verification - checks hashed version if available, falls back to plain text"""
    if provided_key:
        # If a key is provided, verify it against the hash
        hashed_key = os.getenv(f"{api_key_name}_HASH")
        if hashed_key:
            return verify_api_key(provided_key, hashed_key)
        else:
            # No hash available, compare with plain text
            stored_key = os.getenv(api_key_name)
            return stored_key == provided_key if stored_key else False
    
    # Return the actual key for use (plain text for backward compatibility)
    return os.getenv(api_key_name)

def save_api_key_with_hash(env_path, api_key_name, api_key_value):
    """Save API key with hash for verification"""
    if api_key_value:
        # Hash the API key
        hashed_key = hash_api_key(api_key_value)
        safe_set_key(env_path, f"{api_key_name}_HASH", hashed_key)
        # Keep plain text for backward compatibility
        safe_set_key(env_path, api_key_name, api_key_value)
    else:
        # Clear both hash and plain text
        safe_set_key(env_path, f"{api_key_name}_HASH", "")
        safe_set_key(env_path, api_key_name, "")

@app.route("/trigger-poster-downloads", methods=["POST"])
@csrf.exempt
def trigger_poster_downloads_route():
    """Manually trigger poster downloads for debugging"""
    if not session.get("admin_authenticated"):
        return jsonify({"success": False, "error": "Unauthorized"})
    
    try:
        # Ensure worker is running
        ensure_worker_running()
        
        # Get current library selection
        selected_ids = os.getenv("LIBRARY_IDS", "")
        selected_ids = [i.strip() for i in selected_ids.split(",") if i.strip()]
        all_libraries = get_plex_libraries()
        libraries = [lib for lib in all_libraries if lib["key"] in selected_ids]
        
        if libraries:
            # Queue poster downloads for background processing
            download_and_cache_posters_for_libraries(libraries, background=True)
            if debug_mode:
                print(f"[INFO] Manually triggered poster download for {len(libraries)} libraries")
        
        # Queue ABS poster download if enabled
        if os.getenv("ABS_ENABLED", "yes") == "yes":
            poster_download_queue.put(('abs', None, None))
            if debug_mode:
                print("[INFO] Manually triggered ABS poster download")
        
        return jsonify({"success": True, "message": "Poster downloads triggered"})
    except Exception as e:
        if debug_mode:
            print(f"Error triggering poster downloads: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route("/poster-status", methods=["GET"])
def poster_status():
    """Get poster download status for debugging"""
    if not session.get("admin_authenticated"):
        return jsonify({"success": False, "error": "Unauthorized"})
    
    try:
        queue_size = poster_download_queue.qsize()
        progress = get_poster_download_progress()
        
        return jsonify({
            "success": True,
            "worker_running": poster_download_running,
            "queue_size": queue_size,
            "progress": progress,
            "debug_mode": debug_mode
        })
    except Exception as e:
        if debug_mode:
            print(f"Error getting poster status: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route("/ajax/update-libraries", methods=["POST"])
def ajax_update_libraries():
    if not session.get("admin_authenticated"):
        return jsonify({"success": False, "error": "Unauthorized"})
    
    try:
        data = request.get_json()
        library_ids = data.get("library_ids", [])
        
        # Update the LIBRARY_IDS environment variable
        env_path = os.path.join(os.getcwd(), ".env")
        safe_set_key(env_path, "LIBRARY_IDS", ",".join(library_ids))
        
        # Reload environment variables
        load_dotenv(override=True)
        
        # Update library notes with media type information
        try:
            library_notes = load_library_notes()
            plex_token = os.getenv("PLEX_TOKEN")
            plex_url = os.getenv("PLEX_URL")
            
            if plex_token and plex_url:
                headers = {"X-Plex-Token": plex_token}
                
                # Get all libraries to get their media types
                url = f"{plex_url}/library/sections"
                response = requests.get(url, headers=headers, timeout=5)
                response.raise_for_status()
                root = ET.fromstring(response.text)
                
                # Create a mapping of library IDs to their media types
                id_to_media_type = {}
                for directory in root.findall(".//Directory"):
                    key = directory.attrib.get("key")
                    media_type = directory.attrib.get("type")
                    if key and media_type:
                        id_to_media_type[key] = media_type
                
                # Update library notes with media types
                updated = False
                for lib_id in library_ids:
                    if lib_id not in library_notes:
                        library_notes[lib_id] = {}
                    
                    media_type = id_to_media_type.get(lib_id)
                    if media_type and library_notes[lib_id].get('media_type') != media_type:
                        library_notes[lib_id]['media_type'] = media_type
                        updated = True
                        if debug_mode:
                            print(f"[DEBUG] Updated media type for library {lib_id}: {media_type}")
                
                if updated:
                    save_library_notes(library_notes)
                    if debug_mode:
                        print(f"[INFO] Updated media types for {len(library_ids)} libraries")
                        
        except Exception as e:
            if debug_mode:
                print(f"[WARN] Failed to update library media types: {e}")
        
        if debug_mode:
            print(f"[INFO] Updated library IDs to: {library_ids}")
        
        return jsonify({"success": True})
        
    except Exception as e:
        if debug_mode:
            print(f"Error updating libraries: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route("/ajax/get-random-posters", methods=["POST"])
@csrf.exempt
def get_random_posters():
    """Get random posters for a specific library"""
    if not session.get("authenticated"):
        return jsonify({"error": "Not authenticated"}), 401
    
    data = request.get_json()
    if not data:
        print("No JSON data received")
        print(f"Request data: {request.data}")
        print(f"Request headers: {dict(request.headers)}")
        return jsonify({"error": "No JSON data"}), 400
    
    library_name = data.get('library')
    count = data.get('count', 5)
    
    print(f"Requested posters for library: '{library_name}', count: {count}")
    print(f"Full request data: {data}")
    
    if not library_name:
        print("Library name is empty")
        return jsonify({"error": "Library name required"}), 400
    
    # Find the library by name
    libraries = get_plex_libraries()
    library = None
    for lib in libraries:
        if lib["title"] == library_name:
            library = lib
            break
    
    if not library:
        print(f"Library '{library_name}' not found. Available libraries: {[lib['title'] for lib in libraries]}")
        return jsonify({"error": f"Library '{library_name}' not found"}), 404
    
    section_id = library["key"]
    poster_dir = os.path.join("static", "posters", section_id)
    
    print(f"Looking for posters in: {poster_dir}")
    
    try:
        if os.path.exists(poster_dir):
            # Get all image files
            all_files = [f for f in os.listdir(poster_dir) if f.lower().endswith(('.webp', '.jpg', '.jpeg', '.png'))]
            
            print(f"Found {len(all_files)} poster files in {poster_dir}")
            
            if not all_files:
                print(f"No poster files found in {poster_dir}")
                return jsonify({"posters": [], "imdb_ids": []})
            
            # Get random posters
            import random
            if len(all_files) > count:
                selected_files = random.sample(all_files, count)
            else:
                selected_files = all_files
            
            posters = []
            imdb_ids = []
            lastfm_urls = []
            
            for fname in selected_files:
                poster_url = f"/static/posters/{section_id}/{fname}"
                posters.append(poster_url)
                
                # Load metadata
                json_path = os.path.join(poster_dir, fname.rsplit('.', 1)[0] + '.json')
                imdb_id = None
                lastfm_url = None
                try:
                    if os.path.exists(json_path):
                        with open(json_path, 'r', encoding='utf-8') as f:
                            meta = json.load(f)
                            imdb_id = meta.get('imdb')
                            # Check if this is a music artist
                            is_artist = is_music_artist(meta)
                            if is_artist:
                                title = meta.get('title')
                                lastfm_url = get_lastfm_url(title) if title else None
                except (IOError, json.JSONDecodeError) as e:
                    print(f"Error loading metadata for {fname}: {e}")
                    pass
                
                imdb_ids.append(imdb_id)
                lastfm_urls.append(lastfm_url)
            
            print(f"Returning {len(posters)} posters for {library_name}")
            return jsonify({
                "posters": posters,
                "imdb_ids": imdb_ids,
                "lastfm_urls": lastfm_urls
            })
        else:
            print(f"Poster directory does not exist: {poster_dir}")
            return jsonify({"posters": [], "imdb_ids": [], "lastfm_urls": []})
            
    except Exception as e:
        print(f"Error getting random posters for {library_name}: {e}")
        return jsonify({"error": "Failed to get posters"}), 500

@app.route("/ajax/get-random-posters-all", methods=["POST"])
@csrf.exempt
def get_random_posters_all():
    """Get random posters from all libraries combined (excluding music by default)"""
    if not session.get("authenticated"):
        return jsonify({"error": "Not authenticated"}), 401
    
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data"}), 400
    
    count = data.get('count', 5)
    include_music = data.get('include_music', False)  # Default to False
    
    print(f"Requested posters from all libraries, count: {count}, include_music: {include_music}")
    
    try:
        # Get all libraries
        libraries = get_plex_libraries()
        all_posters = []
        all_imdb_ids = []
        all_lastfm_urls = []
        
        # Collect posters from all libraries (excluding music unless explicitly requested)
        for lib in libraries:
            section_id = lib["key"]
            media_type = lib.get("media_type", "")
            
            # Skip music libraries unless explicitly requested
            if media_type == "artist" and not include_music:
                if debug_mode:
                    print(f"Skipping music library: {lib['title']}")
                continue
                
            poster_dir = os.path.join("static", "posters", section_id)
            
            if os.path.exists(poster_dir):
                # Get all image files
                all_files = [f for f in os.listdir(poster_dir) if f.lower().endswith(('.webp', '.jpg', '.jpeg', '.png'))]
                
                for fname in all_files:
                    poster_url = f"/static/posters/{section_id}/{fname}"
                    all_posters.append(poster_url)
                    
                    # Load metadata
                    json_path = os.path.join(poster_dir, fname.rsplit('.', 1)[0] + '.json')
                    imdb_id = None
                    lastfm_url = None
                    try:
                        if os.path.exists(json_path):
                            with open(json_path, 'r', encoding='utf-8') as f:
                                meta = json.load(f)
                                imdb_id = meta.get('imdb')
                                # Check if this is a music artist
                                is_artist = is_music_artist(meta)
                                if is_artist:
                                    title = meta.get('title')
                                    lastfm_url = get_lastfm_url(title) if title else None
                    except (IOError, json.JSONDecodeError) as e:
                        print(f"Error loading metadata for {fname}: {e}")
                        pass
                    
                    all_imdb_ids.append(imdb_id)
                    all_lastfm_urls.append(lastfm_url)
        
        if not all_posters:
            print("No posters found in any library")
            return jsonify({"posters": [], "imdb_ids": [], "lastfm_urls": []})
        
        # Get random posters from all libraries combined
        import random
        if len(all_posters) > count:
            # Get random indices
            indices = random.sample(range(len(all_posters)), count)
            selected_posters = [all_posters[i] for i in indices]
            selected_imdb_ids = [all_imdb_ids[i] for i in indices]
            selected_lastfm_urls = [all_lastfm_urls[i] for i in indices]
        else:
            selected_posters = all_posters
            selected_imdb_ids = all_imdb_ids
            selected_lastfm_urls = all_lastfm_urls
        
        print(f"Returning {len(selected_posters)} posters from all libraries")
        return jsonify({
            "posters": selected_posters,
            "imdb_ids": selected_imdb_ids,
            "lastfm_urls": selected_lastfm_urls
        })
            
    except Exception as e:
        print(f"Error getting random posters from all libraries: {e}")
        return jsonify({"error": "Failed to get posters"}), 500

if __name__ == "__main__":
    # --- Dynamic configuration for section IDs ---
    global MOVIES_SECTION_ID, SHOWS_SECTION_ID, AUDIOBOOKS_SECTION_ID
    MOVIES_SECTION_ID = os.getenv("MOVIES_ID")
    SHOWS_SECTION_ID = os.getenv("SHOWS_ID")
    AUDIOBOOKS_SECTION_ID = os.getenv("AUDIOBOOKS_ID")
    
    # Check if this is the first run (setup not complete)
    is_first_run = os.getenv("SETUP_COMPLETE", "0") != "1"
    
    # Recreate library notes on startup (only in main process, not reloader)
    if os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        recreate_library_notes()
    
    # Start background poster worker (only in main process, not reloader)
    if os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        start_background_poster_worker()
    
    try:
        if os.getenv("SETUP_COMPLETE") == "1":
            if not PLEX_TOKEN:
                if debug_mode:
                    print("[WARN] Skipping poster download: PLEX_TOKEN is not set.")
            else:
                # Ensure worker is running before queuing downloads
                ensure_worker_running()
                
                # Queue poster downloads for background processing instead of blocking startup
                selected_ids = os.getenv("LIBRARY_IDS", "")
                selected_ids = [i.strip() for i in selected_ids.split(",") if i.strip()]
                all_libraries = get_plex_libraries()
                libraries = [lib for lib in all_libraries if lib["key"] in selected_ids]
                
                if libraries:
                    # Queue for background processing (only if not already in progress)
                    if not is_poster_download_in_progress():
                        download_and_cache_posters_for_libraries(libraries, background=True)
                        if debug_mode:
                            print(f"[INFO] Queued poster download for {len(libraries)} libraries")
                    else:
                        if debug_mode:
                            print("[INFO] Poster download already in progress, skipping")
                
                # Start periodic refresh in background
                periodic_poster_refresh(libraries, interval_hours=6)
                
            # --- ADD THIS FOR ABS ---
            if os.getenv("ABS_ENABLED", "yes") == "yes":
                # Queue ABS poster download for background processing
                poster_download_queue.put(('abs', None, None))
                if debug_mode:
                    print("[INFO] Queued ABS poster download")
        else:
            if debug_mode:
                print("[INFO] Skipping poster download: setup is not complete.")
    except Exception as e:
        if debug_mode:
            print(f"Warning: Could not queue poster downloads: {e}")
    
    # After initial poster download
    debug_mode = os.getenv("FLASK_DEBUG", "0") == "1"
    
    # Start browser opening thread if this is the first run
    # Only open browser in the main process (not the reloader)
    if is_first_run and os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        print(f"\n[INFO] First run detected! Setup not complete.")
        print(f"[INFO] Server will start and browser will open automatically.")
        browser_thread = threading.Thread(target=open_browser_delayed, daemon=True)
        browser_thread.start()
    
    app.run(host="0.0.0.0", port=APP_PORT, debug=debug_mode)
