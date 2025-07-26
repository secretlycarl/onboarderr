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

# Before load_dotenv()
if not os.path.exists('.env') and os.path.exists('empty.env'):
    print('\n[WARN] .env file not found. Copying empty.env to .env for you. Please edit .env with your settings!\n')
    shutil.copyfile('empty.env', '.env')

def is_running_in_docker():
    """Detect if the application is running inside a Docker container"""
    try:
        with open('/proc/1/cgroup', 'r') as f:
            return any('docker' in line for line in f)
    except (FileNotFoundError, PermissionError):
        # Check for Docker environment variables
        return any(var in os.environ for var in ['DOCKER_CONTAINER', 'KUBERNETES_SERVICE_HOST'])

# Application configuration
APP_PORT = 10000

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
        if title and key:
            libraries.append({"title": title, "key": key})
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
                    
                    # Update missing titles
                    updated = False
                    for lib_id in missing_titles:
                        title = id_to_title.get(lib_id)
                        if title:
                            if lib_id not in notes:
                                notes[lib_id] = {}
                            notes[lib_id]['title'] = title
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
        
        # Convert to RGB if necessary
        if img.mode in ('RGBA', 'LA', 'P'):
            img = img.convert('RGB')
        
        # Save logo based on original format
        logo_path = os.path.join('static', 'clearlogo.webp')
        if file_ext in ['.png', '.webp']:
            # For PNG and WebP, preserve original format
            if file_ext == '.png':
                logo_path = os.path.join('static', 'clearlogo.png')
                img.save(logo_path, 'PNG')
            else:  # .webp
                img.save(logo_path, 'WEBP')
        else:
            # For JPG/JPEG, convert to WebP
            img.save(logo_path, 'WEBP', quality=85)
        
        # Create favicon (32x32) - always save as WebP for consistency
        favicon = img.resize((32, 32), Image.Resampling.LANCZOS)
        favicon_path = os.path.join('static', 'favicon.webp')
        favicon.save(favicon_path, 'WEBP', quality=85)
        
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
        
        # Convert to RGB if necessary
        if img.mode in ('RGBA', 'LA', 'P'):
            img = img.convert('RGB')
        
        # Save wordmark based on original format
        wordmark_path = os.path.join('static', 'wordmark.webp')
        if file_ext in ['.png', '.webp']:
            # For PNG and WebP, preserve original format
            if file_ext == '.png':
                wordmark_path = os.path.join('static', 'wordmark.png')
                img.save(wordmark_path, 'PNG')
            else:  # .webp
                img.save(wordmark_path, 'WEBP')
        else:
            # For JPG/JPEG, convert to WebP
            img.save(wordmark_path, 'WEBP', quality=85)
        
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

    submitted = False
    library_notes = load_library_notes()
    selected_ids = os.getenv("LIBRARY_IDS", "").split(",") if os.getenv("LIBRARY_IDS") else []

    if request.method == "POST":
        email = request.form.get("email")
        selected_keys = request.form.getlist("libraries")

        if email and selected_keys:
            all_libraries = get_plex_libraries()
            key_to_title = {lib["key"]: lib["title"] for lib in all_libraries}
            selected_titles = [key_to_title.get(key, f"Unknown ({key})") for key in selected_keys]
            submission_entry = {
                "email": email,
                "libraries_keys": selected_keys,
                "libraries_titles": selected_titles,
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
        if os.path.exists(poster_dir):
            all_files = [f for f in os.listdir(poster_dir) if f.lower().endswith(('.webp', '.jpg', '.jpeg', '.png'))]
            import random
            random.shuffle(all_files)
            # Limit to 10 posters per library
            limited_files = all_files[:10]
            for fname in limited_files:
                posters.append(f"/static/posters/{section_id}/{fname}")
                json_path = os.path.join(poster_dir, fname.rsplit('.', 1)[0] + '.json')
                imdb_id = None
                if os.path.exists(json_path):
                    with open(json_path, 'r', encoding='utf-8') as f:
                        meta = json.load(f)
                        imdb_id = meta.get('imdb')
                imdb_ids.append(imdb_id)
        library_posters[name] = posters
        poster_imdb_ids[name] = imdb_ids

    pulsarr_enabled = bool(os.getenv("PULSARR"))
    overseerr_enabled = bool(os.getenv("OVERSEERR"))
    overseerr_url = os.getenv("OVERSEERR", "")

    return render_template(
        "onboarding.html",
        libraries=libraries,
        submitted=submitted,
        library_notes=library_notes,
        pulsarr_enabled=pulsarr_enabled,
        overseerr_enabled=overseerr_enabled,
        overseerr_url=overseerr_url,
        library_posters=library_posters,
        poster_imdb_ids=poster_imdb_ids
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

    return render_template(
        "audiobookshelf.html",
        submitted=submitted,
        abs_covers=abs_covers,
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
        admin_password = os.getenv("ADMIN_PASSWORD")
        site_password = os.getenv("SITE_PASSWORD")

        if entered_password == admin_password:
            session["authenticated"] = True
            session["admin_authenticated"] = True
            return redirect(url_for("services"))
        elif entered_password == site_password:
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
        for field in ["server_name", "plex_token", "plex_url", "audiobooks_id"]:
            value = request.form.get(field, "").strip()
            current_value = os.getenv(field.upper(), "")
            if value != current_value:
                safe_set_key(env_path, field.upper(), value)

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
            safe_set_key(env_path, "AUDIOBOOKSHELF_TOKEN", "")
        else:
            # If any Audiobookshelf field is filled, set ABS_ENABLED to 'yes'
            safe_set_key(env_path, "ABS_ENABLED", "yes")
            if audiobooks_id:
                safe_set_key(env_path, "AUDIOBOOKS_ID", audiobooks_id)
            if audiobookshelf_url:
                safe_set_key(env_path, "AUDIOBOOKSHELF_URL", audiobookshelf_url)
            if audiobookshelf_token:
                safe_set_key(env_path, "AUDIOBOOKSHELF_TOKEN", audiobookshelf_token)

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
        current_discord_notify_plex = os.getenv("DISCORD_NOTIFY_PLEX", "1")
        if discord_notify_plex in ["1", "0"] and discord_notify_plex != current_discord_notify_plex:
            safe_set_key(env_path, "DISCORD_NOTIFY_PLEX", discord_notify_plex)

        discord_notify_abs = request.form.get("discord_notify_abs")
        current_discord_notify_abs = os.getenv("DISCORD_NOTIFY_ABS", "1")
        if discord_notify_abs in ["1", "0"] and discord_notify_abs != current_discord_notify_abs:
            safe_set_key(env_path, "DISCORD_NOTIFY_ABS", discord_notify_abs)

        # Handle password fields
        site_password = request.form.get("site_password", "").strip()
        admin_password = request.form.get("admin_password", "").strip()
        if site_password:
            safe_set_key(env_path, "SITE_PASSWORD", site_password)
        if admin_password:
            safe_set_key(env_path, "ADMIN_PASSWORD", admin_password)

        # Handle accent color
        accent_color = request.form.get("accent_color_text", "").strip()
        current_accent_color = os.getenv("ACCENT_COLOR", "")
        if accent_color and accent_color != current_accent_color:
            safe_set_key(env_path, "ACCENT_COLOR", accent_color)

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
            if title and key:
                libraries.append({"title": title, "key": key})
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

def download_and_cache_posters_for_libraries(libraries, limit=None):
    headers = {"X-Plex-Token": PLEX_TOKEN}
    for lib in libraries:
        section_id = lib["key"]
        lib_dir = os.path.join("static", "posters", section_id)
        os.makedirs(lib_dir, exist_ok=True)
        url = f"{PLEX_URL}/library/sections/{section_id}/all"
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            root = ET.fromstring(response.content)
            posters = []
            items = []
            for el in root.findall(".//Video"):
                thumb = el.attrib.get("thumb")
                rating_key = el.attrib.get("ratingKey")
                title = el.attrib.get("title")
                if thumb and rating_key:
                    items.append({"thumb": thumb, "ratingKey": rating_key, "title": title})
            for el in root.findall(".//Directory"):
                thumb = el.attrib.get("thumb")
                rating_key = el.attrib.get("ratingKey")
                title = el.attrib.get("title")
                if thumb and rating_key and not any(i["ratingKey"] == rating_key for i in items):
                    items.append({"thumb": thumb, "ratingKey": rating_key, "title": title})
            random.shuffle(items)
            if limit is not None:
                items = items[:limit]
            for i, item in enumerate(items):
                out_path = os.path.join(lib_dir, f"poster{i+1}.webp")
                meta_path = os.path.join(lib_dir, f"poster{i+1}.json")
                if os.path.exists(out_path) and os.path.exists(meta_path):
                    continue  # Skip if already cached
                img_url = f"{PLEX_URL}{item['thumb']}?X-Plex-Token={PLEX_TOKEN}"
                try:
                    r = requests.get(img_url, headers=headers)
                    with open(out_path, "wb") as f:
                        f.write(r.content)
                except Exception as e:
                    if debug_mode:
                        print(f"Error saving {img_url}: {e}")
                # Fetch GUIDs
                guids = {"imdb": None, "tmdb": None, "tvdb": None}
                try:
                    meta_url = f"{PLEX_URL}/library/metadata/{item['ratingKey']}"
                    meta_resp = requests.get(meta_url, headers=headers, timeout=10)
                    meta_resp.raise_for_status()
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
                # Save metadata JSON
                meta = {
                    "title": item["title"],
                    "ratingKey": item["ratingKey"],
                    "imdb": guids["imdb"],
                    "tmdb": guids["tmdb"],
                    "tvdb": guids["tvdb"],
                    "poster": f"poster{i+1}.webp"
                }
                with open(meta_path, "w", encoding="utf-8") as f:
                    json.dump(meta, f, indent=2)
        except Exception as e:
            if debug_mode:
                print(f"Error fetching posters for section {section_id}: {e}")

def group_titles_by_letter(titles):
    groups = defaultdict(list)
    for title in titles:
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
                    libraries = response.json()
                    for library in libraries:
                        if library.get("type") == "audiobooks":
                            # Fetch audiobooks from this library
                            library_id = library.get("id")
                            books_response = requests.get(f"{abs_url}/api/libraries/{library_id}/items", headers=headers, timeout=10)
                            if books_response.status_code == 200:
                                books_data = books_response.json()
                                # Group by author
                                for book in books_data.get("results", []):
                                    author = book.get("author", "Unknown Author")
                                    title = book.get("title", "Unknown Title")
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
            data = resp.json()
            libraries = data.get("libraries", [])
            for library in libraries:
                if library.get("mediaType") == "book":
                    lib_id = library.get("id")
                    # Get all items in this library
                    items_resp = requests.get(f"{abs_url}/api/libraries/{lib_id}/items", headers=headers, timeout=10)
                    items_resp.raise_for_status()
                    items_data = items_resp.json()
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
    library_posters = {}
    library_poster_groups = {}
    for lib in filtered_libraries:
        section_id = lib["key"]
        name = lib["title"]
        titles = fetch_titles_for_library(section_id)
        library_media[name] = group_titles_by_letter(titles)
        # Load poster metadata for this library
        poster_dir = os.path.join("static", "posters", section_id)
        poster_items = []
        if os.path.exists(poster_dir):
            for fname in sorted(os.listdir(poster_dir)):
                if fname.endswith(".json"):
                    meta_path = os.path.join(poster_dir, fname)
                    try:
                        with open(meta_path, "r", encoding="utf-8") as f:
                            meta = json.load(f)
                        poster_file = meta.get("poster")
                        poster_url = f"/static/posters/{section_id}/{poster_file}" if poster_file else None
                        poster_items.append({
                            "poster": poster_url,
                            "title": meta.get("title"),
                            "imdb": meta.get("imdb"),
                            "tmdb": meta.get("tmdb"),
                            "tvdb": meta.get("tvdb"),
                        })
                    except Exception as e:
                        if debug_mode:
                            print(f"Error loading poster metadata: {e}")
        library_posters[name] = poster_items
        library_poster_groups[name] = group_posters_by_letter(poster_items)

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
        library_posters=library_posters,
        library_poster_groups=library_poster_groups,
        abs_books=abs_books,
        abs_book_groups=abs_book_groups,
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
        admin_password = os.getenv("ADMIN_PASSWORD")
        site_password = os.getenv("SITE_PASSWORD")

        if entered_password == admin_password:
            session["authenticated"] = True
            session["admin_authenticated"] = True
            return redirect(url_for("services"))
        elif entered_password == site_password:
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
        safe_set_key(env_path, "PLEX_TOKEN", form.get("plex_token", ""))
        safe_set_key(env_path, "PLEX_URL", form.get("plex_url", ""))
        safe_set_key(env_path, "ABS_ENABLED", abs_enabled)
        if abs_enabled == "yes":
            safe_set_key(env_path, "AUDIOBOOKS_ID", audiobooks_id)
            safe_set_key(env_path, "AUDIOBOOKSHELF_URL", audiobookshelf_url)
            audiobookshelf_token = form.get("audiobookshelf_token", "").strip()
            if audiobookshelf_token:
                safe_set_key(env_path, "AUDIOBOOKSHELF_TOKEN", audiobookshelf_token)
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

@app.route("/setup_complete")
def setup_complete():
    return render_template("setup_complete.html")

def periodic_poster_refresh(libraries, interval_hours=6):
    def refresh():
        while True:
            if debug_mode:
                print("[INFO] Refreshing library posters...")
            download_and_cache_posters_for_libraries(libraries)
            time.sleep(interval_hours * 3600)
    t = threading.Thread(target=refresh, daemon=True)
    t.start()

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

if __name__ == "__main__":
    # --- Dynamic configuration for section IDs ---
    global MOVIES_SECTION_ID, SHOWS_SECTION_ID, AUDIOBOOKS_SECTION_ID
    MOVIES_SECTION_ID = os.getenv("MOVIES_ID")
    SHOWS_SECTION_ID = os.getenv("SHOWS_ID")
    AUDIOBOOKS_SECTION_ID = os.getenv("AUDIOBOOKS_ID")
    
    # Check if this is the first run (setup not complete)
    is_first_run = os.getenv("SETUP_COMPLETE", "0") != "1"
    
    try:
        if os.getenv("SETUP_COMPLETE") == "1":
            if not PLEX_TOKEN:
                if debug_mode:
                    print("[WARN] Skipping poster download: PLEX_TOKEN is not set.")
            else:
                # Download new-style library posters
                selected_ids = os.getenv("LIBRARY_IDS", "")
                selected_ids = [i.strip() for i in selected_ids.split(",") if i.strip()]
                all_libraries = get_plex_libraries()
                libraries = [lib for lib in all_libraries if lib["key"] in selected_ids]
                download_and_cache_posters_for_libraries(libraries)
                periodic_poster_refresh(libraries, interval_hours=6)
            # --- ADD THIS FOR ABS ---
            if os.getenv("ABS_ENABLED", "yes") == "yes":
                download_abs_audiobook_posters()
        else:
            if debug_mode:
                print("[INFO] Skipping poster download: setup is not complete.")
    except Exception as e:
        if debug_mode:
            print(f"Warning: Could not download posters: {e}")
    
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