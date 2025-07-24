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

# Before load_dotenv()
if not os.path.exists('.env') and os.path.exists('empty.env'):
    print('\n[WARN] .env file not found. Copying empty.env to .env for you. Please edit .env with your settings!\n')
    shutil.copyfile('empty.env', '.env')

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
        AUDIOBOOKSHELF_URL=os.getenv("AUDIOBOOKSHELF_URL", "")
    )

@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)

@app.context_processor
def inject_admin_status():
    # Make sure session is available in context
    from flask import session
    return dict(is_admin=session.get("admin_authenticated", False))

def get_plex_libraries():
    print("DEBUG: PLEX_URL =", PLEX_URL)
    headers = {"X-Plex-Token": PLEX_TOKEN}
    url = f"{PLEX_URL}/library/sections"
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
    try:
        with open(os.path.join(os.getcwd(), "library_notes.json"), "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_library_notes(notes):
    with open(os.path.join(os.getcwd(), "library_notes.json"), "w", encoding="utf-8") as f:
        json.dump(notes, f, indent=2)

def safe_set_key(env_path, key, value):
    set_key(env_path, key, value, quote_mode="never")


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
    avatar_url = os.getenv("DISCORD_AVATAR", url_for('static', filename='clearlogo.webp', _external=True))
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
        print(f"Failed to send Discord notification: {e}")

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
            try:
                with open(os.path.join(os.getcwd(), "plex_submissions.json"), "r") as f:
                    submissions = json.load(f)
            except FileNotFoundError:
                submissions = []
            submissions.append(submission_entry)
            with open(os.path.join(os.getcwd(), "plex_submissions.json"), "w") as f:
                json.dump(submissions, f, indent=2)
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
        print(f"Failed to get Plex libraries: {e}")
        libraries = []

    # Build static poster URLs for each library
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
            for fname in all_files:
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
            try:
                with open(os.path.join(os.getcwd(), "audiobookshelf_submissions.json"), "r") as f:
                    submissions = json.load(f)
            except FileNotFoundError:
                submissions = []
            submissions.append(submission_entry)
            with open(os.path.join(os.getcwd(), "audiobookshelf_submissions.json"), "w") as f:
                json.dump(submissions, f, indent=2)
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
        "audiobookshelf_url" in request.form
    ):
        env_path = os.path.join(os.getcwd(), ".env")
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
        service_defs = [
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

        return redirect(url_for("setup_complete"))

    # Handle Plex/Audiobookshelf request deletion
    if request.method == "POST":
        delete_index = int(request.form.get("delete_index", -1))
        if delete_index >= 0:
            try:
                with open(os.path.join(os.getcwd(), "plex_submissions.json"), "r") as f:
                    submissions = json.load(f)
                if 0 <= delete_index < len(submissions):
                    del submissions[delete_index]
                    with open(os.path.join(os.getcwd(), "plex_submissions.json"), "w") as f:
                        json.dump(submissions, f, indent=2)
            except Exception as e:
                print(f"Error deleting submission: {e}")
        audiobookshelf_delete_index = request.form.get("audiobookshelf_delete_index")
        if audiobookshelf_delete_index is not None:
            try:
                audiobookshelf_delete_index = int(audiobookshelf_delete_index)
                with open(os.path.join(os.getcwd(), "audiobookshelf_submissions.json"), "r") as f:
                    audiobookshelf_submissions = json.load(f)
                if 0 <= audiobookshelf_delete_index < len(audiobookshelf_submissions):
                    del audiobookshelf_submissions[audiobookshelf_delete_index]
                    with open(os.path.join(os.getcwd(), "audiobookshelf_submissions.json"), "w") as f:
                        json.dump(audiobookshelf_submissions, f, indent=2)
            except Exception as e:
                print(f"Error deleting audiobookshelf submission: {e}")

    # Load Plex submissions
    try:
        with open(os.path.join(os.getcwd(), "plex_submissions.json"), "r") as f:
            submissions = json.load(f)
    except FileNotFoundError:
        submissions = []

    # Load Audiobookshelf submissions
    try:
        with open(os.path.join(os.getcwd(), "audiobookshelf_submissions.json"), "r") as f:
            audiobookshelf_submissions = json.load(f)
    except FileNotFoundError:
        audiobookshelf_submissions = []

    # Build services list from per-service environment variables
    service_defs = [
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
    services = []
    for name, env, logo in service_defs:
        url = os.getenv(env, "")
        services.append({"name": name, "url": url or "", "logo": logo})

    # Read flags for showing/hiding services and custom URL
    show_services = os.getenv("SHOW_SERVICES", "yes").lower() == "yes"
    custom_services_url = os.getenv("CUSTOM_SERVICES_URL", "").strip()

    # --- Platform-agnostic drive detection ---
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
            print(f"Error reading {drive}: {e}")

    # Load library notes for descriptions
    library_notes = load_library_notes()
    
    return render_template(
        "services.html",
        services=services,
        submissions=submissions,
        storage_info=storage_info,
        audiobookshelf_submissions=audiobookshelf_submissions,
        # Current configuration values
        SERVER_NAME=os.getenv("SERVER_NAME", ""),
        PLEX_TOKEN=os.getenv("PLEX_TOKEN", ""),
        PLEX_URL=os.getenv("PLEX_URL", ""),
        AUDIOBOOKS_ID=os.getenv("AUDIOBOOKS_ID", ""),
        ABS_ENABLED=os.getenv("ABS_ENABLED", "no"),
        LIBRARY_IDS=os.getenv("LIBRARY_IDS", ""),
        library_notes=library_notes,
        # Discord settings
        DISCORD_WEBHOOK=os.getenv("DISCORD_WEBHOOK", ""),
        DISCORD_USERNAME=os.getenv("DISCORD_USERNAME", ""),
        DISCORD_AVATAR=os.getenv("DISCORD_AVATAR", ""),
        DISCORD_COLOR=os.getenv("DISCORD_COLOR", ""),
        AUDIOBOOKSHELF_URL=os.getenv("AUDIOBOOKSHELF_URL", ""),
        AUDIOBOOKSHELF_TOKEN=os.getenv("AUDIOBOOKSHELF_TOKEN", ""),
        show_services=show_services,
        custom_services_url=custom_services_url,
        DISCORD_NOTIFY_PLEX=os.getenv("DISCORD_NOTIFY_PLEX", "1"),
        DISCORD_NOTIFY_ABS=os.getenv("DISCORD_NOTIFY_ABS", "1")
    )

@app.route("/fetch-libraries", methods=["POST"])
def fetch_libraries():
    data = request.get_json()
    plex_token = data.get("plex_token")
    plex_url = data.get("plex_url")
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
        return jsonify({"libraries": [], "error": str(e)})

# --- Use os.path.join for all file paths ---
def download_and_cache_posters():
    headers = {'X-Plex-Token': PLEX_TOKEN}
    audiobook_dir = os.path.join("static", "posters", "audiobooks")
    os.makedirs(audiobook_dir, exist_ok=True)

    def save_images(section_id, out_dir, tag, limit):
        url = f"{PLEX_URL}/library/sections/{section_id}/all"
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
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
                print(f"Error saving {img_url}: {e}")

    # Only audiobooks (if ABS is disabled)
    if os.getenv("ABS_ENABLED", "yes") != "yes":
        print("[INFO] ABS disabled, downloading audiobook posters from Plex")
        save_images(AUDIOBOOKS_SECTION_ID, audiobook_dir, "audiobook", 25)
    else:
        # Download audiobook posters from ABS
        print("[INFO] ABS enabled, downloading audiobook posters from ABS")
        download_abs_audiobook_posters()

def download_abs_audiobook_posters():
    """Download audiobook posters from ABS API"""
    abs_url = os.getenv("AUDIOBOOKSHELF_URL")
    if not abs_url:
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
                                print(f"[WARN] Failed to get books from library {library_id}: {books_response.status_code}")
                print(f"[INFO] Downloaded {poster_count} audiobook posters")
            except Exception as e:
                print(f"[WARN] Error parsing ABS response: {e}")
                print(f"[WARN] Raw response: {response.text}")
        else:
            print(f"[WARN] Failed to connect to ABS API: {response.status_code}")
            print(f"[WARN] Response content: {response.text[:200]}...")
    except Exception as e:
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
            print(f"Error fetching titles for section {section_id}: {e}")
        return titles

    def fetch_audiobooks(section_id):
        books = {}
        abs_enabled = os.getenv("ABS_ENABLED", "yes") == "yes"
        
        if abs_enabled:
            # Fetch from ABS API
            abs_url = os.getenv("AUDIOBOOKSHELF_URL")
            if not abs_url:
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
                    print(f"[WARN] Failed to connect to ABS API: {response.status_code}")
            except Exception as e:
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
            print(f"[ABS] Error fetching books: {e}")
        return abs_books

    # Get all libraries
    try:
        libraries = get_plex_libraries()
    except Exception as e:
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
# DEBUG!!!!
    return os.getenv("SETUP_COMPLETE") == "1"

@app.before_request
def check_setup():
    allowed_endpoints = {"setup", "fetch_libraries", "static"}
    if not is_setup_complete():
        # Allow setup page, fetch-libraries API, and static files
        if request.endpoint not in allowed_endpoints and not request.path.startswith("/static"):
            return redirect(url_for("setup"))

@app.before_request
def show_restarting_page():
    if os.path.exists("/tmp/restarting_server"):
        return render_template("restarting.html"), 503

def restart_container_delayed():
    RESTART_FLAG = os.path.join(tempfile.gettempdir(), "restarting_server")
    with open(RESTART_FLAG, "w") as f:
        f.write("restarting")
    time.sleep(2)  # Give browser time to receive the response
    if platform.system() == "Windows":
        sys.exit(0)
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

        # Save SITE_PASSWORD, ADMIN_PASSWORD, DRIVES from the top entry boxes if present
        site_password = form.get("site_password_box") or form.get("site_password")
        admin_password = form.get("admin_password_box") or form.get("admin_password")
        drives = form.get("drives_box") or form.get("drives")
        if site_password is not None and admin_password is not None and drives is not None:
            if not site_password or not admin_password or not drives:
                error_message = "SITE_PASSWORD, ADMIN_PASSWORD, and DRIVES are required."
                return render_template("setup.html", error_message=error_message, prompt_passwords=True, site_password=site_password, admin_password=admin_password, drives=drives)
            if site_password == admin_password:
                error_message = "SITE_PASSWORD and ADMIN_PASSWORD must be different."
                return render_template("setup.html", error_message=error_message, prompt_passwords=True, site_password=site_password, admin_password=admin_password, drives=drives)
            safe_set_key(env_path, "SITE_PASSWORD", site_password)
            safe_set_key(env_path, "ADMIN_PASSWORD", admin_password)
            safe_set_key(env_path, "DRIVES", drives)

        abs_enabled = form.get("abs_enabled", "")
        audiobooks_id = form.get("audiobooks_id", "").strip()
        audiobookshelf_url = form.get("audiobookshelf_url", "").strip()
        discord_webhook = form.get("discord_webhook", "").strip()
        discord_username = form.get("discord_username", "").strip()
        discord_avatar = form.get("discord_avatar", "").strip()
        discord_color = form.get("discord_color", "").strip()

        # Server-side validation for ABS
        if abs_enabled == "yes":
            if not audiobooks_id:
                error_message = "Some entries are missing: Audiobook Library ID"
                return render_template("setup.html", error_message=error_message)
            if not audiobookshelf_url:
                error_message = "Some entries are missing: Audiobookshelf URL"
                return render_template("setup.html", error_message=error_message)

        # Server-side validation for Discord
        if discord_webhook:
            error_message = "Some entries are missing: Discord Webhook URL"
            return render_template("setup.html", error_message=error_message)

        safe_set_key(env_path, "SERVER_NAME", form.get("server_name", ""))
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
            print("[INFO] Refreshing library posters...")
            download_and_cache_posters_for_libraries(libraries)
            time.sleep(interval_hours * 3600)
    t = threading.Thread(target=refresh, daemon=True)
    t.start()

if __name__ == "__main__":
    # Remove the restart flag file if it exists
    RESTART_FLAG = os.path.join(tempfile.gettempdir(), "restarting_server")
    if os.path.exists(RESTART_FLAG):
        os.remove(RESTART_FLAG)
    # --- Dynamic configuration for section IDs ---
    global MOVIES_SECTION_ID, SHOWS_SECTION_ID, AUDIOBOOKS_SECTION_ID
    MOVIES_SECTION_ID = os.getenv("MOVIES_ID")
    SHOWS_SECTION_ID = os.getenv("SHOWS_ID")
    AUDIOBOOKS_SECTION_ID = os.getenv("AUDIOBOOKS_ID")
    try:
        if os.getenv("SETUP_COMPLETE") == "1":
            if not PLEX_TOKEN:
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
            print("[INFO] Skipping poster download: setup is not complete.")
    except Exception as e:
        print(f"Warning: Could not download posters: {e}")
    # After initial poster download
    debug_mode = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=10000, debug=debug_mode)