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

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY") or os.urandom(24)
csrf = CSRFProtect(app)
PASSWORD = os.getenv("SITE_PASSWORD")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")


# Plex details
PLEX_TOKEN = os.getenv("PLEX_TOKEN")
PLEX_URL = os.getenv("PLEX_URL")

@app.context_processor
def inject_server_name():
    return dict(
        SERVER_NAME=os.getenv("SERVER_NAME", "DefaultName"),
        ABS_ENABLED=os.getenv("ABS_ENABLED", "yes")
    )

@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)

def get_plex_libraries():
    headers = {"X-Plex-Token": PLEX_TOKEN}
    url = f"{PLEX_URL}/library/sections"
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

def load_library_notes():
    try:
        with open("library_notes.json", "r") as f:
            return json.load(f)
    except Exception:
        return {}

def save_library_notes(notes):
    with open("library_notes.json", "w") as f:
        json.dump(notes, f, indent=2)

def safe_set_key(env_path, key, value):
    if value != "":
        set_key(env_path, key, value)

def send_discord_notification(email, service_type):
    """Send Discord notification for form submissions"""
    webhook_url = os.getenv("DISCORD_WEBHOOK")
    if not webhook_url:
        return
    
    username = os.getenv("DISCORD_USERNAME", "Monitor")
    avatar_url = os.getenv("DISCORD_AVATAR", "")
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
                with open("plex_submissions.json", "r") as f:
                    submissions = json.load(f)
            except FileNotFoundError:
                submissions = []
            submissions.append(submission_entry)
            with open("plex_submissions.json", "w") as f:
                json.dump(submissions, f, indent=2)
            submitted = True
            send_discord_notification(email, "Plex")
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

    return render_template(
        "onboarding.html",
        libraries=libraries,
        submitted=submitted,
        library_notes=library_notes
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
                with open("audiobookshelf_submissions.json", "r") as f:
                    submissions = json.load(f)
            except FileNotFoundError:
                submissions = []
            submissions.append(submission_entry)
            with open("audiobookshelf_submissions.json", "w") as f:
                json.dump(submissions, f, indent=2)
            submitted = True
            send_discord_notification(email, "Audiobookshelf")
            # AJAX response
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"success": True})
        # AJAX error response
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": False, "error": "Missing required fields."})

    return render_template(
        "audiobookshelf.html",
        submitted=submitted
    )

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        entered_password = request.form.get("password")

        if entered_password == ADMIN_PASSWORD:
            session["authenticated"] = True
            session["admin_authenticated"] = True
            return redirect(url_for("services"))
        elif entered_password == PASSWORD:
            session["authenticated"] = True
            session["admin_authenticated"] = False
            return redirect(url_for("onboarding"))
        else:
            return render_template("login.html", error="Incorrect password")

    return render_template("login.html")

@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    if not session.get("authenticated"):
        return redirect(url_for("login"))

    if request.method == "POST":
        entered = request.form.get("admin_password")
        if entered == ADMIN_PASSWORD:
            session["admin_authenticated"] = True
            return redirect(url_for("services"))
        else:
            return render_template("admin_login.html", error="Incorrect password")

    return render_template("admin_login.html")

@app.route("/services", methods=["GET", "POST"])
def services():
    if not session.get("admin_authenticated"):
        return redirect(url_for("login"))

    # Handle admin settings form POST
    if request.method == "POST" and (
        "server_name" in request.form or
        "plex_token" in request.form or
        "plex_url" in request.form or
        "movies_id" in request.form or
        "shows_id" in request.form or
        "audiobooks_id" in request.form or
        "abs_enabled" in request.form or
        "discord_enabled" in request.form or
        "library_ids" in request.form
    ):
        env_path = os.path.join(os.path.dirname(__file__), ".env")
        # Update .env with any non-empty fields (only if they changed)
        for field in ["server_name", "plex_token", "plex_url", "movies_id", "shows_id", "audiobooks_id"]:
            value = request.form.get(field, "").strip()
            current_value = os.getenv(field.upper(), "")
            if value and value != current_value:
                set_key(env_path, field.upper(), value)
        # ABS enabled/disabled
        abs_enabled = request.form.get("abs_enabled")
        current_abs = os.getenv("ABS_ENABLED", "no")
        if abs_enabled in ["yes", "no"] and abs_enabled != current_abs:
            set_key(env_path, "ABS_ENABLED", "yes" if abs_enabled == "yes" else "no")
        # Library IDs (checkboxes)
        library_ids = request.form.getlist("library_ids")
        current_library_ids = os.getenv("LIBRARY_IDS", "")
        if library_ids and ",".join(library_ids) != current_library_ids:
            set_key(env_path, "LIBRARY_IDS", ",".join(library_ids))
        # Library descriptions (optional)
        library_notes = {}
        for lib_id in library_ids:
            desc = request.form.get(f"library_desc_{lib_id}", "").strip()
            if desc:
                library_notes[lib_id] = {"description": desc}
        if library_notes:
            with open("library_notes.json", "w", encoding="utf-8") as f:
                json.dump(library_notes, f, indent=2)
        # Discord settings
        discord_enabled = request.form.get("discord_enabled")
        current_discord = os.getenv("DISCORD_ENABLED", "no")
        if discord_enabled in ["yes", "no"] and discord_enabled != current_discord:
            set_key(env_path, "DISCORD_ENABLED", discord_enabled)
        
        discord_webhook = request.form.get("discord_webhook", "").strip()
        current_webhook = os.getenv("DISCORD_WEBHOOK", "")
        if discord_webhook and discord_webhook != current_webhook:
            set_key(env_path, "DISCORD_WEBHOOK", discord_webhook)
        
        discord_username = request.form.get("discord_username", "").strip()
        current_username = os.getenv("DISCORD_USERNAME", "")
        if discord_username and discord_username != current_username:
            set_key(env_path, "DISCORD_USERNAME", discord_username)
        
        discord_avatar = request.form.get("discord_avatar", "").strip()
        current_avatar = os.getenv("DISCORD_AVATAR", "")
        if discord_avatar and discord_avatar != current_avatar:
            set_key(env_path, "DISCORD_AVATAR", discord_avatar)
        
        discord_color = request.form.get("discord_color", "").strip()
        current_color = os.getenv("DISCORD_COLOR", "")
        if discord_color and discord_color != current_color:
            set_key(env_path, "DISCORD_COLOR", discord_color)
        return redirect(url_for("setup_complete"))

    # Handle Plex/Audiobookshelf request deletion
    if request.method == "POST":
        delete_index = int(request.form.get("delete_index", -1))
        if delete_index >= 0:
            try:
                with open("plex_submissions.json", "r") as f:
                    submissions = json.load(f)
                if 0 <= delete_index < len(submissions):
                    del submissions[delete_index]
                    with open("plex_submissions.json", "w") as f:
                        json.dump(submissions, f, indent=2)
            except Exception as e:
                print(f"Error deleting submission: {e}")
        audiobookshelf_delete_index = request.form.get("audiobookshelf_delete_index")
        if audiobookshelf_delete_index is not None:
            try:
                audiobookshelf_delete_index = int(audiobookshelf_delete_index)
                with open("audiobookshelf_submissions.json", "r") as f:
                    audiobookshelf_submissions = json.load(f)
                if 0 <= audiobookshelf_delete_index < len(audiobookshelf_submissions):
                    del audiobookshelf_submissions[audiobookshelf_delete_index]
                    with open("audiobookshelf_submissions.json", "w") as f:
                        json.dump(audiobookshelf_submissions, f, indent=2)
            except Exception as e:
                print(f"Error deleting audiobookshelf submission: {e}")

    # Load Plex submissions
    try:
        with open("plex_submissions.json", "r") as f:
            submissions = json.load(f)
    except FileNotFoundError:
        submissions = []

    # Load Audiobookshelf submissions
    try:
        with open("audiobookshelf_submissions.json", "r") as f:
            audiobookshelf_submissions = json.load(f)
    except FileNotFoundError:
        audiobookshelf_submissions = []

    services = [
        {"name": "Plex", "url": "https://app.plex.tv", "logo": "plex.webp"},
        {"name": "Tautulli", "url": "http://localhost:8181", "logo": "tautulli.webp"},
        {"name": "Audiobookshelf", "url": "http://localhost:13378", "logo": "abs.webp"},
        {"name": "qbittorrent", "url": "http://localhost:8080/", "logo": "qbit.webp"},
        {"name": "Immich", "url": "http://localhost:2283/", "logo": "immich.webp"},
        {"name": "Sonarr", "url": "http://localhost:8989/", "logo": "sonarr.webp"},
        {"name": "Radarr", "url": "http://localhost:7878/", "logo": "radarr.webp"},
        {"name": "Lidarr", "url": "http://localhost:8686", "logo": "lidarr.webp"},
        {"name": "Prowlarr", "url": "http://localhost:9696/", "logo": "prowlarr.webp"},
        {"name": "Bazarr", "url": "http://localhost:6767/", "logo": "bazarr.webp"},
        {"name": "Pulsarr", "url": "http://localhost:3003/", "logo": "pulsarr.webp"}
    ]

    drives = os.getenv("DRIVES", "").split(",")
    drives = [d.strip() for d in drives if d.strip()]
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
        MOVIES_ID=os.getenv("MOVIES_ID", ""),
        SHOWS_ID=os.getenv("SHOWS_ID", ""),
        AUDIOBOOKS_ID=os.getenv("AUDIOBOOKS_ID", ""),
        ABS_ENABLED=os.getenv("ABS_ENABLED", "no"),
        LIBRARY_IDS=os.getenv("LIBRARY_IDS", ""),
        library_notes=library_notes,
        # Discord settings
        DISCORD_ENABLED=os.getenv("DISCORD_ENABLED", "no"),
        DISCORD_WEBHOOK=os.getenv("DISCORD_WEBHOOK", ""),
        DISCORD_USERNAME=os.getenv("DISCORD_USERNAME", ""),
        DISCORD_AVATAR=os.getenv("DISCORD_AVATAR", ""),
        DISCORD_COLOR=os.getenv("DISCORD_COLOR", "")
    )

@app.route("/posters")
def get_random_posters():
    paths = [f"/static/posters/movies/movie{i+1}.webp" for i in range(25)]
    random.shuffle(paths)
    return jsonify(paths)

@app.route("/show-posters")
def get_random_show_posters():
    paths = [f"/static/posters/shows/show{i+1}.webp" for i in range(25)]
    random.shuffle(paths)
    return jsonify(paths)

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

def download_and_cache_posters():
    headers = {'X-Plex-Token': PLEX_TOKEN}
    movie_dir = os.path.join("static", "posters", "movies")
    show_dir = os.path.join("static", "posters", "shows")
    audiobook_dir = os.path.join("static", "posters", "audiobooks")
    os.makedirs(movie_dir, exist_ok=True)
    os.makedirs(show_dir, exist_ok=True)
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
            elements = root.findall(".//Directory" if section_id != MOVIES_SECTION_ID else ".//Video")
            posters = [el.attrib.get("thumb") for el in elements if el.attrib.get("thumb")]
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

    save_images(MOVIES_SECTION_ID, movie_dir, "movie", 25)
    save_images(SHOWS_SECTION_ID, show_dir, "show", 25)
    if os.getenv("ABS_ENABLED", "yes") == "yes":
        save_images(AUDIOBOOKS_SECTION_ID, audiobook_dir, "audiobook", 25)

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

@app.route("/medialists")
def medialists():
    if not session.get("authenticated"):
        return redirect(url_for("login"))

    # Movies and Shows: get all titles from the section
    def fetch_titles(section_id, is_show=False):
        titles = []
        if not section_id:
            return titles
        headers = {"X-Plex-Token": PLEX_TOKEN}
        url = f"{PLEX_URL}/library/sections/{section_id}/all"
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            root = ET.fromstring(response.content)
            if is_show:
                for show in root.findall(".//Directory"):
                    title = show.attrib.get("title")
                    if title:
                        titles.append(title)
            else:
                for video in root.findall(".//Video"):
                    title = video.attrib.get("title")
                    if title:
                        titles.append(title)
        except Exception as e:
            print(f"Error fetching titles for section {section_id}: {e}")
        return titles

    # Audiobooks: group by author, each author has a list of books
    def fetch_audiobooks(section_id):
        books = {}
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
            print(f"Error fetching audiobooks: {e}")
        return books

    movies = fetch_titles(MOVIES_SECTION_ID)
    shows = fetch_titles(SHOWS_SECTION_ID, is_show=True)
    audiobooks = {}
    abs_enabled = os.getenv("ABS_ENABLED", "yes") == "yes"
    if abs_enabled and AUDIOBOOKS_SECTION_ID:
        audiobooks = fetch_audiobooks(AUDIOBOOKS_SECTION_ID)

    movies_grouped = group_titles_by_letter(movies) if len(movies) > 300 else None
    shows_grouped = group_titles_by_letter(shows) if len(shows) > 300 else None

    return render_template(
        "medialists.html",
        movies=movies,
        shows=shows,
        audiobooks=audiobooks if abs_enabled else None,
        abs_enabled=abs_enabled,
        movies_grouped=movies_grouped,
        shows_grouped=shows_grouped
    )

@app.route("/audiobook-covers")
def get_random_audiobook_covers():
    if os.getenv("ABS_ENABLED", "yes") != "yes":
        return ("Not Found", 404)
    paths = [f"/static/posters/audiobooks/audiobook{i+1}.webp" for i in range(25)]
    random.shuffle(paths)
    return jsonify(paths)

def is_setup_complete():
    return os.getenv("SETUP_COMPLETE") == "1"

@app.before_request
def check_setup():
    allowed_endpoints = {"setup", "fetch_libraries", "static"}
    if not is_setup_complete():
        # Allow setup page, fetch-libraries API, and static files
        if request.endpoint not in allowed_endpoints and not request.path.startswith("/static"):
            return redirect(url_for("setup"))

@app.route("/setup", methods=["GET", "POST"])
def setup():
    if is_setup_complete():
        return redirect(url_for("login"))
    error_message = None
    if request.method == "POST":
        from dotenv import set_key
        env_path = os.path.join(os.getcwd(), ".env")
        form = request.form
        abs_enabled = form.get("abs_enabled", "")
        audiobooks_id = form.get("audiobooks_id", "").strip()
        discord_enabled = form.get("discord_enabled", "")
        discord_webhook = form.get("discord_webhook", "").strip()
        discord_username = form.get("discord_username", "").strip()
        discord_avatar = form.get("discord_avatar", "").strip()
        discord_color = form.get("discord_color", "").strip()

        # Server-side validation for ABS
        if abs_enabled == "yes" and not audiobooks_id:
            error_message = "Some entries are missing: Audiobook Library ID"
            return render_template("setup.html", error_message=error_message)

        # Server-side validation for Discord
        if discord_enabled == "yes" and not discord_webhook:
            error_message = "Some entries are missing: Discord Webhook URL"
            return render_template("setup.html", error_message=error_message)

        set_key(env_path, "SERVER_NAME", form.get("server_name", ""))
        set_key(env_path, "PLEX_TOKEN", form.get("plex_token", ""))
        set_key(env_path, "PLEX_URL", form.get("plex_url", ""))
        set_key(env_path, "MOVIES_ID", form.get("movies_id", ""))
        set_key(env_path, "SHOWS_ID", form.get("shows_id", ""))
        safe_set_key(env_path, "ABS_ENABLED", abs_enabled)
        if abs_enabled == "yes":
            safe_set_key(env_path, "AUDIOBOOKS_ID", audiobooks_id)
        # Save Discord settings
        safe_set_key(env_path, "DISCORD_ENABLED", discord_enabled)
        if discord_enabled == "yes":
            safe_set_key(env_path, "DISCORD_WEBHOOK", discord_webhook)
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
                set_key(env_path, "LIBRARY_IDS", ",".join(library_ids))
                set_key(env_path, "LIBRARY_NAMES", ",".join([t or "" for t in selected_titles]))
                # Save library notes with title and description
                for lib_id in library_ids:
                    desc = form.get(f"library_desc_{lib_id}", "")
                    library_notes[lib_id] = {
                        "title": id_to_title.get(lib_id, f"Unknown ({lib_id})"),
                        "description": desc
                    }
                save_library_notes(library_notes)
            except Exception as e:
                set_key(env_path, "LIBRARY_IDS", ",".join(library_ids))
                set_key(env_path, "LIBRARY_NAMES", "")
        set_key(env_path, "SETUP_COMPLETE", "1")
        load_dotenv(override=True)
        return redirect(url_for("setup_complete"))
    return render_template("setup.html", error_message=error_message)

@app.route("/setup_complete")
def setup_complete():
    return render_template("setup_complete.html")

if __name__ == "__main__":
    # Always use latest env values for section IDs
    global MOVIES_SECTION_ID, SHOWS_SECTION_ID, AUDIOBOOKS_SECTION_ID
    MOVIES_SECTION_ID = os.getenv("MOVIES_ID")
    SHOWS_SECTION_ID = os.getenv("SHOWS_ID")
    AUDIOBOOKS_SECTION_ID = os.getenv("AUDIOBOOKS_ID")
    try:
        download_and_cache_posters()
    except Exception as e:
        print(f"Warning: Could not download posters: {e}")
    app.run(host="0.0.0.0", port=10000, debug=True)
