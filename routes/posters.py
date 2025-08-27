"""
Poster Management Routes Module

Handles poster-related functionality that was previously in old_app.py.
This module manages poster downloads, progress tracking, and poster display.
"""

from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify
from services.template_context_service import TemplateContextService
from services.library_service import LibraryService
from services.submissions_service import SubmissionsService
from config import get_config
import os
import json
import random
import urllib.parse

# Global functions that can be imported
def get_random_posters():
    """Get random posters for a specific library."""
    
    # Check if user is authenticated (regular or admin)
    if not session.get("authenticated", False) and not session.get("admin_authenticated", False):
        return jsonify({"error": "Not authenticated"}), 401
    
    try:
        data = request.get_json()
        if not data:
            print("No JSON data received")
            return jsonify({"error": "No JSON data"}), 400
        
        library_name = data.get('library')
        count = data.get('count', 5)
        
        print(f"Requested posters for library: '{library_name}', count: {count}")
        
        if not library_name:
            print("Library name is empty")
            return jsonify({"error": "Library name required"}), 400
        
        # Find the library by name - use local files for better performance
        from services.poster_service import PosterService
        poster_service = PosterService()
        libraries = poster_service.get_ordered_libraries()
        
        library = None
        for lib in libraries:
            if lib["title"] == library_name:
                library = lib
                break
        
        if not library:
            print(f"Library '{library_name}' not found. Available libraries: {[lib['title'] for lib in libraries]}")
            return jsonify({"error": f"Library '{library_name}' not found"}), 404
        
        section_id = library["key"]
        poster_dir = poster_service.get_library_poster_dir(section_id)
        
        print(f"Looking for posters in: {poster_dir}")
        
        if os.path.exists(poster_dir):
            # Get all image files
            all_files = [f for f in os.listdir(poster_dir) if f.lower().endswith(('.webp', '.jpg', '.jpeg', '.png'))]
            
            if not all_files:
                print(f"No poster files found in {poster_dir}")
                return jsonify({"posters": [], "imdb_ids": [], "lastfm_urls": [], "titles": []})
            
            # Get random posters
            if len(all_files) > count:
                selected_files = random.sample(all_files, count)
            else:
                selected_files = all_files
            
            posters = []
            imdb_ids = []
            lastfm_urls = []
            titles = []
            
            for fname in selected_files:
                poster_url = f"/static/posters/{section_id}/{fname}"
                posters.append(poster_url)
                
                # Extract title from filename
                title = fname.rsplit('.', 1)[0].replace('_', ' ').replace('-', ' ').title()
                titles.append(title)
                
                # Load metadata
                json_path = os.path.join(poster_dir, fname.rsplit('.', 1)[0] + '.json')
                imdb_id = None
                lastfm_url = None
                try:
                    if os.path.exists(json_path):
                        with open(json_path, 'r', encoding='utf-8') as f:
                            meta = json.load(f)
                            imdb_id = meta.get('imdb')
                            # Use metadata title if available
                            if meta.get('title'):
                                titles[-1] = meta.get('title')
                            # Check if this is a music artist
                            is_artist = poster_service.is_music_artist(meta, library)
                            if is_artist:
                                title = meta.get('title')
                                lastfm_url = poster_service.get_lastfm_url(title) if title else None
                except (IOError, json.JSONDecodeError) as e:
                    print(f"Error loading metadata for {fname}: {e}")
                    pass
                
                imdb_ids.append(imdb_id)
                lastfm_urls.append(lastfm_url)
            
            print(f"Returning {len(posters)} posters for {library_name}")
            return jsonify({
                "posters": posters,
                "imdb_ids": imdb_ids,
                "lastfm_urls": lastfm_urls,
                "titles": titles
            })
        else:
            print(f"Poster directory does not exist: {poster_dir}")
            return jsonify({"posters": [], "imdb_ids": [], "lastfm_urls": [], "titles": []})
            
    except Exception as e:
        print(f"Error in get_random_posters: {e}")
        return jsonify({"error": str(e)}), 500

def get_random_posters_all():
    """Get random posters from all libraries combined (excluding music by default)"""
    
    # Check if user is authenticated (regular or admin)
    if not session.get("authenticated", False) and not session.get("admin_authenticated", False):
        return jsonify({"error": "Not authenticated"}), 401
    
    try:
        data = request.get_json()
        if not data:
            print("No JSON data received for random posters all")
            return jsonify({"error": "No JSON data"}), 400
        
        count = data.get('count', 10)
        include_music = data.get('include_music', False)
        
        print(f"Requested random posters from all libraries, count: {count}, include_music: {include_music}")
        
        # Get all libraries from local files only (no Plex API calls)
        from services.library_service import LibraryService
        library_service = LibraryService()
        all_libraries = library_service.get_libraries_from_local_files()
        
        # First filter by LIBRARY_IDS to get only available libraries (same logic as onboarding route)
        library_ids = library_service.config.get("LIBRARY_IDS", "")
        selected_ids = [id.strip() for id in library_ids.split(",") if id.strip()]
        selected_ids_str = [str(id).strip() for id in selected_ids]
        available_libraries = [lib for lib in all_libraries if str(lib["key"]) in selected_ids_str]
        
        # Then filter by carousel settings to get libraries that should show carousels
        libraries = available_libraries.copy()
        library_carousels = library_service.config.get("LIBRARY_CAROUSELS", "")
        if library_carousels:
            # Only include libraries that have carousels enabled
            carousel_ids = [str(id).strip() for id in library_carousels.split(",") if str(id).strip()]
            libraries = [lib for lib in available_libraries if str(lib["key"]) in carousel_ids]
            print(f"Filtered to {len(libraries)} libraries with carousels enabled (from {len(available_libraries)} available libraries)")
        else:
            print(f"Using all {len(available_libraries)} available libraries for carousel")
        
        # Apply custom carousel tab order if specified
        library_carousel_order = library_service.config.get("LIBRARY_CAROUSEL_ORDER", "")
        if library_carousel_order and libraries:
            # Get the custom order of library IDs
            custom_order_ids = [str(id).strip() for id in library_carousel_order.split(",") if str(id).strip()]
            
            # Filter out non-existing library IDs and create ordered list
            ordered_libraries = []
            for lib_id in custom_order_ids:
                matching_lib = next((lib for lib in libraries if str(lib["key"]) == lib_id), None)
                if matching_lib:
                    ordered_libraries.append(matching_lib)
            
            # Add any remaining libraries that weren't in the custom order
            remaining_libs = [lib for lib in libraries if str(lib["key"]) not in custom_order_ids]
            ordered_libraries.extend(remaining_libs)
            
            # Update libraries with the custom order
            libraries = ordered_libraries
        
        all_posters = []
        all_imdb_ids = []
        all_lastfm_urls = []
        all_titles = []
        
        for library in libraries:
            section_id = library["key"]
            poster_dir = library_service.get_library_poster_dir(section_id)
            
            if os.path.exists(poster_dir):
                # Get all image files
                all_files = [f for f in os.listdir(poster_dir) if f.lower().endswith(('.webp', '.jpg', '.jpeg', '.png'))]
                
                for fname in all_files:
                    poster_url = f"/static/posters/{section_id}/{fname}"
                    
                    # Load metadata to check if it's music
                    json_path = os.path.join(poster_dir, fname.rsplit('.', 1)[0] + '.json')
                    is_music = False
                    title = fname.rsplit('.', 1)[0].replace('_', ' ').replace('-', ' ').title()
                    imdb_id = None
                    lastfm_url = None
                    
                    try:
                        if os.path.exists(json_path):
                            with open(json_path, 'r', encoding='utf-8') as f:
                                meta = json.load(f)
                                # Check if this is a music artist
                                is_music = meta.get('media_type') == 'artist' or library.get('media_type') == 'artist'
                                imdb_id = meta.get('imdb')
                                if meta.get('title'):
                                    title = meta.get('title')
                                if is_music:
                                    lastfm_url = f"https://www.last.fm/music/{urllib.parse.quote(title)}" if title else None
                    except (IOError, json.JSONDecodeError) as e:
                        print(f"Error loading metadata for {fname}: {e}")
                        pass
                    
                    # Skip music if not including music
                    if not include_music and is_music:
                        continue
                    
                    all_posters.append(poster_url)
                    all_imdb_ids.append(imdb_id)
                    all_lastfm_urls.append(lastfm_url)
                    all_titles.append(title)
        
        if not all_posters:
            print("No posters found in any library")
            return jsonify({"posters": [], "imdb_ids": [], "lastfm_urls": [], "titles": []})
        
        # Get random selection
        if len(all_posters) > count:
            indices = random.sample(range(len(all_posters)), count)
            selected_posters = [all_posters[i] for i in indices]
            selected_imdb_ids = [all_imdb_ids[i] for i in indices]
            selected_lastfm_urls = [all_lastfm_urls[i] for i in indices]
            selected_titles = [all_titles[i] for i in indices]
        else:
            selected_posters = all_posters
            selected_imdb_ids = all_imdb_ids
            selected_lastfm_urls = all_lastfm_urls
            selected_titles = all_titles
        
        print(f"Returning {len(selected_posters)} random posters from libraries with carousels enabled")
        return jsonify({
            "posters": selected_posters,
            "imdb_ids": selected_imdb_ids,
            "lastfm_urls": selected_lastfm_urls,
            "titles": selected_titles
        })
        
    except Exception as e:
        print(f"Error in get_random_posters_all: {e}")
        return jsonify({"error": "Failed to get posters"}), 500

def get_random_audiobook_posters():
    """Get random audiobook posters for display."""
    
    # Check if user is authenticated (regular or admin)
    if not session.get("authenticated", False) and not session.get("admin_authenticated", False):
        return jsonify({"error": "Not authenticated"}), 401
    
    try:
        data = request.get_json()
        if not data:
            print("No JSON data received for audiobook posters")
            return jsonify({"error": "No JSON data"}), 400
        
        count = data.get('count', 5)
        
        print(f"Requested audiobook posters, count: {count}")
        
        # Check which audiobook poster files actually exist
        audiobook_dir = os.path.join("static", "posters", "audiobooks")
        existing_paths = []
        goodreads_links = []
        titles = []
        
        try:
            if os.path.exists(audiobook_dir):
                # Get all image files
                all_files = [f for f in os.listdir(audiobook_dir) if f.lower().endswith(('.webp', '.jpg', '.jpeg', '.png'))]
                
                print(f"Found {len(all_files)} audiobook poster files")
                
                if not all_files:
                    print(f"No audiobook poster files found in {audiobook_dir}")
                    return jsonify({"posters": [], "goodreads_links": [], "titles": []})
                
                # Get random posters
                if len(all_files) > count:
                    selected_files = random.sample(all_files, count)
                else:
                    selected_files = all_files
                
                for fname in selected_files:
                    poster_url = f"/static/posters/audiobooks/{fname}"
                    existing_paths.append(poster_url)
                    
                    # Extract title from filename
                    title = fname.rsplit('.', 1)[0].replace('_', ' ').replace('-', ' ').title()
                    titles.append(title)
                    
                    # Load metadata for Goodreads link
                    json_path = os.path.join(audiobook_dir, fname.rsplit('.', 1)[0] + '.json')
                    goodreads_url = None
                    try:
                        if os.path.exists(json_path):
                            with open(json_path, 'r', encoding='utf-8') as f:
                                meta = json.load(f)
                                goodreads_url = meta.get('goodreads')
                                # Use metadata title if available
                                if meta.get('title'):
                                    titles[-1] = meta.get('title')
                    except (IOError, json.JSONDecodeError) as e:
                        print(f"Error loading metadata for {fname}: {e}")
                        pass
                    
                    goodreads_links.append(goodreads_url)
                
                print(f"Returning {len(existing_paths)} audiobook posters")
                return jsonify({
                    "posters": existing_paths,
                    "goodreads_links": goodreads_links,
                    "titles": titles
                })
            else:
                print(f"Audiobook poster directory does not exist: {audiobook_dir}")
                return jsonify({"posters": [], "goodreads_links": [], "titles": []})
                
        except Exception as e:
            print(f"Error loading audiobook posters: {e}")
            return jsonify({"posters": [], "goodreads_links": [], "titles": []})
            
    except Exception as e:
        print(f"Error in get_random_audiobook_posters: {e}")
        return jsonify({"error": "Failed to get audiobook posters"}), 500

def register_poster_routes(app):
    """Register poster management routes with the Flask app."""
    
    # Create blueprint for poster routes
    poster_bp = Blueprint('posters', __name__)
    
    # Initialize services
    template_context_service = TemplateContextService()
    library_service = LibraryService()
    submissions_service = SubmissionsService()
    
    @poster_bp.route("/refresh-library-titles", methods=["POST"])
    def refresh_library_titles():
        """Refresh library titles from Plex and Audiobookshelf."""
        
        # Check if user is authenticated
        if not session.get("admin_authenticated", False):
            return jsonify({"error": "Unauthorized"}), 401
        
        try:
            # This will be implemented with actual library title refresh logic
            return jsonify({"status": "success", "message": "Library titles refreshed successfully"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @poster_bp.route("/trigger-abs-poster-downloads", methods=["POST"])
    def trigger_abs_poster_downloads():
        """Trigger Audiobookshelf poster downloads."""
        
        # Check if user is authenticated
        if not session.get("admin_authenticated", False):
            return jsonify({"error": "Unauthorized"}), 401
        
        try:
            # Import poster service
            from services.poster_service import PosterService
            poster_service = PosterService()
            
            # Start ABS poster downloads
            success = poster_service.download_abs_audiobook_posters(check_local_first=True)
            
            if success:
                return jsonify({
                    "status": "success", 
                    "message": "ABS poster downloads started successfully"
                })
            else:
                return jsonify({
                    "status": "error", 
                    "message": "Failed to start ABS poster downloads"
                }), 500
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @poster_bp.route("/trigger-poster-downloads", methods=["POST"])
    def trigger_poster_downloads():
        """Manually trigger poster downloads for debugging."""
        
        # Check if user is authenticated
        if not session.get("admin_authenticated", False):
            return jsonify({"error": "Unauthorized"}), 401
        
        try:
            # Get selected library IDs
            library_ids = get_config().get("LIBRARY_IDS", "")
            selected_ids = [i.strip() for i in library_ids.split(",") if i.strip()]
            
            if not selected_ids:
                return jsonify({"error": "No libraries selected"}), 400
            
            # Import poster service
            from services.poster_service import PosterService
            poster_service = PosterService()
            
            # Start poster downloads for each selected library
            libraries_started = 0
            for lib_id in selected_ids:
                try:
                    success = poster_service.start_poster_download(lib_id)
                    if success:
                        libraries_started += 1
                except Exception as e:
                    print(f"Error starting poster downloads for library {lib_id}: {e}")
            
            return jsonify({
                "status": "success", 
                "message": f"Poster downloads triggered for {libraries_started} libraries"
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @poster_bp.route("/poster-status", methods=["GET"])
    def poster_status():
        """Get poster download status."""
        
        # For testing purposes, allow access without authentication
        # TODO: Re-enable authentication check in production
        # if not session.get("admin_authenticated", False):
        #     return jsonify({"error": "Unauthorized"}), 401
        
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
    
    @poster_bp.route("/poster-progress-summary", methods=["GET"])
    def poster_progress_summary():
        """Get poster download progress summary."""
        
        # Check if user is authenticated
        if not session.get("admin_authenticated", False):
            return jsonify({"error": "Unauthorized"}), 401
        
        try:
            # Import poster service
            from services.poster_service import PosterService
            poster_service = PosterService()
            
            # Get progress summary
            summary = poster_service.get_progress_summary()
            
            return jsonify({
                "status": "success",
                "summary": summary
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @poster_bp.route("/failed-downloads", methods=["GET"])
    def failed_downloads():
        """Get list of failed downloads that can be retried."""
        
        # Check if user is authenticated
        if not session.get("admin_authenticated", False):
            return jsonify({"error": "Unauthorized"}), 401
        
        try:
            # Import poster service
            from services.poster_service import PosterService
            poster_service = PosterService()
            
            # Get failed downloads
            failed_downloads = poster_service.get_failed_downloads()
            
            return jsonify({
                "status": "success",
                "failed_downloads": failed_downloads
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @poster_bp.route("/retry-download", methods=["POST"])
    def retry_download():
        """Retry a failed download."""
        
        # Check if user is authenticated
        if not session.get("admin_authenticated", False):
            return jsonify({"error": "Unauthorized"}), 401
        
        try:
            data = request.get_json()
            library_id = data.get("library_id")
            
            if not library_id:
                return jsonify({"error": "Library ID is required"}), 400
            
            # Import poster service
            from services.poster_service import PosterService
            poster_service = PosterService()
            
            # Retry the download
            success = poster_service.retry_failed_download(library_id)
            
            if success:
                return jsonify({
                    "status": "success",
                    "message": f"Retry initiated for library {library_id}"
                })
            else:
                return jsonify({
                    "status": "error",
                    "message": f"Cannot retry download for library {library_id}"
                }), 400
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @poster_bp.route("/ajax/load-library-posters", methods=["POST"])
    def load_library_posters():
        """Load posters for a specific library."""
        
        # Check if user is authenticated
        if not session.get("admin_authenticated", False):
            return jsonify({"error": "Unauthorized"}), 401
        
        try:
            data = request.get_json()
            library_id = data.get('library_id')
            
            if not library_id:
                return jsonify({"error": "Library ID is required"}), 400
            
            # Import poster service
            from services.poster_service import PosterService
            poster_service = PosterService()
            
            # Get posters for the library
            posters = poster_service.get_library_posters(library_id, limit=100)
            
            return jsonify({
                "status": "success",
                "posters": posters,
                "total": len(posters)
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    

    
    @poster_bp.route("/ajax/update-libraries", methods=["POST"])
    def update_libraries():
        """Update library information."""
        
        # Check if user is authenticated
        if not session.get("admin_authenticated", False):
            return jsonify({"error": "Unauthorized"}), 401
        
        try:
            data = request.get_json()
            libraries = data.get('libraries', [])
            
            if not libraries:
                return jsonify({"error": "Library data is required"}), 400
            
            # This will be implemented with actual library update logic
            return jsonify({"status": "success", "message": "Libraries updated successfully"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @poster_bp.route("/ajax/load-posters-by-letter", methods=["POST"])
    def load_posters_by_letter():
        """Load posters filtered by letter."""
        
        # Check if user is authenticated (regular or admin)
        if not session.get("authenticated", False) and not session.get("admin_authenticated", False):
            return jsonify({"success": False, "error": "Unauthorized"})
        
        try:
            data = request.get_json()
            letter = data.get('letter')
            library_name = data.get('library_name')
            
            if not letter or not library_name:
                return jsonify({"success": False, "error": "Letter and library name are required"})
            
            # Get ordered libraries using the helper function
            from services.poster_service import PosterService
            poster_service = PosterService()
            ordered_libraries = poster_service.get_ordered_libraries()
            
            # Find library by name
            library = None
            for lib in ordered_libraries:
                if lib["title"] == library_name:
                    library = lib
                    break
            
            if library is None:
                return jsonify({"success": False, "error": "Library not found"})
            
            section_id = library["key"]
            poster_dir = poster_service.get_library_poster_dir(section_id)
            
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
                            # Strip articles for sorting purposes
                            sort_title = poster_service.strip_articles(title)
                            
                            # Use the same letter extraction logic as the old app.py
                            letter_match = False
                            
                            if sort_title and sort_title[0].isdigit():
                                # Check if sort_title starts with a digit
                                if letter == "0-9":
                                    letter_match = True
                            else:
                                # Find the first ASCII letter in the sort_title
                                import re
                                match = re.search(r'[A-Za-z]', sort_title)
                                if match:
                                    extracted_letter = match.group(0).upper()
                                    if letter == extracted_letter:
                                        letter_match = True
                                elif any(c.isdigit() for c in sort_title):
                                    if letter == "0-9":
                                        letter_match = True
                                else:
                                    if letter == "Other":
                                        letter_match = True
                            
                            if letter_match:
                                poster_file = meta.get("poster")
                                poster_url = f"/static/posters/{section_id}/{poster_file}" if poster_file else None
                                
                                # Check if this is a music artist and add Last.fm URL
                                is_artist = poster_service.is_music_artist(meta, library)
                                lastfm_url = poster_service.get_lastfm_url(title) if is_artist else None
                                
                                # Debug logging for music detection
                                if is_artist:
                                    print(f"DEBUG: Music artist detected: {title} - Last.fm URL: {lastfm_url}")
                                
                                # Debug logging for IMDB IDs
                                imdb_id = meta.get("imdb")
                                if imdb_id:
                                    print(f"DEBUG: IMDB ID found for {title}: {imdb_id}")
                                
                                items_with_posters.append({
                                    "title": title,
                                    "poster": poster_url,
                                    "imdb": imdb_id,
                                    "tmdb": meta.get("tmdb"),
                                    "tvdb": meta.get("tvdb"),
                                    "lastfm_url": lastfm_url,
                                    "is_artist": is_artist,
                                })
                    except Exception as e:
                        print(f"Error loading poster metadata from {meta_path}: {e}")
                        continue
            
            # Sort items alphabetically by title (stripping articles for sorting)
            items_with_posters.sort(key=lambda x: poster_service.strip_articles(x["title"]).lower())
            
            print(f"DEBUG: Returning {len(items_with_posters)} items for letter '{letter}'")
            # Debug: Print first few items to check if IMDB and Last.fm links are present
            for i, item in enumerate(items_with_posters[:3]):
                print(f"DEBUG: Item {i}: {item.get('title')} - IMDB: {item.get('imdb')} - Last.fm: {item.get('lastfm_url')} - Is Artist: {item.get('is_artist')}")
            
            return jsonify({"success": True, "items": items_with_posters})
            
        except Exception as e:
            print(f"Error loading posters by letter: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({"success": False, "error": str(e)})
    
    @poster_bp.route("/ajax/trigger-smart-refresh", methods=["POST"])
    def trigger_smart_refresh():
        """Trigger smart poster refresh that only downloads new posters and removes deleted ones."""
        
        # Check if user is authenticated (admin only)
        if not session.get("admin_authenticated", False):
            return jsonify({"error": "Admin authentication required"}), 401
        
        try:
            from services.poster_service import PosterService
            poster_service = PosterService()
            
            # Trigger smart refresh
            downloaded, removed = poster_service.smart_refresh_posters(force_download=False)
            
            return jsonify({
                "success": True,
                "message": f"Smart refresh completed: {downloaded} new posters downloaded, {removed} deleted posters removed",
                "downloaded": downloaded,
                "removed": removed
            })
            
        except Exception as e:
            print(f"Error triggering smart refresh: {e}")
            return jsonify({"error": "Failed to trigger smart refresh"}), 500
    
    @poster_bp.route("/ajax/fix-missing-poster-fields", methods=["POST"])
    def fix_missing_poster_fields():
        """Fix existing metadata files that are missing the poster field."""
        
        # Check if user is authenticated (admin only)
        if not session.get("admin_authenticated", False):
            return jsonify({"error": "Admin authentication required"}), 401
        
        try:
            from services.poster_service import PosterService
            poster_service = PosterService()
            
            # Fix missing poster fields
            fixed_count = poster_service.fix_missing_poster_fields()
            
            return jsonify({
                "success": True,
                "message": f"Fixed {fixed_count} metadata files with missing poster fields",
                "fixed_count": fixed_count
            })
            
        except Exception as e:
            print(f"Error fixing missing poster fields: {e}")
            return jsonify({"error": "Failed to fix missing poster fields"}), 500
    
    # Register the blueprint with the app
    app.register_blueprint(poster_bp) 