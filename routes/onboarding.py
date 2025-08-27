"""
Onboarding Routes Module

Handles the onboarding page functionality that was previously in old_app.py.
This module manages the onboarding flow for new users.
"""

from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify
from services.template_context_service import TemplateContextService
from services.library_service import LibraryService
from services.submissions_service import SubmissionsService
from config import get_config
from utils.data_utils import load_json_file
import os
import json
import random

def register_onboarding_routes(app):
    """Register onboarding routes with the Flask app."""
    
    # Create blueprint for onboarding routes
    onboarding_bp = Blueprint('onboarding', __name__)
    
    # Initialize services
    template_context_service = TemplateContextService()
    library_service = LibraryService()
    submissions_service = SubmissionsService()
    
    def get_library_poster_dir(section_id):
        """Get the poster directory for a library using the old naming format (just ID)"""
        return os.path.join("static", "posters", str(section_id))
    
    def load_section7_content():
        """Load section 7 content from JSON file"""
        content = load_json_file("section7_content.json", {})
        
        # Set defaults if file is empty or missing fields
        if not content:
            content = {
                "personal_message": "Why did I do all this? I started out collecting all the Star Trek shows because they kept jumping around to different streaming services. At some point I joined r/datahoarder and now I have about 10TB of movies, shows, music, and books. And I wanted to share! So enjoy. 🖖",
                "payment_services": [
                    {"title": "Venmo", "handle": "your-venmo"},
                    {"title": "Cashapp", "handle": "your-cashapp"},
                    {"title": "Zelle", "handle": "your-zelle"}
                ]
            }
        elif "payment_services" not in content:
            content["payment_services"] = [
                {"title": "Venmo", "handle": "your-venmo"},
                {"title": "Cashapp", "handle": "your-cashapp"},
                {"title": "Zelle", "handle": "your-zelle"}
            ]
        elif "personal_message" not in content:
            content["personal_message"] = "Why did I do all this? I started out collecting all the Star Trek shows because they kept jumping around to different streaming services. At some point I joined r/datahoarder and now I have about 10TB of movies, shows, music, and books. And I wanted to share! So enjoy. 🖖"
        
        return content
    
    @onboarding_bp.route("/onboarding", methods=["GET", "POST"])
    def onboarding():
        """Handle the onboarding page - main entry point for new users."""
        
        # Check if user is authenticated (check both admin and user sessions)
        if not session.get("admin_authenticated", False) and not session.get("authenticated", False):
            return redirect(url_for("login"))
        
        # Get configuration
        config = get_config()
        
        # Get selected library IDs
        selected_ids = [id.strip() for id in config.get("LIBRARY_IDS", "").split(",") if id.strip()]
        
        # Initialize variables
        available_libraries = []
        carousel_libraries = []
        all_libraries = []
        
        try:
            # Get all libraries from local files only (no Plex API calls for onboarding)
            all_libraries = library_service.get_libraries_from_local_files()
            
            # Filter libraries for access requests (only selected ones from LIBRARY_IDS)
            selected_ids_str = [str(id).strip() for id in selected_ids]
            available_libraries = [lib for lib in all_libraries if str(lib["key"]) in selected_ids_str]
            
            # Get libraries for carousel display (filtered by carousel settings)
            carousel_libraries = available_libraries.copy()
            library_carousels = config.get("LIBRARY_CAROUSELS", "")
            if library_carousels:
                # Only show libraries that have carousels enabled for carousel display
                carousel_ids = [str(id).strip() for id in library_carousels.split(",") if str(id).strip()]
                carousel_libraries = [lib for lib in available_libraries if str(lib["key"]) in carousel_ids]
            
            # Apply custom carousel tab order if specified
            library_carousel_order = config.get("LIBRARY_CAROUSEL_ORDER", "")
            if library_carousel_order and carousel_libraries:
                # Get the custom order of library IDs
                custom_order_ids = [str(id).strip() for id in library_carousel_order.split(",") if str(id).strip()]
                
                # Filter out non-existing library IDs and create ordered list
                ordered_libraries = []
                for lib_id in custom_order_ids:
                    matching_lib = next((lib for lib in carousel_libraries if str(lib["key"]) == lib_id), None)
                    if matching_lib:
                        ordered_libraries.append(matching_lib)
                
                # Add any remaining libraries that weren't in the custom order
                remaining_libs = [lib for lib in carousel_libraries if str(lib["key"]) not in custom_order_ids]
                ordered_libraries.extend(remaining_libs)
                
                # Update carousel_libraries with the custom order
                carousel_libraries = ordered_libraries
            
            # Order libraries for the "Select Libraries" section:
            # 1. Libraries with carousels (in carousel tab order)
            # 2. Libraries without carousels (in A-Z order)
            
            # Get carousel library IDs
            carousel_ids = set()
            if library_carousels:
                carousel_ids = {str(id).strip() for id in library_carousels.split(",") if str(id).strip()}
            
            # Create a mapping of library keys to their carousel status from all_libraries
            library_carousel_status = {}
            for lib in all_libraries:
                library_carousel_status[str(lib["key"])] = str(lib["key"]) in carousel_ids
            
            # Separate available libraries with and without carousels
            libraries_with_carousels = []
            libraries_without_carousels = []
            
            for lib in available_libraries:
                if library_carousel_status.get(str(lib["key"]), False):
                    libraries_with_carousels.append(lib)
                else:
                    libraries_without_carousels.append(lib)
            
            # Apply carousel tab order to libraries with carousels
            if library_carousel_order and libraries_with_carousels:
                custom_order_ids = [str(id).strip() for id in library_carousel_order.split(",") if str(id).strip()]
                
                # Create ordered list based on custom order
                ordered_carousel_libraries = []
                for lib_id in custom_order_ids:
                    matching_lib = next((lib for lib in libraries_with_carousels if str(lib["key"]) == lib_id), None)
                    if matching_lib:
                        ordered_carousel_libraries.append(matching_lib)
                
                # Add any remaining carousel libraries that weren't in the custom order
                remaining_carousel_libs = [lib for lib in libraries_with_carousels if str(lib["key"]) not in custom_order_ids]
                ordered_carousel_libraries.extend(remaining_carousel_libs)
                
                libraries_with_carousels = ordered_carousel_libraries
            elif libraries_with_carousels:
                # If no custom order specified, sort carousel libraries alphabetically
                libraries_with_carousels.sort(key=lambda lib: lib["title"].lower())
            
            # Sort libraries without carousels alphabetically by title
            libraries_without_carousels.sort(key=lambda lib: lib["title"].lower())
            
            # Combine the lists: carousel libraries first, then non-carousel libraries
            libraries = libraries_with_carousels + libraries_without_carousels
            
        except Exception as e:
            print(f"Failed to get libraries from local files: {e}")
            libraries = []
            all_libraries = []
            carousel_libraries = []
            available_libraries = []

        # Build static poster URLs for each library (limit to 10 per library)
        library_posters = {}
        poster_imdb_ids = {}
        for lib in carousel_libraries:
            section_id = lib["key"]
            name = lib["title"]
            poster_dir = get_library_poster_dir(section_id)
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
                print(f"Error loading posters for library {name}: {e}")
                # Continue with empty posters list
            
            library_posters[name] = posters
            poster_imdb_ids[name] = imdb_ids

        # Get service configuration
        pulsarr_enabled = bool(config.get("PULSARR"))
        overseerr_enabled = bool(config.get("OVERSEERR"))
        jellyseerr_enabled = bool(config.get("JELLYSEERR"))
        overseerr_url = config.get("OVERSEERR", "")
        jellyseerr_url = config.get("JELLYSEERR", "")
        tautulli_enabled = bool(config.get("TAUTULLI"))
        
        # Get default library setting
        default_library = config.get("DEFAULT_LIBRARY", "all")
        
        # Map "all" to "plex" for the "Random All" tab
        if default_library == "all":
            default_library = "plex"
        
        # Get all libraries to map numbers to names (use local data)
        library_map = {lib["key"]: lib["title"] for lib in all_libraries}
        
        # Check if any library has media_type of "artist" (music)
        has_music_library = any(lib.get("media_type") == "artist" for lib in carousel_libraries)
        
        # Load section 7 content
        section7_content = load_section7_content()
        
        # Get template context
        context = template_context_service.get_template_context()
        
        # Add onboarding-specific context
        context.update({
            'page_title': 'Onboarding - Onboarderr',
            'current_page': 'onboarding',
            'libraries': libraries,
            'carousel_libraries': carousel_libraries,
            'available_libraries': available_libraries,
            'all_libraries': all_libraries,
            'library_posters': library_posters,
            'poster_imdb_ids': poster_imdb_ids,
            'pulsarr_enabled': pulsarr_enabled,
            'overseerr_enabled': overseerr_enabled,
            'jellyseerr_enabled': jellyseerr_enabled,
            'overseerr_url': overseerr_url,
            'jellyseerr_url': jellyseerr_url,
            'tautulli_enabled': tautulli_enabled,
            'default_library': default_library,
            'library_map': library_map,
            'has_music_library': has_music_library,
            'section7_content': section7_content,
            # Ensure audiobookshelf tab visibility
            'abs_enabled': config.get("ABS_ENABLED", "yes") == "yes"
        })
        
        return render_template("onboarding.html", **context)
    
    # Register the blueprint with the app
    app.register_blueprint(onboarding_bp) 