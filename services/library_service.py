"""
Library Service for Onboarderr

This service handles library-related operations including loading libraries
from files, managing library notes, and other library-specific functionality.
"""

import os
import time
import requests
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
import json
from threading import Lock
import threading

from config import get_config
from utils.data_utils import load_json_file, save_json_file
from utils.logging_utils import log_debug, log_error
from utils.network_utils import retry_operation

class LibraryService:
    """Service for handling library operations."""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        """Implement singleton pattern."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        """Initialize the library service."""
        # Only initialize once
        if hasattr(self, '_initialized'):
            return
            
        # Only log initialization in verbose debug mode
        if os.getenv("VERBOSE_DEBUG", "0") == "1":
            log_debug("library_service", "Initializing LibraryService")
        self.config = get_config()
        
        # Library caching infrastructure
        self.library_cache = {}
        self.library_cache_timestamp = 0
        self.library_cache_lock = Lock()
        self.library_cache_ttl = self.config.get_int("LIBRARY_CACHE_TTL", 43200)
        
        # Configuration caching to reduce repeated calls
        self._config_cache = {}
        self._config_cache_timestamp = 0
        self._config_cache_ttl = 60  # Cache config values for 60 seconds
        
        self._initialized = True
        if os.getenv("VERBOSE_DEBUG", "0") == "1":
            log_debug("library_service", "LibraryService initialized")
    
    def _get_cached_config(self, key: str, default: Any = None) -> str:
        """Get configuration value with caching to reduce repeated calls."""
        import time
        current_time = time.time()
        
        # Return cached value if still valid
        if (self._config_cache and 
            current_time - self._config_cache_timestamp < self._config_cache_ttl and
            key in self._config_cache):
            return self._config_cache[key]
        
        # Get fresh value and cache it
        value = self.config.get(key, default)
        
        # Update cache
        if not self._config_cache:
            self._config_cache = {}
        self._config_cache[key] = value
        self._config_cache_timestamp = current_time
        
        return value
    
    def get_plex_libraries(self, force_refresh: bool = False) -> List[Dict[str, Any]]:
        """
        Get Plex libraries with caching support and improved error handling.
        
        Args:
            force_refresh: If True, bypass cache and fetch fresh data
            
        Returns:
            List of library dictionaries
        """
        current_time = time.time()
        
        # Check if we have valid cached data
        if not force_refresh and self.library_cache and (current_time - self.library_cache_timestamp) < self.library_cache_ttl:
            log_debug("library_service", f"Using cached library data (age: {current_time - self.library_cache_timestamp:.1f}s)")
            return self.library_cache
        
        # Get Plex credentials with validation
        plex_token = self._get_cached_config("PLEX_TOKEN")
        plex_url = self._get_cached_config("PLEX_URL")
        
        log_debug("library_service", "Getting Plex libraries...")
        log_debug("library_service", f"PLEX_URL = {plex_url}")
        log_debug("library_service", f"PLEX_TOKEN = {plex_token[:10]}..." if plex_token else "PLEX_TOKEN = None")
        
        # Validate Plex configuration
        if not self.config.validate_token(plex_token, "PLEX_TOKEN"):
            log_error("plex_config", "Invalid Plex token", {"has_token": bool(plex_token)})
            return []
        
        if not self.config.validate_url(plex_url, "PLEX_URL"):
            log_error("plex_config", "Invalid Plex URL", {"url": plex_url})
            return []
        
        headers = {"X-Plex-Token": plex_token}
        
        # Ensure plex_url has a scheme
        if plex_url and not plex_url.startswith(('http://', 'https://')):
            plex_url = f"http://{plex_url}"  # Default to http if no scheme provided
            log_debug("library_service", f"Added scheme to PLEX_URL: {plex_url}")
        
        url = f"{plex_url}/library/sections"
        log_debug("library_service", f"Making request to: {url}")
        
        def fetch_plex_libraries():
            """Inner function for retry mechanism"""
            # Apply API rate limiting
            from services.rate_limit_service import RateLimitService
            rate_limit_service = RateLimitService(self.config)
            rate_limit_service.initialize()
            rate_limit_service.check_api_rate_limit('plex')
            
            timeout = self.config.get_int("PLEX_API_TIMEOUT", 10)
            response = requests.get(url, headers=headers, timeout=timeout)
            response.raise_for_status()
            return response.text
        
        try:
            # Use retry mechanism for Plex API calls
            response_text = retry_operation(
                fetch_plex_libraries,
                max_retries=3,
                delay=2.0,
                operation_name="plex_library_fetch"
            )
            
            root = ET.fromstring(response_text)
            libraries = []
            
            for directory in root.findall(".//Directory"):
                title = directory.attrib.get("title")
                key = directory.attrib.get("key")
                media_type = directory.attrib.get("type")
                
                if title and key:
                    libraries.append({
                        "title": title, 
                        "key": key, 
                        "media_type": media_type
                    })
                    log_debug("library_service", f"Found library: {title} (ID: {key}, Type: {media_type})")
            
            log_debug("library_service", f"Total libraries found: {len(libraries)}")
            
            # Update cache with thread safety
            with self.library_cache_lock:
                self.library_cache = libraries
                self.library_cache_timestamp = current_time
            
            return libraries
            
        except requests.exceptions.MissingSchema as e:
            log_error("plex_url", f"Invalid Plex URL (missing scheme): {plex_url}", {"original_url": plex_url}, e)
            raise
        except requests.exceptions.RequestException as e:
            log_error("plex_connection", f"Failed to connect to Plex: {e}", {"url": url}, e)
            raise
        except ET.ParseError as e:
            log_error("plex_parse", "Failed to parse Plex XML response", {"url": url}, e)
            raise
        except Exception as e:
            log_error("plex_unknown", "Unexpected error fetching Plex libraries", {"url": url}, e)
            raise
    
    def clear_library_cache(self):
        """Clear the library cache to force fresh data on next request"""
        with self.library_cache_lock:
            self.library_cache = {}
            self.library_cache_timestamp = 0
        log_debug("library_service", "Library cache cleared")
    
    def clear_config_cache(self):
        """Clear the configuration cache to force fresh config values on next request"""
        self._config_cache = {}
        self._config_cache_timestamp = 0
        log_debug("library_service", "Configuration cache cleared")
    
    def clear_all_caches(self):
        """Clear all caches"""
        self.clear_library_cache()
        self.clear_config_cache()
        log_debug("library_service", "All caches cleared")
    
    def cleanup_library_cache(self):
        """Clean up library cache to prevent memory leaks"""
        with self.library_cache_lock:
            # If cache is too large, clear it
            if len(self.library_cache) > 100:  # More than 100 libraries cached
                self.library_cache = {}
                log_debug("library_service", "Library cache cleared due to size limit")
            
            # Clear cache if it's older than 1 hour
            current_time = time.time()
            if self.library_cache_timestamp > 0 and (current_time - self.library_cache_timestamp) > 3600:
                self.library_cache = {}
                self.library_cache_timestamp = 0
                log_debug("library_service", "Library cache cleared due to age")
    
    def get_libraries_from_local_files(self) -> List[Dict[str, Any]]:
        """
        Get libraries from local cache files for better performance.
        Uses library_notes.json and poster directories like the old app.
        
        Returns:
            List of library dictionaries
        """
        log_debug("library_service", "Getting libraries from local files")
        
        libraries = []
        library_notes = self.load_library_notes()
        
        # Get all library IDs from library_notes.json
        for lib_id, note_data in library_notes.items():
            title = note_data.get("title", f"Library {lib_id}")
            # Check if poster directory exists to determine media type
            poster_dir = self.get_library_poster_dir(lib_id)
            media_type = "show"  # Default to show
            
            if os.path.exists(poster_dir):
                # Try to determine media type from existing posters
                poster_files = [f for f in os.listdir(poster_dir) if f.lower().endswith(('.webp', '.jpg', '.jpeg', '.png'))]
                if poster_files:
                    # Check first poster's metadata to determine media type
                    first_poster = poster_files[0]
                    json_path = os.path.join(poster_dir, first_poster.rsplit('.', 1)[0] + '.json')
                    if os.path.exists(json_path):
                        try:
                            with open(json_path, 'r', encoding='utf-8') as f:
                                meta = json.load(f)
                                # Check if it's a music artist
                                if meta.get('type') == 'artist' or 'artist' in meta.get('title', '').lower():
                                    media_type = "artist"
                                elif meta.get('type') == 'movie':
                                    media_type = "movie"
                                elif meta.get('type') == 'show':
                                    media_type = "show"
                        except (IOError, json.JSONDecodeError):
                            pass
            
            libraries.append({
                "title": title,
                "key": lib_id,
                "media_type": media_type
            })
            
            log_debug("library_service", f"Found local library: {title} (ID: {lib_id}, Type: {media_type})")
        
        log_debug("library_service", f"Total libraries from local files: {len(libraries)}")
        return libraries
    
    def load_library_notes(self) -> Dict[str, Any]:
        """
        Load library notes from file.
        
        Returns:
            Dictionary of library notes
        """
        log_debug("library_service", "Loading library notes from file")
        notes = load_json_file("library_notes.json", {})
        log_debug("library_service", f"Loaded {len(notes)} library notes from file")
        return notes
    
    def save_library_notes(self, notes: Dict[str, Any]) -> bool:
        """
        Save library notes to file.
        
        Args:
            notes: Library notes to save
            
        Returns:
            True if successful, False otherwise
        """
        log_debug("library_service", f"save_library_notes called with: {notes}")
        result = save_json_file("library_notes.json", notes)
        log_debug("library_service", f"save_json_file result: {result}")
        return result
    
    def load_section7_content(self) -> Dict[str, Any]:
        """
        Load section 7 content from JSON file.
        
        Returns:
            Section 7 content dictionary
        """
        log_debug("library_service", "Loading section 7 content from file")
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
        
        log_debug("library_service", f"Loaded section 7 content: {content}")
        return content
    
    def save_section7_content(self, content: Dict[str, Any]) -> bool:
        """
        Save section 7 content to JSON file.
        
        Args:
            content: Section 7 content to save
            
        Returns:
            True if successful, False otherwise
        """
        log_debug("library_service", f"Saving section 7 content: {content}")
        result = save_json_file("section7_content.json", content)
        log_debug("library_service", f"Section 7 content save result: {result}")
        return result
    
    def recreate_library_notes(self) -> bool:
        """
        Update library notes on startup by fetching current library information from Plex.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            plex_token = self._get_cached_config("PLEX_TOKEN")
            plex_url = self._get_cached_config("PLEX_URL")
            
            if not plex_token or not plex_url:
                log_debug("library_service", "Plex token or URL not configured, skipping library notes update")
                return False
            
            log_debug("library_service", "Updating library notes from Plex API")
            
            # Load existing library notes to preserve descriptions
            existing_notes = self.load_library_notes()
            
            # Get selected library IDs from environment
            selected_ids_str = self._get_cached_config("LIBRARY_IDS", "")
            selected_ids = []
            if selected_ids_str:
                # Split by comma and clean up whitespace
                selected_ids = [id.strip() for id in selected_ids_str.split(",") if id.strip()]
            
            log_debug("library_service", f"Selected library IDs from environment: {selected_ids}")
            
            headers = {"X-Plex-Token": plex_token}
            updated_count = 0
            
            # Only fetch selected libraries individually to avoid processing unselected ones
            for lib_id in selected_ids:
                url = f"{plex_url}/library/sections/{lib_id}"
                try:
                    timeout = self.config.get_int("GENERAL_API_TIMEOUT", 5)
                    response = requests.get(url, headers=headers, timeout=timeout)
                    response.raise_for_status()
                    root = ET.fromstring(response.text)
                    
                    directory = root.find(".//Directory")
                    if directory is not None:
                        title = directory.get("title", f"Library {lib_id}")
                        key = directory.get("key", lib_id)
                        
                        # Preserve existing description if available
                        existing_description = existing_notes.get(key, {}).get("description", "")
                        
                        # Update library note
                        existing_notes[key] = {
                            "title": title,
                            "description": existing_description,
                            "updated_at": datetime.now(timezone.utc).isoformat() + "Z"
                        }
                        updated_count += 1
                        log_debug("library_service", f"Updated library note for {title} (ID: {key})")
                    
                except Exception as e:
                    log_debug("library_service", f"Error updating library {lib_id}: {e}")
                    continue
            
            # Save updated notes
            if updated_count > 0:
                success = self.save_library_notes(existing_notes)
                log_debug("library_service", f"Updated {updated_count} library notes, save result: {success}")
                return success
            else:
                log_debug("library_service", "No library notes updated")
                return True
                
        except Exception as e:
            log_debug("library_service", f"Error recreating library notes: {e}")
            return False
    
    def get_selected_library_ids(self) -> List[str]:
        """
        Get the list of selected library IDs from configuration.
        
        Returns:
            List of selected library IDs
        """
        selected_ids_str = self._get_cached_config("LIBRARY_IDS", "")
        if not selected_ids_str:
            return []
        
        selected_ids = [id.strip() for id in selected_ids_str.split(",") if id.strip()]
        log_debug("library_service", f"Selected library IDs: {selected_ids}")
        return selected_ids
    
    def get_filtered_libraries(self) -> List[Dict[str, Any]]:
        """
        Get libraries filtered by selected IDs.
        
        Returns:
            List of filtered libraries
        """
        log_debug("library_service", "Getting filtered libraries")
        libraries = self.get_libraries_from_local_files()
        selected_ids = self.get_selected_library_ids()
        
        if not selected_ids:
            log_debug("library_service", "No selected library IDs, returning all libraries")
            return libraries
        
        filtered_libraries = [lib for lib in libraries if lib.get("key") in selected_ids]
        log_debug("library_service", f"Filtered {len(filtered_libraries)} libraries from {len(libraries)} total")
        return filtered_libraries
    
    def get_ordered_libraries(self) -> List[Dict[str, Any]]:
        """
        Get libraries with the same ordering logic as the main medialists route.
        
        Returns:
            List of ordered libraries
        """
        log_debug("library_service", "Getting ordered libraries")
        # Get all libraries - use local files for better performance (no Plex API calls)
        try:
            libraries = self.get_libraries_from_local_files()
        except Exception as e:
            log_debug("library_service", f"Failed to get libraries from local files: {e}")
            libraries = []

        # Only include libraries specified in LIBRARY_IDS
        selected_ids = self._get_cached_config("LIBRARY_IDS", "")
        selected_ids = [i.strip() for i in selected_ids.split(",") if i.strip()]
        filtered_libraries = [lib for lib in libraries if lib["key"] in selected_ids]

        # Apply the same ordering logic as onboarding:
        # 1. Libraries with carousels first (in carousel tab order)
        # 2. Libraries without carousels (in A-Z order)
        # 3. Audiobooks at the bottom
        
        # Get carousel library IDs
        library_carousels = self._get_cached_config("LIBRARY_CAROUSELS", "")
        carousel_ids = set()
        if library_carousels:
            carousel_ids = {str(id).strip() for id in library_carousels.split(",") if str(id).strip()}
        
        # Separate libraries with and without carousels
        libraries_with_carousels = []
        libraries_without_carousels = []
        
        for lib in filtered_libraries:
            if str(lib["key"]) in carousel_ids:
                libraries_with_carousels.append(lib)
            else:
                libraries_without_carousels.append(lib)
        
        # Apply carousel tab order to libraries with carousels
        library_carousel_order = self._get_cached_config("LIBRARY_CAROUSEL_ORDER", "")
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
        ordered_libraries = libraries_with_carousels + libraries_without_carousels
        log_debug("library_service", f"Returning {len(ordered_libraries)} ordered libraries")
        return ordered_libraries
    
    def fetch_titles_for_library(self, section_id: str) -> List[Dict[str, Any]]:
        """
        Fetch titles for a specific library from local cache.
        
        Args:
            section_id: The library section ID
            
        Returns:
            List of title dictionaries
        """
        log_debug("library_service", f"Fetching titles for library {section_id}")
        try:
            # Try to load from local cache first
            cache_file = f"library_{section_id}_titles.json"
            titles = load_json_file(cache_file, [])
            log_debug("library_service", f"Loaded {len(titles)} titles from cache for library {section_id}")
            return titles
        except Exception as e:
            log_debug("library_service", f"Error fetching titles for library {section_id}: {e}")
            return []
    
    def group_titles_by_letter(self, titles: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Group titles by first letter for alphabetical display.
        
        Args:
            titles: List of title dictionaries
            
        Returns:
            Dictionary with letter keys and title lists as values
        """
        log_debug("library_service", f"Grouping {len(titles)} titles by letter")
        grouped = {}
        
        for title in titles:
            title_name = title.get("title", "")
            if title_name:
                first_letter = title_name[0].upper()
                if first_letter.isalpha():
                    if first_letter not in grouped:
                        grouped[first_letter] = []
                    grouped[first_letter].append(title)
                else:
                    # Group non-alphabetic titles under "#"
                    if "#" not in grouped:
                        grouped["#"] = []
                    grouped["#"].append(title)
        
        # Sort titles within each group
        for letter in grouped:
            grouped[letter].sort(key=lambda x: x.get("title", "").lower())
        
        log_debug("library_service", f"Grouped titles into {len(grouped)} letter groups")
        return grouped
    
    def get_library_poster_dir(self, library_id: str) -> str:
        """Get the poster directory path for a library using the old naming format (just ID)"""
        return os.path.join("static", "posters", str(library_id))
    
    def is_music_artist(self, meta: Dict[str, Any], library: Dict[str, Any]) -> bool:
        """Check if the metadata represents a music artist."""
        # Check if this is a music library
        if library.get("type") == "artist":
            return True
        
        # Check metadata for music-specific fields
        if meta.get("type") == "artist":
            return True
        
        # Check for music-specific genres
        genres = meta.get("genres", [])
        music_genres = ["music", "rock", "pop", "jazz", "classical", "hip hop", "country", "electronic"]
        if any(genre.lower() in music_genres for genre in genres):
            return True
        
        return False
    
    def get_lastfm_url(self, title: str) -> str:
        """Generate Last.fm URL for a music artist."""
        if not title:
            return ""
        
        # URL encode the title
        import urllib.parse
        encoded_title = urllib.parse.quote(title)
        return f"https://www.last.fm/music/{encoded_title}"
    
    def strip_articles(self, title: str) -> str:
        """
        Strip articles (A, An, The) from the beginning of a title for sorting purposes.
        
        Args:
            title: The title to process
            
        Returns:
            Title with articles stripped
        """
        if not title:
            return title
        
        # Remove leading whitespace and convert to lowercase for comparison
        title_clean = title.strip()
        title_lower = title_clean.lower()
        
        # Check for articles at the beginning
        if title_lower.startswith('the '):
            return title_clean[4:].strip()  # Remove "The " and any trailing whitespace
        elif title_lower.startswith('a '):
            return title_clean[2:].strip()  # Remove "A " and any trailing whitespace
        elif title_lower.startswith('an '):
            return title_clean[3:].strip()  # Remove "An " and any trailing whitespace
        
        return title_clean
    
    def group_titles_by_letter_advanced(self, titles: List[str]) -> Dict[str, List[str]]:
        """
        Group titles by letter with advanced sorting (strips articles).
        
        Args:
            titles: List of title strings
            
        Returns:
            Dictionary with letter keys and title lists as values
        """
        from collections import defaultdict, OrderedDict
        import re
        
        groups = defaultdict(list)
        for title in titles:
            # Strip articles for sorting purposes
            sort_title = self.strip_articles(title)
            
            # Check if sort_title starts with a digit
            if sort_title and sort_title[0].isdigit():
                groups['0-9'].append(title)
            else:
                # Find the first ASCII letter in the sort_title
                match = re.search(r'[A-Za-z]', sort_title)
                if match:
                    letter = match.group(0).upper()
                    groups[letter].append(title)
                elif any(c.isdigit() for c in sort_title):
                    groups['0-9'].append(title)
                else:
                    groups['Other'].append(title)
        
        # Sort groups alphabetically, but put 'Other' at the end
        sorted_keys = sorted([k for k in groups if k != 'Other'], key=lambda x: (x != '0-9', x))
        if 'Other' in groups:
            sorted_keys.append('Other')
        
        return OrderedDict((k, sorted(groups[k], key=lambda t: self.strip_articles(t).casefold())) for k in sorted_keys) 