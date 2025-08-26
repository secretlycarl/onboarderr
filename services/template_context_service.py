"""
Template Context Service for Onboarderr

This service provides template context data for all routes, centralizing
the logic for building template variables and avoiding repetition.
"""

import os
import platform
import psutil
from typing import Dict, List, Any, Tuple
from pathlib import Path
import json
import time
import urllib.parse
import threading

from config import get_config
from config.constants import *
from utils.data_utils import load_json_file
from services.library_service import LibraryService
from services.submissions_service import SubmissionsService

def debug_log(message: str) -> None:
    """Log a debug message only if FLASK_DEBUG is enabled."""
    try:
        flask_debug = os.getenv("FLASK_DEBUG", "0") == "1"
        if flask_debug:
            print(f"[DEBUG] {message}")
    except Exception:
        pass

class TemplateContextService:
    """Service for providing template context data."""
    
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
        """Initialize the template context service."""
        # Only initialize once
        if hasattr(self, '_initialized'):
            return
            
        # Only log initialization in verbose debug mode
        if os.getenv("VERBOSE_DEBUG", "0") == "1":
            debug_log("Initializing TemplateContextService")
        self.config = get_config()
        self.library_service = LibraryService()
        self.submissions_service = SubmissionsService()
        
        # Initialize rate limiting service once and reuse it
        self._rate_limit_service = None
        self._initialize_rate_limit_service()
        
        # Cache for template context to reduce overhead
        self._context_cache = None
        self._cache_timestamp = 0
        self._cache_ttl = 30  # Cache for 30 seconds (increased from 10)
        
        # Cache for configuration values to reduce repeated calls
        self._config_cache = {}
        self._config_cache_timestamp = 0
        self._config_cache_ttl = 60  # Cache config values for 60 seconds
        
        self._initialized = True
        if os.getenv("VERBOSE_DEBUG", "0") == "1":
            debug_log("TemplateContextService initialized")
    
    def _initialize_rate_limit_service(self):
        """Initialize the rate limiting service."""
        try:
            from services.rate_limit_service import RateLimitService
            self._rate_limit_service = RateLimitService(self.config)
            self._rate_limit_service.initialize()
            debug_log("Rate limit service initialized successfully")
        except Exception as e:
            debug_log(f"Failed to initialize rate limit service: {e}")
            self._rate_limit_service = None
    
    def _get_rate_limit_service(self):
        """Get the rate limiting service, reinitializing if needed."""
        if self._rate_limit_service is None:
            self._initialize_rate_limit_service()
        return self._rate_limit_service
    
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
    
    def get_service_definitions(self) -> List[Tuple[str, str, str]]:
        """Get service definitions for admin services."""
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
            ("Jellyseerr", "JELLYSEERR", "jellyseerr.webp"),
        ]
    
    def get_public_service_definitions(self) -> List[Tuple[str, str, str]]:
        """Get service definitions for end users (non-admin services)."""
        return [
            ("Plex", "PLEX", "plex.webp"),
            ("Audiobookshelf", "AUDIOBOOKSHELF", "abs.webp"),
            ("Tautulli", "TAUTULLI", "tautulli.webp"),
            ("Overseerr", "OVERSEERR", "overseerr.webp"),
            ("Jellyseerr", "JELLYSEERR", "jellyseerr.webp"),
        ]
    
    def build_services_data(self) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
        """Build services data for templates."""
        debug_log("Building services data")
        service_defs = self.get_service_definitions()
        services = []
        all_services = []
        
        for name, env, logo in service_defs:
            url = self._get_cached_config(env, "")
            all_services.append({"name": name, "env": env, "url": url, "logo": logo})
            if url:
                services.append({"name": name, "url": url, "logo": logo})
        
        debug_log(f"Built {len(services)} active services out of {len(all_services)} total")
        return services, all_services
    
    def build_public_services_data(self) -> List[Dict[str, str]]:
        """Build public services data for end users."""
        debug_log("Building public services data")
        service_defs = self.get_public_service_definitions()
        services = []
        
        for name, env, logo in service_defs:
            url = self._get_cached_config(env, "")
            if url:
                services.append({"name": name, "url": url, "logo": logo})
        
        debug_log(f"Built {len(services)} public services")
        return services
    
    def build_quick_access_services_data(self) -> List[Dict[str, str]]:
        """Build filtered services data for quick access panel."""
        debug_log("Building quick access services data")
        service_defs = self.get_public_service_definitions()
        services = []
        
        for name, env, logo in service_defs:
            url = self._get_cached_config(env, "")
            if not url:
                continue
                
            # Check individual QA service toggles
            qa_env = f"QA_{env}_ENABLED"
            qa_enabled = self._get_cached_config(qa_env, "yes")  # Default to "yes" for backward compatibility
            
            if qa_enabled.lower() == "yes":
                services.append({"name": name, "url": url, "logo": logo})
        
        debug_log(f"Built {len(services)} quick access services")
        return services
    
    def get_storage_info(self) -> List[Dict[str, Any]]:
        """Get storage information for templates."""
        debug_log("Getting storage info")
        drives_env = self._get_cached_config("DRIVES")
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
                debug_log(f"Error reading {drive}: {e}")
        
        debug_log(f"Got storage info for {len(storage_info)} drives")
        return storage_info
    
    def load_library_notes(self) -> Dict[str, Any]:
        """Load library notes from file."""
        return self.library_service.load_library_notes()
    
    def load_section7_content(self) -> Dict[str, Any]:
        """Load section 7 content from JSON file."""
        return self.library_service.load_section7_content()
    
    def get_ip_lists(self) -> Dict[str, List[str]]:
        """Get current IP whitelist and blacklist."""
        debug_log("Getting IP lists")
        try:
            rate_limit_service = self._get_rate_limit_service()
            if rate_limit_service:
                return rate_limit_service.get_ip_lists()
            else:
                debug_log("Rate limit service not available")
                return {
                    'whitelisted': [],
                    'banned': []
                }
        except Exception as e:
            debug_log(f"Error getting IP lists: {e}")
            # Return empty lists as fallback
            return {
                'whitelisted': [],
                'banned': []
            }
    
    def get_template_context(self) -> Dict[str, Any]:
        """Get template context with caching to reduce overhead."""
        current_time = time.time()
        
        # Return cached context if still valid
        if (self._context_cache is not None and 
            current_time - self._cache_timestamp < self._cache_ttl):
            return self._context_cache
        
        # Build fresh context
        debug_log("Building fresh template context")
        context = self._build_template_context()
        
        # Cache the context
        self._context_cache = context
        self._cache_timestamp = current_time
        
        return context
    
    def clear_cache(self) -> None:
        """Clear the template context cache."""
        self._context_cache = None
        self._cache_timestamp = 0
        debug_log("Template context cache cleared")
    
    def clear_config_cache(self) -> None:
        """Clear the configuration cache."""
        self._config_cache = {}
        self._config_cache_timestamp = 0
        debug_log("Configuration cache cleared")
    
    def clear_all_caches(self) -> None:
        """Clear all caches."""
        self.clear_cache()
        self.clear_config_cache()
        debug_log("All caches cleared")
    
    def _build_template_context(self) -> Dict[str, Any]:
        """Build the template context (internal method)."""
        debug_log("Building template context")
        
        # Build services data
        services_data, all_services = self.build_services_data()
        quick_access_services = self.build_quick_access_services_data()
        
        # Get storage info
        storage_info = self.get_storage_info()
        
        # Get library data
        library_notes = self.library_service.load_library_notes()
        submissions = self.submissions_service.get_submissions()
        section7_content = self.library_service.load_section7_content()
        
        # Get ordered libraries
        ordered_libraries = self.library_service.get_ordered_libraries()
        
        # Initialize library_media and library_counts with empty data
        # Titles will be loaded on-demand via AJAX to improve performance
        library_media = {}
        library_counts = {}
        
        # Only load basic library info, not titles
        for lib in ordered_libraries:
            section_id = lib["key"]
            name = lib["title"]
            library_media[name] = {}  # Empty dict - titles loaded on-demand
            library_counts[name] = 0  # Will be updated when titles are loaded
        
        # Get ABS data
        abs_enabled = self._get_cached_config("ABS_ENABLED", "yes") == "yes"
        abs_books = []
        abs_book_groups = {}
        abs_book_count = 0
        
        if abs_enabled:
            abs_books = self._fetch_abs_books_from_cache()
            abs_book_groups = self._group_books_by_letter(abs_books) if abs_books else {}
            abs_book_count = len(abs_books) if abs_books else 0
        
        # Get rate limiting info
        rate_limit_info = self._get_rate_limit_info()
        
        # Get IP lists
        ip_lists = self.get_ip_lists()
        
        # Build context
        context = {
            # Server info
            "SERVER_NAME": self._get_cached_config("SERVER_NAME", "Onboarderr"),
            "ACCENT_COLOR": self._get_cached_config("ACCENT_COLOR", "#d33fbc"),
            
            # Authentication tokens
            "PLEX_TOKEN": self._get_cached_config("PLEX_TOKEN", ""),
            "PLEX_URL": self._get_cached_config("PLEX_URL", ""),
            "AUDIOBOOKS_ID": self._get_cached_config("AUDIOBOOKS_ID", ""),
            "ABS_ENABLED": "yes" if abs_enabled else "no",  # Fix: Use uppercase to match template
            
            # Library configuration
            "LIBRARY_IDS": self._get_cached_config("LIBRARY_IDS", ""),
            "LIBRARY_CAROUSELS": self._get_cached_config("LIBRARY_CAROUSELS", ""),
            "LIBRARY_CAROUSEL_ORDER": self._get_cached_config("LIBRARY_CAROUSEL_ORDER", ""),
            
            # Discord configuration
            "DISCORD_WEBHOOK": self._get_cached_config("DISCORD_WEBHOOK", ""),
            "DISCORD_USERNAME": self._get_cached_config("DISCORD_USERNAME", ""),
            "DISCORD_AVATAR": self._get_cached_config("DISCORD_AVATAR", ""),
            "DISCORD_COLOR": self._get_cached_config("DISCORD_COLOR", ""),
            
            # Audiobookshelf configuration
            "AUDIOBOOKSHELF_URL": self._get_cached_config("AUDIOBOOKSHELF_URL", ""),
            "AUDIOBOOKSHELF_TOKEN": self._get_cached_config("AUDIOBOOKSHELF_TOKEN", ""),
            
            # Services configuration
            "SHOW_SERVICES": self._get_cached_config("SHOW_SERVICES", "yes"),
            "CUSTOM_SERVICES_URL": self._get_cached_config("CUSTOM_SERVICES_URL", ""),
            "show_services": self._get_cached_config("SHOW_SERVICES", "yes").lower() == "yes",
            "custom_services_url": self._get_cached_config("CUSTOM_SERVICES_URL", "").strip(),
            
            # Discord notifications
            "DISCORD_NOTIFY_PLEX": self._get_cached_config("DISCORD_NOTIFY_PLEX", ""),
            "DISCORD_NOTIFY_ABS": self._get_cached_config("DISCORD_NOTIFY_ABS", ""),
            "DISCORD_NOTIFY_RATE_LIMITING": self._get_cached_config("DISCORD_NOTIFY_RATE_LIMITING", ""),
            "DISCORD_NOTIFY_IP_MANAGEMENT": self._get_cached_config("DISCORD_NOTIFY_IP_MANAGEMENT", ""),
            "DISCORD_NOTIFY_LOGIN_ATTEMPTS": self._get_cached_config("DISCORD_NOTIFY_LOGIN_ATTEMPTS", ""),
            "DISCORD_NOTIFY_FORM_RATE_LIMITING": self._get_cached_config("DISCORD_NOTIFY_FORM_RATE_LIMITING", ""),
            "DISCORD_NOTIFY_FIRST_ACCESS": self._get_cached_config("DISCORD_NOTIFY_FIRST_ACCESS", ""),
            
            # Quick access configuration
            "QUICK_ACCESS_ENABLED": self._get_cached_config("QUICK_ACCESS_ENABLED", "no"),
            "QA_PLEX_ENABLED": self._get_cached_config("QA_PLEX_ENABLED", "yes"),
            "QA_AUDIOBOOKSHELF_ENABLED": self._get_cached_config("QA_AUDIOBOOKSHELF_ENABLED", "yes"),
            "QA_TAUTULLI_ENABLED": self._get_cached_config("QA_TAUTULLI_ENABLED", "yes"),
            "QA_OVERSEERR_ENABLED": self._get_cached_config("QA_OVERSEERR_ENABLED", "yes"),
            "QA_JELLYSEERR_ENABLED": self._get_cached_config("QA_JELLYSEERR_ENABLED", "yes"),
            
            # IP management
            "IP_MANAGEMENT_ENABLED": self._get_cached_config("IP_MANAGEMENT_ENABLED", "no"),
            
            # Rate limiting
            "RATE_LIMIT_SETTINGS_ENABLED": self._get_cached_config("RATE_LIMIT_SETTINGS_ENABLED", "yes"),
            "RATE_LIMIT_MAX_LOGIN_ATTEMPTS": self._get_cached_config("RATE_LIMIT_MAX_LOGIN_ATTEMPTS", "5"),
            "RATE_LIMIT_MAX_FORM_SUBMISSIONS": self._get_cached_config("RATE_LIMIT_MAX_FORM_SUBMISSIONS", "2"),
            
            # IP lists
            "ip_lists": ip_lists,
            "IP_WHITELIST": ip_lists["whitelisted"],
            "IP_BLACKLIST": ip_lists["banned"],
            
            # Debug
            "JS_DEBUG": self._get_cached_config("JS_DEBUG", "0"),
            
            # Services data - use only public services for quick access
            "services": services_data,
            "quick_access_services": quick_access_services,
            "all_services": all_services,
            
            # Storage info
            "storage_info": storage_info,
            
            # Library data
            "library_notes": library_notes,
            "submissions": submissions["plex"],
            "audiobookshelf_submissions": submissions["audiobookshelf"],
            "section7_content": section7_content,
            "ordered_libraries": ordered_libraries,
            
            # Library media data
            "library_media": library_media,
            "library_counts": library_counts,
            
            # Library posters data (empty by default, loaded on-demand)
            "library_posters": {},
            "poster_imdb_ids": {},
            
            # ABS data
            "abs_books": abs_books,
            "abs_book_groups": abs_book_groups,
            "abs_book_count": abs_book_count,
            
            # Rate limiting info
            "rate_limit_info": rate_limit_info,
            
            # Favicon timestamp
            "favicon_timestamp": self._get_favicon_timestamp(),
        }
        
        debug_log(f"Template context built with {len(context)} variables")
        return context
    
    def _fetch_abs_books_from_cache(self) -> List[Dict[str, Any]]:
        """Fetch ABS books from cache."""
        try:
            audiobook_dir = os.path.join("static", "posters", "audiobooks")
            books = []
            
            if os.path.exists(audiobook_dir):
                # Get all JSON files
                json_files = [f for f in os.listdir(audiobook_dir) if f.endswith(".json")]
                
                for fname in json_files:
                    meta_path = os.path.join(audiobook_dir, fname)
                    try:
                        with open(meta_path, "r", encoding="utf-8") as f:
                            meta = json.load(f)
                        
                        title = meta.get("title")
                        if title:
                            # Use the old app's naming convention: audiobook{number}.webp
                            if fname.startswith("audiobook") and fname.endswith(".json"):
                                number = fname[9:-5]  # Remove "audiobook" prefix and ".json" suffix
                                cover_file = f"audiobook{number}.webp"
                                cover_path = os.path.join(audiobook_dir, cover_file)
                                
                                # Only include if the cover file actually exists
                                if os.path.exists(cover_path):
                                    poster_url = f"/static/posters/audiobooks/{cover_file}"
                                else:
                                    poster_url = None
                            else:
                                # Fallback to poster field from metadata
                                poster_file = meta.get("poster")
                                poster_url = f"/static/posters/audiobooks/{poster_file}" if poster_file else None
                            
                            books.append({
                                "title": title,
                                "poster": poster_url,
                                "author": meta.get("author", ""),
                                "series": meta.get("series", ""),
                                "book_id": meta.get("id"),
                                "library_id": meta.get("library_id"),
                            })
                    except Exception as e:
                        print(f"Error loading ABS book metadata from {meta_path}: {e}")
                        continue
            
            return books
        except Exception as e:
            print(f"Error fetching ABS books from cache: {e}")
            return []
    
    def _group_books_by_letter(self, books: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group books by first letter of title."""
        try:
            groups = {}
            
            for book in books:
                title = book.get("title", "")
                if title:
                    # Strip articles for sorting
                    sort_title = self._strip_articles(title)
                    first_letter = sort_title[0].upper() if sort_title else "Other"
                    
                    # Handle numbers and special characters
                    if not first_letter.isalpha():
                        if first_letter.isdigit():
                            first_letter = "0-9"
                        else:
                            first_letter = "Other"
                    
                    if first_letter not in groups:
                        groups[first_letter] = []
                    
                    groups[first_letter].append(book)
            
            # Sort books within each group
            for letter in groups:
                groups[letter].sort(key=lambda x: self._strip_articles(x.get("title", "")).lower())
            
            return groups
        except Exception as e:
            print(f"Error grouping books by letter: {e}")
            return {}
    
    def _strip_articles(self, title: str) -> str:
        """Remove articles from title for sorting purposes."""
        try:
            if not title:
                return ""
            
            # Common articles to strip
            articles = ["the ", "a ", "an "]
            
            title_lower = title.lower().strip()
            for article in articles:
                if title_lower.startswith(article):
                    return title[len(article):].strip()
            
            return title.strip()
        except Exception as e:
            print(f"Error stripping articles from {title}: {e}")
            return title 

    def _get_rate_limit_info(self) -> Dict[str, Any]:
        """Get rate limiting information."""
        try:
            rate_limit_service = self._get_rate_limit_service()
            if rate_limit_service:
                return {
                    "enabled": True,
                    "max_login_attempts": self.config.get("RATE_LIMIT_MAX_LOGIN_ATTEMPTS", "5"),
                    "max_form_submissions": self.config.get("RATE_LIMIT_MAX_FORM_SUBMISSIONS", "2"),
                }
            else:
                return {"enabled": False}
        except Exception as e:
            debug_log(f"Error getting rate limit info: {e}")
            return {"enabled": False}
    
    def _get_ip_lists(self) -> Dict[str, List[str]]:
        """Get IP whitelist and blacklist."""
        try:
            whitelist = self.config.get("IP_WHITELIST", "").split(",") if self.config.get("IP_WHITELIST") else []
            blacklist = self.config.get("IP_BLACKLIST", "").split(",") if self.config.get("IP_BLACKLIST") else []
            
            return {
                "whitelist": [ip.strip() for ip in whitelist if ip.strip()],
                "blacklist": [ip.strip() for ip in blacklist if ip.strip()]
            }
        except Exception as e:
            debug_log(f"Error getting IP lists: {e}")
            return {"whitelist": [], "blacklist": []}
    
    def _get_csrf_token(self) -> str:
        """Get CSRF token for forms."""
        try:
            from flask_wtf.csrf import generate_csrf
            return generate_csrf()
        except Exception as e:
            debug_log(f"Error generating CSRF token: {e}")
            return ""
    
    def _get_favicon_timestamp(self) -> int:
        """Get favicon timestamp to force browser cache updates."""
        try:
            favicon_path = os.path.join('static', 'favicon.webp')
            return int(os.path.getmtime(favicon_path))
        except (OSError, FileNotFoundError):
            return int(time.time())
    
    def get_lastfm_url(self, artist_name: str) -> str:
        """Generate Last.fm URL for an artist"""
        if not artist_name:
            return None
        
        # Clean the artist name for URL
        # Replace spaces with + for Last.fm URL format
        clean_name = artist_name.replace(' ', '+')
        # URL encode for special characters
        encoded_name = urllib.parse.quote(clean_name)
        
        return f"https://www.last.fm/music/{encoded_name}"
    
    def is_music_artist(self, poster_data: Dict[str, Any], library_info: Dict[str, Any] = None) -> bool:
        """Check if a poster represents a music artist"""
        if not poster_data:
            return False
        
        # If library info is provided, check if it's actually a music library
        if library_info and library_info.get("media_type") == "artist":
            title = poster_data.get("title")
            year = poster_data.get("year")
            
            # For music libraries, if it has a title but no year, it's likely an artist
            if title and year is None:
                return True
        
        return False 