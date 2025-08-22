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

from config import get_config
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
    
    def __init__(self):
        """Initialize the template context service."""
        debug_log("Initializing TemplateContextService")
        self.config = get_config()
        self.library_service = LibraryService()
        self.submissions_service = SubmissionsService()
        debug_log("TemplateContextService initialized")
    
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
            url = self.config.get(env, "")
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
            url = self.config.get(env, "")
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
            url = self.config.get(env, "")
            if not url:
                continue
                
            # Check individual QA service toggles
            qa_env = f"QA_{env}_ENABLED"
            qa_enabled = self.config.get(qa_env, "yes")  # Default to "yes" for backward compatibility
            
            if qa_enabled.lower() == "yes":
                services.append({"name": name, "url": url, "logo": logo})
        
        debug_log(f"Built {len(services)} quick access services")
        return services
    
    def get_storage_info(self) -> List[Dict[str, Any]]:
        """Get storage information for templates."""
        debug_log("Getting storage info")
        drives_env = self.config.get("DRIVES")
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
        # This will be implemented when we extract the rate limit service
        # For now, return empty lists
        return {
            'whitelisted': [],
            'banned': []
        }
    
    def get_template_context(self) -> Dict[str, Any]:
        """Get common template context data to avoid repetition."""
        debug_log("Getting template context")
        
        services, all_services = self.build_services_data()
        quick_access_services = self.build_quick_access_services_data()
        storage_info = self.get_storage_info()
        library_notes = self.load_library_notes()
        
        # Load submissions
        submissions = self.submissions_service.load_plex_submissions()
        audiobookshelf_submissions = self.submissions_service.load_audiobookshelf_submissions()
        
        # Load section 7 content
        section7_content = self.load_section7_content()
        
        context = {
            "services": services,
            "quick_access_services": quick_access_services,
            "all_services": all_services,
            "submissions": submissions,
            "storage_info": storage_info,
            "audiobookshelf_submissions": audiobookshelf_submissions,
            "library_notes": library_notes,
            "section7_content": section7_content,
            "SERVER_NAME": self.config.get("SERVER_NAME", ""),
            "ACCENT_COLOR": self.config.get("ACCENT_COLOR", "#d33fbc"),
            "PLEX_TOKEN": self.config.get("PLEX_TOKEN", ""),
            "PLEX_URL": self.config.get("PLEX_URL", ""),
            "AUDIOBOOKS_ID": self.config.get("AUDIOBOOKS_ID", ""),
            "ABS_ENABLED": self.config.get("ABS_ENABLED", "no"),
            "LIBRARY_IDS": self.config.get("LIBRARY_IDS", ""),
            "LIBRARY_CAROUSELS": self.config.get("LIBRARY_CAROUSELS", ""),
            "LIBRARY_CAROUSEL_ORDER": self.config.get("LIBRARY_CAROUSEL_ORDER", ""),
            "DISCORD_WEBHOOK": self.config.get("DISCORD_WEBHOOK", ""),
            "DISCORD_USERNAME": self.config.get("DISCORD_USERNAME", ""),
            "DISCORD_AVATAR": self.config.get("DISCORD_AVATAR", ""),
            "DISCORD_COLOR": self.config.get("DISCORD_COLOR", ""),
            "AUDIOBOOKSHELF_URL": self.config.get("AUDIOBOOKSHELF_URL", ""),
            "AUDIOBOOKSHELF_TOKEN": self.config.get("AUDIOBOOKSHELF_TOKEN", ""),
            "show_services": self.config.get("SHOW_SERVICES", "yes").lower() == "yes",
            "custom_services_url": self.config.get("CUSTOM_SERVICES_URL", "").strip(),
            "DISCORD_NOTIFY_PLEX": self.config.get("DISCORD_NOTIFY_PLEX", "1"),
            "DISCORD_NOTIFY_ABS": self.config.get("DISCORD_NOTIFY_ABS", "1"),
            "DISCORD_NOTIFY_RATE_LIMITING": self.config.get("DISCORD_NOTIFY_RATE_LIMITING", "0"),
            "DISCORD_NOTIFY_IP_MANAGEMENT": self.config.get("DISCORD_NOTIFY_IP_MANAGEMENT", "0"),
            "DISCORD_NOTIFY_LOGIN_ATTEMPTS": self.config.get("DISCORD_NOTIFY_LOGIN_ATTEMPTS", "0"),
            "DISCORD_NOTIFY_FORM_RATE_LIMITING": self.config.get("DISCORD_NOTIFY_FORM_RATE_LIMITING", "0"),
            "DISCORD_NOTIFY_FIRST_ACCESS": self.config.get("DISCORD_NOTIFY_FIRST_ACCESS", "0"),
            "QUICK_ACCESS_ENABLED": self.config.get("QUICK_ACCESS_ENABLED", "yes"),
            "QA_PLEX_ENABLED": self.config.get("QA_PLEX_ENABLED", "yes"),
            "QA_AUDIOBOOKSHELF_ENABLED": self.config.get("QA_AUDIOBOOKSHELF_ENABLED", "yes"),
            "QA_TAUTULLI_ENABLED": self.config.get("QA_TAUTULLI_ENABLED", "yes"),
            "QA_OVERSEERR_ENABLED": self.config.get("QA_OVERSEERR_ENABLED", "yes"),
            "QA_JELLYSEERR_ENABLED": self.config.get("QA_JELLYSEERR_ENABLED", "yes"),
            "IP_MANAGEMENT_ENABLED": self.config.get("IP_MANAGEMENT_ENABLED", "no"),
            "RATE_LIMIT_SETTINGS_ENABLED": self.config.get("RATE_LIMIT_SETTINGS_ENABLED", "yes"),
            "RATE_LIMIT_MAX_LOGIN_ATTEMPTS": self.config.get_int("RATE_LIMIT_MAX_LOGIN_ATTEMPTS", self.config.get_int("RATE_LIMIT_LOGIN_ATTEMPTS", 5)),
            "RATE_LIMIT_MAX_FORM_SUBMISSIONS": self.config.get_int("RATE_LIMIT_MAX_FORM_SUBMISSIONS", self.config.get_int("RATE_LIMIT_FORM_SUBMISSIONS", 1)),
            "ip_lists": self.get_ip_lists(),
            "JS_DEBUG": self.config.get_bool("JS_DEBUG", False)
        }
        
        debug_log(f"Template context built with {len(context)} variables")
        return context 