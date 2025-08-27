"""
Setup service for Onboarderr

This module handles all business logic related to the setup process,
including form validation, environment variable management, and setup completion.
"""

import os
import requests
import xml.etree.ElementTree as ET
from typing import Dict, List, Tuple, Optional, Any
from pathlib import Path
import threading

from config import get_config
import os

def debug_log(message: str) -> None:
    """Log a debug message only if FLASK_DEBUG is enabled."""
    try:
        flask_debug = os.getenv("FLASK_DEBUG", "0") == "1"
        if flask_debug:
            print(f"[DEBUG] {message}")
    except Exception:
        pass

debug_log("Importing constants in setup service")
from config.constants import *
from utils.env_utils import (
    safe_set_key, save_api_key_with_hash,
    get_env_file_path, reload_environment
)
from utils.crypto_utils import generate_salt, hash_password

class SetupService:
    """Service class for handling setup operations."""
    
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
        """Initialize the setup service."""
        # Only initialize once
        if hasattr(self, '_initialized'):
            return
            
        # Only log initialization in verbose debug mode
        if os.getenv("VERBOSE_DEBUG", "0") == "1":
            debug_log(f"[DEBUG] SetupService constructor called")
        self.config = get_config()
        self.env_path = get_env_file_path()
        self._initialized = True
        if os.getenv("VERBOSE_DEBUG", "0") == "1":
            debug_log(f"[DEBUG] SetupService initialized with env path: {self.env_path}")
    
    def is_setup_complete(self) -> bool:
        """
        Check if setup is complete.
        
        Returns:
            True if setup is complete, False otherwise
        """
        setup_complete = self.config.is_setup_complete()
        # Only log setup complete checks in verbose debug mode
        if os.getenv("VERBOSE_DEBUG", "0") == "1":
            debug_log(f"[DEBUG] Setup service setup complete check: {setup_complete}")
        return setup_complete
    
    def get_setup_context(self) -> Dict[str, Any]:
        """
        Get the context data for the setup page.
        
        Returns:
            Dictionary containing setup page context
        """
        debug_log(f"[DEBUG] Getting setup context")
        site_password = self.config.get(SITE_PASSWORD_KEY, DEFAULT_SITE_PASSWORD)
        admin_password = self.config.get(ADMIN_PASSWORD_KEY, DEFAULT_ADMIN_PASSWORD)
        drives = self.config.get(DRIVES_KEY, "")
        
        debug_log(f"[DEBUG] Setup context values:")
        debug_log(f"[DEBUG] - Site password: {bool(site_password)}")
        debug_log(f"[DEBUG] - Admin password: {bool(admin_password)}")
        debug_log(f"[DEBUG] - Drives: {drives}")
        
        # Check if passwords need to be prompted
        prompt = False
        if (site_password == DEFAULT_SITE_PASSWORD or 
            admin_password == DEFAULT_ADMIN_PASSWORD or 
            not drives):
            prompt = True
        
        debug_log(f"[DEBUG] - Prompt passwords: {prompt}")
        
        return {
            "prompt_passwords": prompt,
            "site_password": site_password,
            "admin_password": admin_password,
            "drives": drives,
            "server_name": self.config.get(SERVER_NAME_KEY, ""),
            "ACCENT_COLOR": self.config.get(ACCENT_COLOR_KEY, "#d33fbc"),
            "service_urls": self.config.get_service_urls(),
            "ip_lists": self._get_ip_lists(),
            "section7_content": self._load_section7_content(),
            "RATE_LIMIT_SETTINGS_ENABLED": self.config.get(RATE_LIMIT_SETTINGS_ENABLED_KEY, "yes"),
            "RATE_LIMIT_MAX_LOGIN_ATTEMPTS": self.config.get_int(RATE_LIMIT_MAX_LOGIN_ATTEMPTS_KEY, 5),
            "RATE_LIMIT_MAX_FORM_SUBMISSIONS": self.config.get_int(RATE_LIMIT_MAX_FORM_SUBMISSIONS_KEY, 2)
        }
    
    def validate_setup_form(self, form_data: Dict[str, Any]) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """
        Validate setup form data.
        
        Args:
            form_data: Form data from the request
            
        Returns:
            Tuple of (is_valid, error_message, context_data)
        """
        # Extract form data
        site_password = form_data.get("site_password_box") or form_data.get("site_password", "")
        admin_password = form_data.get("admin_password_box") or form_data.get("admin_password", "")
        drives = form_data.get("drives_box") or form_data.get("drives", "")
        server_name = form_data.get(FORM_SERVER_NAME, "").strip()
        plex_token = form_data.get(FORM_PLEX_TOKEN, "").strip()
        plex_url = form_data.get(FORM_PLEX_URL, "").strip()
        library_ids = form_data.getlist(FORM_LIBRARY_IDS) if hasattr(form_data, 'getlist') else form_data.get(FORM_LIBRARY_IDS, [])
        
        # Validate required fields
        missing_fields = []
        if not site_password:
            missing_fields.append("Guest Password")
        if not admin_password:
            missing_fields.append("Admin Password")
        if not drives:
            missing_fields.append("Storage Drives")
        if not server_name:
            missing_fields.append("Server Name")
        if not plex_token:
            missing_fields.append("Plex Token")
        if not plex_url:
            missing_fields.append("Plex URL")
        if not library_ids:
            missing_fields.append("At least one Library")
        
        # Validate Audiobookshelf settings if enabled
        abs_enabled = form_data.get(FORM_ABS_ENABLED, "")
        if abs_enabled == "yes":
            audiobooks_id = form_data.get(FORM_AUDIOBOOKS_ID, "").strip()
            audiobookshelf_url = form_data.get(FORM_AUDIOBOOKSHELF_URL, "").strip()
            audiobookshelf_token = form_data.get(FORM_AUDIOBOOKSHELF_TOKEN, "").strip()
            
            if not audiobooks_id:
                missing_fields.append("Audiobook Library ID")
            if not audiobookshelf_url:
                missing_fields.append("Audiobookshelf URL")
            if not audiobookshelf_token:
                missing_fields.append("Audiobookshelf API Token")
        elif not abs_enabled:
            missing_fields.append("Enable Audiobookshelf?")
        
        if missing_fields:
            error_message = f"Some entries are missing: {', '.join(missing_fields)}"
            context_data = self._get_error_context(error_message, form_data)
            return False, error_message, context_data
        
        # Check if passwords are different
        if site_password == admin_password:
            error_message = "Guest Password and Admin Password must be different."
            context_data = self._get_error_context(error_message, form_data)
            return False, error_message, context_data
        
        return True, None, {}
    
    def process_setup_form(self, form_data: Dict[str, Any], files: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Process the setup form and save all configuration.
        
        Args:
            form_data: Form data from the request
            files: File uploads from the request
            
        Returns:
            Tuple of (success, error_message)
        """
        try:
            debug_log(f"[DEBUG] Processing setup form with {len(form_data)} fields")
            
            # Handle file uploads
            logo_file = files.get('logo_file')
            wordmark_file = files.get('wordmark_file')
            
            if logo_file and logo_file.filename:
                debug_log(f"[DEBUG] Processing logo file: {logo_file.filename}")
                if not self._process_uploaded_logo(logo_file):
                    return False, "Failed to process logo file. Please ensure it's a valid image file (.png, .webp, .jpg, .jpeg)."
            
            if wordmark_file and wordmark_file.filename:
                debug_log(f"[DEBUG] Processing wordmark file: {wordmark_file.filename}")
                if not self._process_uploaded_wordmark(wordmark_file):
                    return False, "Failed to process wordmark file. Please ensure it's a valid image file (.png, .webp, .jpg, .jpeg)."
            
            # Save passwords
            site_password = form_data.get("site_password_box") or form_data.get("site_password", "")
            admin_password = form_data.get("admin_password_box") or form_data.get("admin_password", "")
            drives = form_data.get("drives_box") or form_data.get("drives", "")
            
            debug_log(f"[DEBUG] Saving site password (length: {len(site_password)})")
            if not self._save_password_with_crypto(SITE_PASSWORD_KEY, site_password):
                return False, "Failed to save site password"
            
            debug_log(f"[DEBUG] Saving admin password (length: {len(admin_password)})")
            if not self._save_password_with_crypto(ADMIN_PASSWORD_KEY, admin_password):
                return False, "Failed to save admin password"
            
            debug_log(f"[DEBUG] Saving drives: {drives}")
            safe_set_key(self.env_path, DRIVES_KEY, drives)
            
            # Save basic settings
            server_name = form_data.get(FORM_SERVER_NAME, "")
            debug_log(f"[DEBUG] Saving server name: {server_name}")
            safe_set_key(self.env_path, SERVER_NAME_KEY, server_name)
            
            # Handle accent color
            accent_color = form_data.get(FORM_ACCENT_COLOR, "").strip()
            current_accent_color = self.config.get(ACCENT_COLOR_KEY, "")
            if accent_color and accent_color != current_accent_color:
                debug_log(f"[DEBUG] Saving accent color: {accent_color}")
                safe_set_key(self.env_path, ACCENT_COLOR_KEY, accent_color)
            
            # Save API keys with hashing
            plex_token = form_data.get(FORM_PLEX_TOKEN, "").strip()
            if plex_token:
                debug_log(f"[DEBUG] Saving Plex token (length: {len(plex_token)})")
                save_api_key_with_hash(self.env_path, PLEX_TOKEN_KEY, plex_token)
            
            plex_url = form_data.get(FORM_PLEX_URL, "")
            debug_log(f"[DEBUG] Saving Plex URL: {plex_url}")
            safe_set_key(self.env_path, PLEX_URL_KEY, plex_url)
            
            # Save Audiobookshelf settings
            abs_enabled = form_data.get(FORM_ABS_ENABLED, "")
            debug_log(f"[DEBUG] Saving Audiobookshelf enabled: {abs_enabled}")
            safe_set_key(self.env_path, ABS_ENABLED_KEY, abs_enabled)
            
            if abs_enabled == "yes":
                safe_set_key(self.env_path, AUDIOBOOKS_ID_KEY, form_data.get(FORM_AUDIOBOOKS_ID, ""))
                safe_set_key(self.env_path, AUDIOBOOKSHELF_URL_KEY, form_data.get(FORM_AUDIOBOOKSHELF_URL, ""))
                audiobookshelf_token = form_data.get(FORM_AUDIOBOOKSHELF_TOKEN, "").strip()
                if audiobookshelf_token:
                    debug_log(f"[DEBUG] Saving Audiobookshelf token (length: {len(audiobookshelf_token)})")
                    save_api_key_with_hash(self.env_path, AUDIOBOOKSHELF_TOKEN_KEY, audiobookshelf_token)
            
            # Save Discord settings
            self._save_discord_settings(form_data)
            
            # Save Quick Access settings
            self._save_quick_access_settings(form_data)
            
            # Save library settings
            self._save_library_settings(form_data)
            
            # Save service URLs
            self._save_service_urls(form_data)
            
            # Save IP management and rate limiting settings
            self._save_security_settings(form_data)
            
            # Save section 7 content
            self._save_section7_content(form_data)
            
            # Mark setup as complete
            debug_log(f"[DEBUG] Marking setup as complete")
            safe_set_key(self.env_path, SETUP_COMPLETE_KEY, "1")
            
            # Reload environment
            debug_log(f"[DEBUG] Reloading environment")
            reload_environment()
            
            # Also reload the config instance
            debug_log(f"[DEBUG] Reloading config instance")
            self.config.reload()
            
            # Clear template context cache to ensure fresh data
            try:
                from services.template_context_service import TemplateContextService
                template_service = TemplateContextService()
                template_service.clear_cache()
                debug_log(f"[DEBUG] Template context cache cleared")
            except Exception as e:
                debug_log(f"[WARN] Failed to clear template context cache: {e}")
            
            debug_log(f"[INFO] Setup form processed successfully")
            return True, None
            
        except Exception as e:
            debug_log(f"[ERROR] Failed to process setup form: {e}")
            return False, f"Failed to save configuration: {str(e)}"
    
    def _get_error_context(self, error_message: str, form_data: Dict[str, Any]) -> Dict[str, Any]:
        """Get context data for error display."""
        return {
            "error_message": error_message,
            "prompt_passwords": True,
            "site_password": form_data.get("site_password_box") or form_data.get("site_password", ""),
            "admin_password": form_data.get("admin_password_box") or form_data.get("admin_password", ""),
            "drives": form_data.get("drives_box") or form_data.get("drives", ""),
            "server_name": self.config.get(SERVER_NAME_KEY, ""),
            "service_urls": self.config.get_service_urls(),
            "ip_lists": self._get_ip_lists(),
            "section7_content": self._load_section7_content(),
            "RATE_LIMIT_SETTINGS_ENABLED": self.config.get(RATE_LIMIT_SETTINGS_ENABLED_KEY, "yes"),
            "RATE_LIMIT_MAX_LOGIN_ATTEMPTS": self.config.get_int(RATE_LIMIT_MAX_LOGIN_ATTEMPTS_KEY, 5),
            "RATE_LIMIT_MAX_FORM_SUBMISSIONS": self.config.get_int(RATE_LIMIT_MAX_FORM_SUBMISSIONS_KEY, 2)
        }
    
    def _save_discord_settings(self, form_data: Dict[str, Any]):
        """Save Discord notification settings."""
        discord_webhook = form_data.get(FORM_DISCORD_WEBHOOK, "").strip()
        safe_set_key(self.env_path, DISCORD_WEBHOOK_KEY, discord_webhook)
        
        if discord_webhook:
            safe_set_key(self.env_path, DISCORD_USERNAME_KEY, form_data.get(FORM_DISCORD_USERNAME, ""))
            safe_set_key(self.env_path, DISCORD_AVATAR_KEY, form_data.get(FORM_DISCORD_AVATAR, ""))
            safe_set_key(self.env_path, DISCORD_COLOR_KEY, form_data.get(FORM_DISCORD_COLOR, ""))
            safe_set_key(self.env_path, ONBOARDERR_URL_KEY, form_data.get(FORM_ONBOARDERR_URL, ""))
        
        # Save notification settings
        notification_keys = [
            DISCORD_NOTIFY_PLEX_KEY, DISCORD_NOTIFY_ABS_KEY, DISCORD_NOTIFY_RATE_LIMITING_KEY,
            DISCORD_NOTIFY_IP_MANAGEMENT_KEY, DISCORD_NOTIFY_LOGIN_ATTEMPTS_KEY,
            DISCORD_NOTIFY_FORM_RATE_LIMITING_KEY, DISCORD_NOTIFY_FIRST_ACCESS_KEY
        ]
        
        for key in notification_keys:
            value = form_data.get(key.lower(), "0")
            safe_set_key(self.env_path, key, value)
    
    def _save_quick_access_settings(self, form_data: Dict[str, Any]):
        """Save Quick Access settings."""
        quick_access_enabled = form_data.get("quick_access_enabled", "yes")
        safe_set_key(self.env_path, QUICK_ACCESS_ENABLED_KEY, quick_access_enabled)
        
        # Save individual service toggles
        qa_settings = [
            (QA_PLEX_ENABLED_KEY, "qa_plex_enabled"),
            (QA_AUDIOBOOKSHELF_ENABLED_KEY, "qa_audiobookshelf_enabled"),
            (QA_TAUTULLI_ENABLED_KEY, "qa_tautulli_enabled"),
            (QA_OVERSEERR_ENABLED_KEY, "qa_overseerr_enabled"),
            (QA_JELLYSEERR_ENABLED_KEY, "qa_jellyseerr_enabled")
        ]
        
        for key, form_key in qa_settings:
            value = "yes" if form_data.get(form_key) else "no"
            safe_set_key(self.env_path, key, value)
    
    def _save_library_settings(self, form_data: Dict[str, Any]):
        """Save library settings."""
        library_ids = form_data.getlist(FORM_LIBRARY_IDS) if hasattr(form_data, 'getlist') else form_data.get(FORM_LIBRARY_IDS, [])
        
        # Clean library IDs
        cleaned_library_ids = []
        for lib_id in library_ids:
            cleaned_id = lib_id.strip()
            if cleaned_id:
                cleaned_library_ids.append(cleaned_id)
        
        if cleaned_library_ids:
            # Get library names from Plex API
            plex_token = form_data.get(FORM_PLEX_TOKEN, "")
            plex_url = form_data.get(FORM_PLEX_URL, "")
            
            try:
                headers = {"X-Plex-Token": plex_token}
                url = f"{plex_url}/library/sections"
                
                # Apply API rate limiting
                from services.rate_limit_service import RateLimitService
                rate_limit_service = RateLimitService(self.config)
                rate_limit_service.initialize()
                rate_limit_service.check_api_rate_limit('plex')
                
                response = requests.get(url, headers=headers, timeout=5)
                response.raise_for_status()
                
                root = ET.fromstring(response.text)
                id_to_title = {d.attrib.get("key"): d.attrib.get("title") for d in root.findall(".//Directory")}
                selected_titles = [id_to_title.get(i, f"Unknown ({i})") for i in cleaned_library_ids]
                
                safe_set_key(self.env_path, LIBRARY_IDS_KEY, ",".join(cleaned_library_ids))
                safe_set_key(self.env_path, LIBRARY_NAMES_KEY, ",".join([t or "" for t in selected_titles]))
                
                # Save library notes
                library_notes = {}
                for lib_id in cleaned_library_ids:
                    desc = form_data.get(f"library_desc_{lib_id}", "")
                    library_notes[lib_id] = {
                        "title": id_to_title.get(lib_id, f"Unknown ({lib_id})"),
                        "description": desc
                    }
                self._save_library_notes(library_notes)
                
                # Handle carousel settings
                self._save_carousel_settings(form_data, cleaned_library_ids)
                
            except Exception as e:
                debug_log(f"[WARN] Failed to get library names from Plex API: {e}")
                safe_set_key(self.env_path, LIBRARY_IDS_KEY, ",".join(cleaned_library_ids))
                safe_set_key(self.env_path, LIBRARY_NAMES_KEY, "")
    
    def _save_carousel_settings(self, form_data: Dict[str, Any], selected_library_ids: List[str]):
        """Save library carousel settings."""
        library_carousels = form_data.getlist("library_carousels") if hasattr(form_data, 'getlist') else form_data.get("library_carousels", [])
        
        if library_carousels:
            # Validate that all carousel libraries are in the selected library IDs
            carousel_set = set(library_carousels)
            selected_set = set(selected_library_ids)
            valid_carousels = list(carousel_set & selected_set)
            safe_set_key(self.env_path, LIBRARY_CAROUSELS_KEY, ",".join(valid_carousels))
        else:
            safe_set_key(self.env_path, LIBRARY_CAROUSELS_KEY, "")
        
        # Handle carousel order
        library_carousel_order = form_data.get("library_carousel_order", "").strip()
        if library_carousel_order:
            order_ids = [id.strip() for id in library_carousel_order.split(",") if id.strip()]
            valid_order_ids = [id for id in order_ids if id in selected_library_ids]
            safe_set_key(self.env_path, LIBRARY_CAROUSEL_ORDER_KEY, ",".join(valid_order_ids))
        else:
            safe_set_key(self.env_path, LIBRARY_CAROUSEL_ORDER_KEY, "")
        
        # Clear caches to ensure changes are reflected immediately
        self._clear_carousel_caches()
    
    def _clear_carousel_caches(self):
        """Clear caches related to carousel settings to ensure immediate updates."""
        try:
            # Clear library service cache
            from services.library_service import LibraryService
            library_service = LibraryService()
            if hasattr(library_service, '_config_cache'):
                library_service._config_cache = {}
                library_service._config_cache_timestamp = 0
            
            # Clear template context service cache
            from services.template_context_service import TemplateContextService
            template_service = TemplateContextService()
            if hasattr(template_service, '_context_cache'):
                template_service._context_cache = None
                template_service._cache_timestamp = 0
            if hasattr(template_service, '_config_cache'):
                template_service._config_cache = {}
                template_service._config_cache_timestamp = 0
            
            # Reload configuration
            from config import reload_config
            reload_config()
            
            debug_log("Carousel caches cleared successfully")
        except Exception as e:
            debug_log(f"Error clearing carousel caches: {e}")
    
    def _save_service_urls(self, form_data: Dict[str, Any]):
        """Save service URLs."""
        for key in SERVICE_KEYS:
            url_val = form_data.get(key, "").strip()
            safe_set_key(self.env_path, key, url_val)
    
    def _save_security_settings(self, form_data: Dict[str, Any]):
        """Save IP management and rate limiting settings."""
        # IP management
        ip_management_enabled = form_data.get("ip_management_enabled", "no")
        safe_set_key(self.env_path, IP_MANAGEMENT_ENABLED_KEY, ip_management_enabled)
        
        # Rate limiting
        rate_limit_settings_enabled = form_data.get("rate_limit_settings_enabled", "yes")
        safe_set_key(self.env_path, RATE_LIMIT_SETTINGS_ENABLED_KEY, rate_limit_settings_enabled)
        
        # Rate limiting values
        max_login_attempts = form_data.get("max_login_attempts")
        if max_login_attempts is not None:
            try:
                max_login_attempts = int(max_login_attempts)
                if 0 <= max_login_attempts <= 10:
                    safe_set_key(self.env_path, RATE_LIMIT_MAX_LOGIN_ATTEMPTS_KEY, str(max_login_attempts))
            except ValueError:
                pass
        
        max_form_submissions = form_data.get("max_form_submissions")
        if max_form_submissions is not None:
            try:
                max_form_submissions = int(max_form_submissions)
                if 0 <= max_form_submissions <= 10:
                    safe_set_key(self.env_path, RATE_LIMIT_MAX_FORM_SUBMISSIONS_KEY, str(max_form_submissions))
            except ValueError:
                pass
    
    def _save_section7_content(self, form_data: Dict[str, Any]):
        """Save section 7 content (personal message and payment services)."""
        personal_message = form_data.get("personal_message", "").strip()
        payment_services = []
        
        for i in range(3):
            title = form_data.get(f"payment_service_{i}_title", "").strip()
            handle = form_data.get(f"payment_service_{i}_handle", "").strip()
            if title and handle:
                payment_services.append({
                    "title": title,
                    "handle": handle
                })
        
        section7_content = {
            "personal_message": personal_message,
            "payment_services": payment_services
        }
        self._save_section7_content_to_file(section7_content)
    
    def _get_ip_lists(self) -> Dict[str, List[str]]:
        """Get IP whitelist and blacklist."""
        # This would need to be implemented based on the existing logic
        # For now, return empty lists
        return {
            "whitelist": [],
            "blacklist": []
        }
    
    def _load_section7_content(self) -> Dict[str, Any]:
        """Load section 7 content from file."""
        try:
            import json
            section7_file = Path(SECTION7_CONTENT_FILE)
            if section7_file.exists():
                with open(section7_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            debug_log(f"[WARN] Failed to load section 7 content: {e}")
        
        return {
            "personal_message": "",
            "payment_services": []
        }
    
    def _save_section7_content_to_file(self, content: Dict[str, Any]):
        """Save section 7 content to file."""
        try:
            import json
            with open(SECTION7_CONTENT_FILE, 'w') as f:
                json.dump(content, f, indent=2)
        except Exception as e:
            debug_log(f"[ERROR] Failed to save section 7 content: {e}")
    
    def _save_library_notes(self, library_notes: Dict[str, Any]):
        """Save library notes to file."""
        try:
            import json
            with open(LIBRARY_NOTES_FILE, 'w') as f:
                json.dump(library_notes, f, indent=2)
        except Exception as e:
            debug_log(f"[ERROR] Failed to save library notes: {e}")
    
    def _process_uploaded_logo(self, file) -> bool:
        """Process uploaded logo file."""
        # This would need to be implemented based on the existing logic
        # For now, return True to avoid blocking setup
        return True
    
    def _process_uploaded_wordmark(self, file) -> bool:
        """Process uploaded wordmark file."""
        # This would need to be implemented based on the existing logic
        # For now, return True to avoid blocking setup
        return True
    
    def _save_password_with_crypto(self, key: str, password: str) -> bool:
        """
        Save a password with its hash and salt using crypto_utils.
        
        Args:
            key: Base key name (e.g., "SITE_PASSWORD")
            password: The password to save
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Generate salt and hash using crypto_utils
            salt = generate_salt()
            hashed = hash_password(password, salt)
            
            debug_log(f"[DEBUG] Generated salt for {key}: {salt[:10]}...")
            debug_log(f"[DEBUG] Generated hash for {key}: {hashed[:10]}...")
            
            # Save the password (plain text for backward compatibility)
            if not safe_set_key(self.env_path, key, password):
                return False
            
            # Save the hash
            hash_key = f"{key}_HASH"
            if not safe_set_key(self.env_path, hash_key, hashed):
                return False
            
            # Save the salt
            salt_key = f"{key}_SALT"
            if not safe_set_key(self.env_path, salt_key, salt):
                return False
            
            debug_log(f"[DEBUG] Successfully saved password {key} with hash and salt")
            return True
            
        except Exception as e:
            debug_log(f"[ERROR] Failed to save password {key}: {e}")
            return False
    
    def create_abs_user(self, username: str, password: str, user_type: str = "user", permissions: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Create a user in Audiobookshelf using the API.
        
        Args:
            username: Username for the new user
            password: Password for the new user
            user_type: Type of user ("user", "admin", "guest")
            permissions: Custom permissions dictionary
            
        Returns:
            Dictionary with success status and user information
        """
        abs_url = self.config.get("AUDIOBOOKSHELF_URL")
        abs_token = self.config.get("AUDIOBOOKSHELF_TOKEN")
        
        if not self.config.validate_url(abs_url, "AUDIOBOOKSHELF_URL"):
            return {"success": False, "error": "Invalid Audiobookshelf URL"}
        
        if not self.config.validate_token(abs_token, "AUDIOBOOKSHELF_TOKEN"):
            return {"success": False, "error": "Invalid Audiobookshelf API token"}
        
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
            import requests
            
            headers = {
                "Authorization": f"Bearer {abs_token}",
                "Content-Type": "application/json"
            }
            
            timeout = self.config.get_int("ABS_API_TIMEOUT", 10)
            response = requests.post(
                f"{abs_url}/api/users",
                headers=headers,
                json=user_data,
                timeout=timeout
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
                    "error": f"ABS API error: {response.status_code}"
                }
            else:
                return {
                    "success": False,
                    "username": username,
                    "email": "",  # Will be filled by caller
                    "error": f"ABS API returned status {response.status_code}"
                }
                
        except requests.exceptions.Timeout:
            return {
                "success": False,
                "username": username,
                "email": "",  # Will be filled by caller
                "error": "ABS API request timed out"
            }
        except requests.exceptions.ConnectionError:
            return {
                "success": False,
                "username": username,
                "email": "",  # Will be filled by caller
                "error": "Failed to connect to ABS API"
            }
        except Exception as e:
            return {
                "success": False,
                "username": username,
                "email": "",  # Will be filled by caller
                "error": f"Unexpected error: {str(e)}"
            } 