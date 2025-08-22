"""
Library Service for Onboarderr

This service handles library-related operations including loading libraries
from files, managing library notes, and other library-specific functionality.
"""

import os
import requests
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

from config import get_config
from utils.data_utils import load_json_file, save_json_file

def debug_log(message: str) -> None:
    """Log a debug message only if FLASK_DEBUG is enabled."""
    try:
        flask_debug = os.getenv("FLASK_DEBUG", "0") == "1"
        if flask_debug:
            print(f"[DEBUG] {message}")
    except Exception:
        pass

class LibraryService:
    """Service for handling library operations."""
    
    def __init__(self):
        """Initialize the library service."""
        debug_log("Initializing LibraryService")
        self.config = get_config()
        debug_log("LibraryService initialized")
    
    def get_libraries_from_local_files(self) -> List[Dict[str, Any]]:
        """
        Get libraries from local cache files for better performance.
        
        Returns:
            List of library dictionaries
        """
        debug_log("Getting libraries from local files")
        libraries = load_json_file("libraries.json", [])
        debug_log(f"Loaded {len(libraries)} libraries from local files")
        return libraries
    
    def load_library_notes(self) -> Dict[str, Any]:
        """
        Load library notes from file.
        
        Returns:
            Dictionary of library notes
        """
        debug_log("Loading library notes from file")
        notes = load_json_file("library_notes.json", {})
        debug_log(f"Loaded {len(notes)} library notes from file")
        return notes
    
    def save_library_notes(self, notes: Dict[str, Any]) -> bool:
        """
        Save library notes to file.
        
        Args:
            notes: Library notes to save
            
        Returns:
            True if successful, False otherwise
        """
        debug_log(f"Saving {len(notes)} library notes")
        result = save_json_file("library_notes.json", notes)
        debug_log(f"Library notes save result: {result}")
        return result
    
    def load_section7_content(self) -> Dict[str, Any]:
        """
        Load section 7 content from JSON file.
        
        Returns:
            Section 7 content dictionary
        """
        debug_log("Loading section 7 content from file")
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
        
        debug_log(f"Loaded section 7 content: {content}")
        return content
    
    def save_section7_content(self, content: Dict[str, Any]) -> bool:
        """
        Save section 7 content to JSON file.
        
        Args:
            content: Section 7 content to save
            
        Returns:
            True if successful, False otherwise
        """
        debug_log(f"Saving section 7 content: {content}")
        result = save_json_file("section7_content.json", content)
        debug_log(f"Section 7 content save result: {result}")
        return result
    
    def recreate_library_notes(self) -> bool:
        """
        Update library notes on startup by fetching current library information from Plex.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            plex_token = self.config.get("PLEX_TOKEN")
            plex_url = self.config.get("PLEX_URL")
            
            if not plex_token or not plex_url:
                debug_log("Plex token or URL not configured, skipping library notes update")
                return False
            
            debug_log("Updating library notes from Plex API")
            
            # Load existing library notes to preserve descriptions
            existing_notes = self.load_library_notes()
            
            # Get selected library IDs from environment
            selected_ids_str = self.config.get("LIBRARY_IDS", "")
            selected_ids = []
            if selected_ids_str:
                # Split by comma and clean up whitespace
                selected_ids = [id.strip() for id in selected_ids_str.split(",") if id.strip()]
            
            debug_log(f"Selected library IDs from environment: {selected_ids}")
            
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
                        debug_log(f"Updated library note for {title} (ID: {key})")
                    
                except Exception as e:
                    debug_log(f"Error updating library {lib_id}: {e}")
                    continue
            
            # Save updated notes
            if updated_count > 0:
                success = self.save_library_notes(existing_notes)
                debug_log(f"Updated {updated_count} library notes, save result: {success}")
                return success
            else:
                debug_log("No library notes updated")
                return True
                
        except Exception as e:
            debug_log(f"Error recreating library notes: {e}")
            return False
    
    def get_selected_library_ids(self) -> List[str]:
        """
        Get the list of selected library IDs from configuration.
        
        Returns:
            List of selected library IDs
        """
        selected_ids_str = self.config.get("LIBRARY_IDS", "")
        if not selected_ids_str:
            return []
        
        selected_ids = [id.strip() for id in selected_ids_str.split(",") if id.strip()]
        debug_log(f"Selected library IDs: {selected_ids}")
        return selected_ids
    
    def get_filtered_libraries(self) -> List[Dict[str, Any]]:
        """
        Get libraries filtered by selected IDs.
        
        Returns:
            List of filtered libraries
        """
        debug_log("Getting filtered libraries")
        libraries = self.get_libraries_from_local_files()
        selected_ids = self.get_selected_library_ids()
        
        if not selected_ids:
            debug_log("No selected library IDs, returning all libraries")
            return libraries
        
        filtered_libraries = [lib for lib in libraries if lib.get("key") in selected_ids]
        debug_log(f"Filtered {len(filtered_libraries)} libraries from {len(libraries)} total")
        return filtered_libraries 