"""
Poster Service Module

Handles poster download and management functionality that was previously in old_app.py.
This service manages poster downloads, progress tracking, and poster display.
"""

import os
import requests
import threading
import time
import random
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import get_config

class PosterService:
    """Service for managing poster downloads and operations."""
    
    def __init__(self):
        """Initialize the poster service."""
        self.config = get_config()
        self.download_queue = []
        self.download_running = False
        self.download_progress = {}
        self.download_lock = threading.Lock()
        
        # Poster download limits
        self.POSTER_DOWNLOAD_LIMITS = {
            'max_concurrent_downloads': 5,
            'max_download_size_mb': 10,
            'max_downloads_per_hour': 1000,
            'max_progress_entries': 50
        }
        
        # Start background worker
        self._start_background_worker()
    
    def _start_background_worker(self):
        """Start the background poster download worker."""
        if not self.download_running:
            self.download_running = True
            worker_thread = threading.Thread(target=self._background_worker, daemon=True)
            worker_thread.start()
            print("[INFO] Started background poster download worker")
    
    def _background_worker(self):
        """Background worker for poster downloads."""
        print("[INFO] Background poster worker started")
        
        while self.download_running:
            try:
                if self.download_queue:
                    work_item = self.download_queue.pop(0)
                    self._process_work_item(work_item)
                else:
                    time.sleep(1)
            except Exception as e:
                print(f"[ERROR] Error in poster download worker: {e}")
                time.sleep(1)
        
        print("[INFO] Background poster worker stopped")
    
    def _process_work_item(self, work_item):
        """Process a work item from the queue."""
        try:
            work_type, libraries = work_item
            
            if work_type == 'libraries':
                print(f"[INFO] Processing poster downloads for {len(libraries)} libraries")
                for library in libraries:
                    self._download_library_posters(library)
            
        except Exception as e:
            print(f"[ERROR] Failed to process work item: {e}")
    
    def start_poster_download(self, library_id):
        """
        Start poster downloads for a specific library.
        
        Args:
            library_id (str): The library ID to download posters for
        """
        try:
            # Get Plex credentials
            plex_token = self.config.get("PLEX_TOKEN")
            plex_url = self.config.get("PLEX_URL")
            
            if not plex_token or not plex_url:
                print(f"[WARN] No Plex credentials available for library {library_id}")
                return False
            
            # Create library object
            library = {
                "key": library_id,
                "title": f"Library {library_id}"
            }
            
            # Initialize progress tracking
            with self.download_lock:
                self.download_progress[library_id] = {
                    "status": "starting",
                    "total": 0,
                    "downloaded": 0,
                    "message": f"Starting downloads for Library {library_id}",
                    "library_name": f"Library {library_id}",
                    "start_time": time.time()
                }
            
            # Add to download queue
            self.download_queue.append(('libraries', [library]))
            
            print(f"[INFO] Added library {library_id} to poster download queue")
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to start poster download for library {library_id}: {e}")
            return False
    
    def _download_library_posters(self, library):
        """
        Download posters for a specific library.
        
        Args:
            library (dict): Library information with 'key' and 'title'
        """
        try:
            library_id = library["key"]
            library_name = library["title"]
            
            # Get Plex credentials
            plex_token = self.config.get("PLEX_TOKEN")
            plex_url = self.config.get("PLEX_URL")
            
            # Create headers
            headers = {"X-Plex-Token": plex_token}
            
            # Create library directory
            lib_dir = self._get_library_poster_dir(library_id)
            os.makedirs(lib_dir, exist_ok=True)
            
            # Fetch library items
            url = f"{plex_url}/library/sections/{library_id}/all"
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            
            # Parse XML response
            root = ET.fromstring(response.text)
            
            # Collect items
            items = []
            for el in root.findall(".//Video"):
                thumb = el.attrib.get("thumb")
                rating_key = el.attrib.get("ratingKey")
                title = el.attrib.get("title")
                year = el.attrib.get("year")
                if thumb and rating_key:
                    items.append({"thumb": thumb, "ratingKey": rating_key, "title": title, "year": year})
            
            for el in root.findall(".//Directory"):
                thumb = el.attrib.get("thumb")
                rating_key = el.attrib.get("ratingKey")
                title = el.attrib.get("title")
                if thumb and rating_key and not any(i["ratingKey"] == rating_key for i in items):
                    items.append({"thumb": thumb, "ratingKey": rating_key, "title": title})
            
            # Shuffle and limit
            random.shuffle(items)
            items = items[:100]  # Limit to 100 items for setup
            
            print(f"[INFO] Found {len(items)} items in library {library_name}")
            
            # Update progress
            with self.download_lock:
                self.download_progress[library_id] = {
                    "status": "downloading",
                    "total": len(items),
                    "downloaded": 0,
                    "message": f"Downloading posters for {library_name}",
                    "library_name": library_name,
                    "start_time": time.time()
                }
            
            # Process items with ThreadPoolExecutor for parallel downloads
            successful_downloads = 0
            
            with ThreadPoolExecutor(max_workers=self.POSTER_DOWNLOAD_LIMITS['max_concurrent_downloads']) as executor:
                futures = []
                for i, item in enumerate(items):
                    future = executor.submit(self._download_single_poster, item, lib_dir, i, headers, plex_url, plex_token)
                    futures.append(future)
                
                # Wait for completion with progress tracking
                for i, future in enumerate(as_completed(futures)):
                    if future.result():
                        successful_downloads += 1
                    
                    # Update progress every 5 items
                    if i % 5 == 0:
                        with self.download_lock:
                            if library_id in self.download_progress:
                                self.download_progress[library_id].update({
                                    "downloaded": successful_downloads,
                                    "message": f"Downloading {i+1}/{len(items)} items for {library_name}"
                                })
            
            # Mark as complete
            with self.download_lock:
                self.download_progress[library_id].update({
                    "status": "completed",
                    "downloaded": successful_downloads,
                    "message": f"Completed downloading {successful_downloads} posters for {library_name}",
                    "end_time": time.time()
                })
            
            print(f"[INFO] Completed poster downloads for library {library_name}: {successful_downloads}/{len(items)}")
            
        except Exception as e:
            print(f"[ERROR] Failed to download posters for library {library_id}: {e}")
            with self.download_lock:
                self.download_progress[library_id] = {
                    "status": "error",
                    "message": f"Error downloading posters for {library_name}: {str(e)}",
                    "library_name": library_name,
                    "end_time": time.time()
                }
    
    def _download_single_poster(self, item, lib_dir, index, headers, plex_url, plex_token):
        """Download a single poster with metadata."""
        try:
            # Use a unique filename based on ratingKey
            rating_key = item.get('ratingKey', str(index))
            safe_filename = f"poster_{rating_key}"
            out_path = os.path.join(lib_dir, f"{safe_filename}.webp")
            meta_path = os.path.join(lib_dir, f"{safe_filename}.json")
            
            # Skip if already cached and recent (less than 12 hours old)
            if os.path.exists(out_path) and os.path.exists(meta_path):
                file_age = time.time() - os.path.getmtime(out_path)
                if file_age < 43200:  # 12 hours
                    return True
            
            # Download poster only if it doesn't exist
            if not os.path.exists(out_path):
                img_url = f"{plex_url}{item['thumb']}?X-Plex-Token={plex_token}"
                r = requests.get(img_url, headers=headers, timeout=10, stream=True)
                if r.status_code == 200:
                    # Check content length for size limit
                    content_length = r.headers.get('content-length')
                    max_size_bytes = self.POSTER_DOWNLOAD_LIMITS['max_download_size_mb'] * 1024 * 1024
                    
                    if content_length and int(content_length) > max_size_bytes:
                        print(f"[WARN] Poster too large ({content_length} bytes) for {item.get('title', 'Unknown')}")
                        return False
                    
                    # Stream download to check size and save
                    content = b""
                    for chunk in r.iter_content(chunk_size=8192):
                        content += chunk
                        if len(content) > max_size_bytes:
                            print(f"[WARN] Poster download exceeded size limit for {item.get('title', 'Unknown')}")
                            return False
                    
                    with open(out_path, "wb") as f:
                        f.write(content)
                    
                    # Rate limiting - small delay between requests
                    time.sleep(0.1)
                else:
                    print(f"[ERROR] Failed to download poster for {item.get('title', 'Unknown')}: HTTP {r.status_code}")
                    return False
            
            # Fetch metadata
            guids = {"imdb": None, "tmdb": None, "tvdb": None}
            try:
                meta_url = f"{plex_url}/library/metadata/{item['ratingKey']}"
                meta_resp = requests.get(meta_url, headers=headers, timeout=10)
                if meta_resp.status_code == 200:
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
                print(f"[ERROR] Error fetching GUIDs for {item['ratingKey']}: {e}")
            
            # Save metadata
            meta = {
                "title": item["title"],
                "ratingKey": item["ratingKey"],
                "year": item.get("year"),
                "guids": guids,
                "downloaded_at": time.time()
            }
            
            with open(meta_path, "w") as f:
                json.dump(meta, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to download poster for {item.get('title', 'Unknown')}: {e}")
            return False
    
    def _get_library_poster_dir(self, library_id):
        """Get the poster directory for a library."""
        base_dir = os.path.join("static", "posters", "libraries")
        return os.path.join(base_dir, str(library_id))
    
    def get_download_status(self):
        """
        Get the current download status.
        
        Returns:
            dict: Current download status
        """
        with self.download_lock:
            return {
                "download_running": self.download_running,
                "queue_size": len(self.download_queue),
                "progress": self.download_progress.copy()
            }
    
    def get_library_posters(self, library_id, limit=50):
        """
        Get posters for a specific library.
        
        Args:
            library_id (str): The library ID
            limit (int): Maximum number of posters to return
            
        Returns:
            list: List of poster data
        """
        try:
            # Get Plex credentials
            plex_token = self.config.get("PLEX_TOKEN")
            plex_url = self.config.get("PLEX_URL")
            
            if not plex_token or not plex_url:
                return []
            
            # Create headers
            headers = {"X-Plex-Token": plex_token}
            
            # Get library items
            url = f"{plex_url}/library/sections/{library_id}/all"
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            
            # Parse XML response
            root = ET.fromstring(response.text)
            
            # Get items
            items = root.findall(".//Video") + root.findall(".//Show") + root.findall(".//Movie")
            
            posters = []
            for item in items[:limit]:
                poster_url = item.get("thumb") or item.get("art")
                if poster_url:
                    posters.append({
                        "title": item.get("title", "Unknown"),
                        "poster_url": poster_url,
                        "rating_key": item.get("ratingKey"),
                        "type": item.get("type", "unknown")
                    })
            
            return posters
            
        except Exception as e:
            print(f"[ERROR] Failed to get posters for library {library_id}: {e}")
            return []
    
    def should_wait_for_posters(self):
        """
        Check if we should wait for poster downloads to complete.
        
        Returns:
            bool: True if we should wait, False otherwise
        """
        with self.download_lock:
            # Check if downloads are in progress
            if self.download_running and self.download_queue:
                return True
            
            # Check if any downloads are still processing
            if any(status.get('status') == 'in_progress' for status in self.download_progress.values()):
                return True
            
            return False
    
    def is_download_in_progress(self):
        """
        Check if any poster downloads are in progress.
        
        Returns:
            bool: True if downloads are in progress, False otherwise
        """
        with self.download_lock:
            return self.download_running and (len(self.download_queue) > 0 or 
                    any(status.get('status') == 'in_progress' for status in self.download_progress.values()))
    
    def get_download_progress(self):
        """
        Get the current download progress.
        
        Returns:
            dict: Current download progress
        """
        with self.download_lock:
            return self.download_progress.copy()
    
    def get_unified_status(self):
        """
        Get the unified download status.
        
        Returns:
            dict: Unified status or None if not available
        """
        with self.download_lock:
            return self.download_progress.get('unified')
    
    def should_refresh_abs_posters(self):
        """
        Check if ABS posters should be refreshed.
        
        Returns:
            bool: True if refresh is needed, False otherwise
        """
        # This is a simplified implementation
        # In the full implementation, this would check various conditions
        return False
    
    def is_abs_download_in_progress(self):
        """
        Check if ABS downloads are in progress.
        
        Returns:
            bool: True if ABS downloads are in progress, False otherwise
        """
        with self.download_lock:
            return self.download_progress.get('abs', {}).get('status') == 'in_progress'
    
    def is_abs_download_completed(self):
        """
        Check if ABS downloads are completed.
        
        Returns:
            bool: True if ABS downloads are completed, False otherwise
        """
        with self.download_lock:
            return self.download_progress.get('abs', {}).get('status') == 'completed' 