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
import urllib.parse
from utils.network_utils import retry_operation, safe_api_call
from utils.logging_utils import log_debug, log_error, log_info, log_warning

# ============================================================================
# IMPROVED STATE MANAGEMENT AND ERROR HANDLING
# ============================================================================

class DownloadStatus:
    """Enum-like class for download status tracking"""
    IDLE = "idle"
    QUEUED = "queued"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class DownloadProgress:
    """Class for tracking download progress with better error handling"""
    def __init__(self, library_name="", total=0):
        self.current = 0
        self.total = total
        self.successful = 0
        self.failed = 0
        self.library_name = library_name
        self.status = DownloadStatus.IDLE
        self.error_message = ""
        self.start_time = None
        self.end_time = None
        self.retry_count = 0
        self.max_retries = 3
    
    def start(self):
        """Start the download process"""
        self.status = DownloadStatus.IN_PROGRESS
        self.start_time = time.time()
        self.error_message = ""
    
    def complete(self, successful=True):
        """Complete the download process"""
        self.status = DownloadStatus.COMPLETED if successful else DownloadStatus.FAILED
        self.end_time = time.time()
    
    def fail(self, error_message=""):
        """Mark download as failed"""
        self.status = DownloadStatus.FAILED
        self.failed += 1
        self.error_message = error_message
        self.end_time = time.time()
    
    def can_retry(self):
        """Check if download can be retried"""
        return self.retry_count < self.max_retries and self.status == DownloadStatus.FAILED
    
    def retry(self):
        """Increment retry count and reset status"""
        self.retry_count += 1
        self.status = DownloadStatus.QUEUED
        self.error_message = ""
    
    def to_dict(self):
        """Convert progress to dictionary for JSON serialization"""
        return {
            "current": self.current,
            "total": self.total,
            "successful": self.successful,
            "failed": self.failed,
            "library_name": self.library_name,
            "status": self.status,
            "error_message": self.error_message,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries
        }

class PosterService:
    """Service for managing poster downloads and operations."""
    
    # Singleton instance
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        """Implement singleton pattern"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(PosterService, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        """Initialize the poster service (only once due to singleton)."""
        if self._initialized:
            return
            
        self.config = get_config()
        self.download_queue = []
        self.download_running = False
        self.download_progress = {}
        self.download_lock = threading.Lock()
        
        # Enhanced progress tracking with DownloadProgress objects
        self.progress_objects = {}  # library_id -> DownloadProgress
        
        # Poster download limits
        self.POSTER_DOWNLOAD_LIMITS = {
            'max_concurrent_downloads': 5,
            'max_download_size_mb': 10,
            'max_downloads_per_hour': 1000,
            'max_progress_entries': 50
        }
        
        # Start background worker
        self._start_background_worker()
        
        self._initialized = True

    # Helper functions from old_app.py
    def get_library_poster_dir(self, library_id):
        """Get the poster directory path for a library using the old naming format (just ID)"""
        return os.path.join("static", "posters", str(library_id))
    
    def is_music_artist(self, poster_data, library_info=None):
        """Check if a poster represents a music artist - simplified logic matching old app.py"""
        try:
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
        except Exception as e:
            print(f"[WARN] Error checking if item is music artist: {e}")
            return False
    
    def get_lastfm_url(self, artist_name):
        """Generate Last.fm URL for an artist"""
        if not artist_name:
            return None
        
        # Clean the artist name for URL
        import urllib.parse
        # Replace spaces with + for Last.fm URL format
        clean_name = artist_name.replace(' ', '+')
        # URL encode for special characters
        encoded_name = urllib.parse.quote(clean_name)
        
        return f"https://www.last.fm/music/{encoded_name}"
    
    def strip_articles(self, title):
        """Remove articles from title for sorting purposes"""
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
            print(f"[WARN] Error stripping articles from {title}: {e}")
            return title
    
    def get_ordered_libraries(self):
        """Get libraries in the proper order for display"""
        try:
            from services.library_service import LibraryService
            library_service = LibraryService()
            
            # Get all libraries from local files
            all_libraries = library_service.get_libraries_from_local_files()
            
            # Filter by LIBRARY_IDS
            library_ids = self.config.get("LIBRARY_IDS", "")
            selected_ids = [id.strip() for id in library_ids.split(",") if id.strip()]
            selected_ids_str = [str(id).strip() for id in selected_ids]
            
            filtered_libraries = [lib for lib in all_libraries if str(lib["key"]) in selected_ids_str]
            
            # Apply the same ordering logic as onboarding:
            # 1. Libraries with carousels first (in carousel tab order)
            # 2. Libraries without carousels (in A-Z order)
            
            # Get carousel library IDs
            library_carousels = self.config.get("LIBRARY_CAROUSELS", "")
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
            library_carousel_order = self.config.get("LIBRARY_CAROUSEL_ORDER", "")
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
            return libraries_with_carousels + libraries_without_carousels
            
        except Exception as e:
            print(f"[ERROR] Error getting ordered libraries: {e}")
            return []
    
    def _start_background_worker(self):
        """Start the background poster download worker."""
        if not self.download_running:
            self.download_running = True
            worker_thread = threading.Thread(target=self._background_worker, daemon=True)
            worker_thread.start()
            print("[INFO] Started background poster download worker")
    
    def ensure_worker_running(self):
        """Ensure the background poster worker is running."""
        if not self.download_running:
            print("[INFO] Restarting background poster worker")
            self._start_background_worker()
    
    def _background_worker(self):
        """Background worker for poster downloads."""
        print("[INFO] Background poster worker started")
        
        last_cleanup_time = time.time()
        cleanup_interval = 3600  # Clean up every hour
        
        while self.download_running:
            try:
                # Periodic cleanup of old progress entries
                current_time = time.time()
                if current_time - last_cleanup_time > cleanup_interval:
                    self.cleanup_old_progress()
                    last_cleanup_time = current_time
                
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
            work_type, data = work_item
            
            if work_type == 'libraries':
                libraries = data
                print(f"[INFO] Processing poster downloads for {len(libraries)} libraries")
                for library in libraries:
                    self._download_library_posters(library)
            
            elif work_type == 'smart_library':
                library = data['library']
                items = data['items']
                smart_result = data['smart_result']
                print(f"[INFO] Processing smart poster downloads for {library['title']}: {len(items)} items")
                self._download_smart_library_posters(library, items, smart_result)
            
            elif work_type == 'abs_download':
                force_download = data.get('force_download', False)
                print(f"[INFO] Processing ABS poster downloads (force: {force_download})")
                self._download_abs_posters(force_download)
            
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
            
            # Initialize enhanced progress tracking with DownloadProgress object
            with self.download_lock:
                progress_obj = DownloadProgress(library_name=f"Library {library_id}")
                self.progress_objects[library_id] = progress_obj
                self.download_progress[library_id] = progress_obj.to_dict()
            
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
            
            # Apply API rate limiting
            from services.rate_limit_service import RateLimitService
            rate_limit_service = RateLimitService(self.config)
            rate_limit_service.initialize()
            rate_limit_service.check_api_rate_limit('plex')
            
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
            
            # Update progress using DownloadProgress object
            with self.download_lock:
                if library_id in self.progress_objects:
                    progress_obj = self.progress_objects[library_id]
                    progress_obj.start()
                    progress_obj.total = len(items)
                    progress_obj.library_name = library_name
                    self.download_progress[library_id] = progress_obj.to_dict()
                else:
                    # Fallback to dictionary if progress object doesn't exist
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
                    
                    # Update progress every 5 items using DownloadProgress object
                    if i % 5 == 0:
                        with self.download_lock:
                            if library_id in self.progress_objects:
                                progress_obj = self.progress_objects[library_id]
                                progress_obj.current = i + 1
                                progress_obj.successful = successful_downloads
                                self.download_progress[library_id] = progress_obj.to_dict()
                            elif library_id in self.download_progress:
                                self.download_progress[library_id].update({
                                    "downloaded": successful_downloads,
                                    "message": f"Downloading {i+1}/{len(items)} items for {library_name}"
                                })
            
            # Mark as complete using DownloadProgress object
            with self.download_lock:
                if library_id in self.progress_objects:
                    progress_obj = self.progress_objects[library_id]
                    progress_obj.complete(successful=True)
                    progress_obj.successful = successful_downloads
                    self.download_progress[library_id] = progress_obj.to_dict()
                else:
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
                if library_id in self.progress_objects:
                    progress_obj = self.progress_objects[library_id]
                    progress_obj.fail(f"Error downloading posters for {library_name}: {str(e)}")
                    self.download_progress[library_id] = progress_obj.to_dict()
                else:
                    self.download_progress[library_id] = {
                        "status": "error",
                        "message": f"Error downloading posters for {library_name}: {str(e)}",
                        "library_name": library_name,
                        "end_time": time.time()
                    }
    
    def _download_single_poster(self, item, lib_dir, index, headers, plex_url, plex_token):
        """Download a single poster with metadata using retry logic."""
        
        def download_poster():
            """Inner function for retry mechanism"""
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
                
                # Use retry_operation for poster download
                def download_image():
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
                        return True
                    else:
                        print(f"[ERROR] Failed to download poster for {item.get('title', 'Unknown')}: HTTP {r.status_code}")
                        return False
                
                # Retry poster download with exponential backoff
                success = retry_operation(
                    download_image,
                    max_retries=3,
                    delay=1.0,
                    backoff_factor=2.0,
                    exceptions=(requests.exceptions.RequestException, requests.exceptions.Timeout),
                    operation_name=f"poster_download_{rating_key}"
                )
                
                if not success:
                    return False
            
            # Fetch metadata with retry logic
            guids = {"imdb": None, "tmdb": None, "tvdb": None}
            
            def fetch_metadata():
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
                    return True
                return False
            
            # Retry metadata fetch with exponential backoff
            try:
                retry_operation(
                    fetch_metadata,
                    max_retries=2,
                    delay=0.5,
                    backoff_factor=2.0,
                    exceptions=(requests.exceptions.RequestException, requests.exceptions.Timeout),
                    operation_name=f"metadata_fetch_{rating_key}"
                )
            except Exception as e:
                print(f"[ERROR] Error fetching GUIDs for {item['ratingKey']}: {e}")
            
            # Save metadata
            meta = {
                "title": item["title"],
                "ratingKey": item["ratingKey"],
                "year": item.get("year"),
                "guids": guids,
                "poster": f"{safe_filename}.webp",  # Add poster filename to metadata
                "downloaded_at": time.time()
            }
            
            with open(meta_path, "w") as f:
                json.dump(meta, f, indent=2)
            
            return True
        
        try:
            return download_poster()
        except Exception as e:
            print(f"[ERROR] Failed to download poster for {item.get('title', 'Unknown')}: {e}")
            return False
    
    def _get_library_poster_dir(self, library_id):
        """Get the poster directory for a library using the old naming format (just ID)"""
        return os.path.join("static", "posters", str(library_id))
    
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
    
    def retry_failed_download(self, library_id):
        """
        Retry a failed download for a specific library.
        
        Args:
            library_id (str): The library ID to retry
            
        Returns:
            bool: True if retry was initiated, False otherwise
        """
        try:
            with self.download_lock:
                if library_id in self.progress_objects:
                    progress_obj = self.progress_objects[library_id]
                    
                    # Check if download can be retried
                    if progress_obj.can_retry():
                        progress_obj.retry()
                        self.download_progress[library_id] = progress_obj.to_dict()
                        
                        # Re-queue the download
                        library = {
                            "key": library_id,
                            "title": progress_obj.library_name
                        }
                        self.download_queue.append(('libraries', [library]))
                        
                        print(f"[INFO] Retrying failed download for library {library_id} (attempt {progress_obj.retry_count})")
                        return True
                    else:
                        print(f"[WARN] Cannot retry download for library {library_id} - max retries exceeded or not in failed state")
                        return False
                else:
                    print(f"[WARN] No progress object found for library {library_id}")
                    return False
                    
        except Exception as e:
            print(f"[ERROR] Failed to retry download for library {library_id}: {e}")
            return False
    
    def get_failed_downloads(self):
        """
        Get list of failed downloads that can be retried.
        
        Returns:
            list: List of library IDs that can be retried
        """
        try:
            with self.download_lock:
                failed_libraries = []
                for library_id, progress_obj in self.progress_objects.items():
                    if progress_obj.status == DownloadStatus.FAILED and progress_obj.can_retry():
                        failed_libraries.append({
                            'library_id': library_id,
                            'library_name': progress_obj.library_name,
                            'retry_count': progress_obj.retry_count,
                            'max_retries': progress_obj.max_retries,
                            'error_message': progress_obj.error_message
                        })
                return failed_libraries
        except Exception as e:
            print(f"[ERROR] Failed to get failed downloads: {e}")
            return []
    
    def cleanup_old_progress(self):
        """
        Clean up old progress entries to prevent memory leaks.
        Removes completed/failed downloads older than 24 hours.
        """
        try:
            current_time = time.time()
            cutoff_time = current_time - 86400  # 24 hours
            
            with self.download_lock:
                # Clean up progress objects
                libraries_to_remove = []
                for library_id, progress_obj in self.progress_objects.items():
                    # Remove if completed/failed and older than 24 hours
                    if (progress_obj.status in [DownloadStatus.COMPLETED, DownloadStatus.FAILED] and 
                        progress_obj.end_time and progress_obj.end_time < cutoff_time):
                        libraries_to_remove.append(library_id)
                
                # Remove old entries
                for library_id in libraries_to_remove:
                    del self.progress_objects[library_id]
                    if library_id in self.download_progress:
                        del self.download_progress[library_id]
                
                # Also clean up dictionary-based progress entries
                dict_entries_to_remove = []
                for library_id, progress_dict in self.download_progress.items():
                    if (progress_dict.get('status') in ['completed', 'failed', 'error'] and 
                        progress_dict.get('end_time') and progress_dict.get('end_time') < cutoff_time):
                        dict_entries_to_remove.append(library_id)
                
                for library_id in dict_entries_to_remove:
                    del self.download_progress[library_id]
                
                if libraries_to_remove or dict_entries_to_remove:
                    print(f"[INFO] Cleaned up {len(libraries_to_remove)} progress objects and {len(dict_entries_to_remove)} dict entries")
                    
        except Exception as e:
            print(f"[ERROR] Failed to cleanup old progress: {e}")
    
    def get_progress_summary(self):
        """
        Get a summary of all download progress.
        
        Returns:
            dict: Summary of download progress
        """
        try:
            with self.download_lock:
                summary = {
                    'total_libraries': len(self.progress_objects),
                    'in_progress': 0,
                    'completed': 0,
                    'failed': 0,
                    'queued': 0,
                    'idle': 0,
                    'can_retry': 0
                }
                
                for progress_obj in self.progress_objects.values():
                    if progress_obj.status == DownloadStatus.IN_PROGRESS:
                        summary['in_progress'] += 1
                    elif progress_obj.status == DownloadStatus.COMPLETED:
                        summary['completed'] += 1
                    elif progress_obj.status == DownloadStatus.FAILED:
                        summary['failed'] += 1
                        if progress_obj.can_retry():
                            summary['can_retry'] += 1
                    elif progress_obj.status == DownloadStatus.QUEUED:
                        summary['queued'] += 1
                    elif progress_obj.status == DownloadStatus.IDLE:
                        summary['idle'] += 1
                
                return summary
        except Exception as e:
            print(f"[ERROR] Failed to get progress summary: {e}")
            return {}
    
    def should_refresh_abs_posters(self):
        """
        Check if ABS posters should be refreshed.
        
        Returns:
            bool: True if refresh is needed, False otherwise
        """
        try:
            audiobook_dir = os.path.join("static", "posters", "audiobooks")
            completion_file = os.path.join(audiobook_dir, ".last_completion")
            
            if not os.path.exists(completion_file):
                return True
            
            # Check if last completion was more than 12 hours ago
            with open(completion_file, 'r') as f:
                last_completion_time = float(f.read().strip())
            
            time_since_completion = time.time() - last_completion_time
            return time_since_completion > 43200  # 12 hours
            
        except Exception as e:
            print(f"[ERROR] Error checking ABS refresh status: {e}")
            return True
    
    def should_refresh_posters(self, library_id):
        """
        Check if posters for a library should be refreshed.
        
        Args:
            library_id: Library ID to check
            
        Returns:
            bool: True if refresh is needed, False otherwise
        """
        try:
            lib_dir = self._get_library_poster_dir(library_id)
            completion_file = os.path.join(lib_dir, ".last_completion")
            
            if not os.path.exists(completion_file):
                return True
            
            # Check if last completion was more than 12 hours ago
            with open(completion_file, 'r') as f:
                last_completion_time = float(f.read().strip())
            
            time_since_completion = time.time() - last_completion_time
            return time_since_completion > 43200  # 12 hours
            
        except Exception as e:
            print(f"[ERROR] Error checking refresh status for library {library_id}: {e}")
            return True
    
    def get_existing_poster_rating_keys(self, library_id):
        """
        Get existing poster rating keys for a library.
        
        Args:
            library_id: Library ID
            
        Returns:
            set: Set of existing rating keys
        """
        try:
            lib_dir = self._get_library_poster_dir(library_id)
            existing_keys = set()
            
            if os.path.exists(lib_dir):
                for file in os.listdir(lib_dir):
                    if file.endswith('.webp'):
                        # Extract rating key from filename (poster_123456.webp -> 123456)
                        rating_key = file.replace('poster_', '').replace('.webp', '')
                        if rating_key.isdigit():
                            existing_keys.add(rating_key)
            
            return existing_keys
            
        except Exception as e:
            print(f"[ERROR] Error getting existing poster keys for library {library_id}: {e}")
            return set()
    
    def cleanup_deleted_posters(self, library_id, current_rating_keys):
        """
        Clean up posters for items that no longer exist.
        
        Args:
            library_id: Library ID
            current_rating_keys: Set of current rating keys from server
            
        Returns:
            int: Number of posters removed
        """
        try:
            lib_dir = self._get_library_poster_dir(library_id)
            existing_keys = self.get_existing_poster_rating_keys(library_id)
            
            # Find keys that exist locally but not on server
            deleted_keys = existing_keys - current_rating_keys
            
            removed_count = 0
            for rating_key in deleted_keys:
                poster_file = os.path.join(lib_dir, f"poster_{rating_key}.webp")
                meta_file = os.path.join(lib_dir, f"poster_{rating_key}.json")
                
                try:
                    if os.path.exists(poster_file):
                        os.remove(poster_file)
                        removed_count += 1
                    if os.path.exists(meta_file):
                        os.remove(meta_file)
                except Exception as e:
                    print(f"[WARN] Failed to remove deleted poster {rating_key}: {e}")
            
            if removed_count > 0:
                print(f"[INFO] Removed {removed_count} deleted posters from library {library_id}")
            
            return removed_count
            
        except Exception as e:
            print(f"[ERROR] Error cleaning up deleted posters for library {library_id}: {e}")
            return 0
    
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
    
    def initialize_unified_progress(self):
        """Initialize unified progress tracking."""
        with self.download_lock:
            self.download_progress['unified'] = {
                'status': 'checking',
                'message': 'Checking poster downloads...',
                'current': 0,
                'total': 0,
                'start_time': time.time()
            }
    
    def update_unified_status(self, status_update):
        """Update the unified status."""
        with self.download_lock:
            if 'unified' in self.download_progress:
                self.download_progress['unified'].update(status_update)
    
    def determine_download_needs(self, libraries, abs_enabled=True):
        """
        Determine what downloads are needed using smart logic.
        
        Args:
            libraries: List of library dictionaries
            abs_enabled: Whether ABS is enabled
            
        Returns:
            dict: Download needs analysis
        """
        result = {
            'plex_needs_download': False,
            'abs_needs_download': False,
            'plex_results': [],
            'abs_result': None,
            'any_server_offline': False,
            'total_new': 0,
            'total_changed': 0,
            'total_removed': 0
        }
        
        # Get Plex credentials
        plex_token = self.config.get("PLEX_TOKEN")
        plex_url = self.config.get("PLEX_URL")
        
        if not plex_token or not plex_url:
            print("[DEBUG] No Plex credentials available for smart check")
            return result
        
        headers = {"X-Plex-Token": plex_token}
        
        # Check Plex libraries
        for lib in libraries:
            # Check if Plex downloads were recently completed for this library (within last 6 hours)
            plex_completion_file = os.path.join("static", "posters", str(lib["key"]), ".last_completion")
            if os.path.exists(plex_completion_file):
                try:
                    with open(plex_completion_file, 'r') as f:
                        last_completion_time = float(f.read().strip())
                    time_since_completion = time.time() - last_completion_time
                    
                    # If completed within last 6hr, skip download for this library
                    if time_since_completion < 21600:  # 6hr
                        print(f"[DEBUG] Plex downloads for library {lib['key']} completed {time_since_completion:.1f} seconds ago, skipping re-download")
                        result['plex_results'].append({
                            'needs_download': False,
                            'new_items': [],
                            'changed_items': [],
                            'removed_count': 0,
                            'server_offline': False,
                            'error': None,
                            'skipped_recent_completion': True
                        })
                        continue
                except (IOError, ValueError) as e:
                    print(f"[DEBUG] Could not read Plex completion timestamp for library {lib['key']}: {e}")
            
            lib_result = self._smart_check_library_posters(lib["key"], plex_url, headers)
            result['plex_results'].append(lib_result)
            
            if lib_result['server_offline']:
                result['any_server_offline'] = True
            
            if lib_result['needs_download']:
                result['plex_needs_download'] = True
                result['total_new'] += len(lib_result['new_items'])
                result['total_changed'] += len(lib_result['changed_items'])
                result['total_removed'] += lib_result['removed_count']
        
        # Check ABS if enabled (simplified for now)
        if abs_enabled:
            abs_url = self.config.get("AUDIOBOOKSHELF_URL")
            if abs_url:
                # Check if ABS downloads were recently completed (within last 6 hours)
                abs_completion_file = os.path.join("static", "posters", "audiobooks", ".last_completion")
                if os.path.exists(abs_completion_file):
                    try:
                        with open(abs_completion_file, 'r') as f:
                            last_completion_time = float(f.read().strip())
                        time_since_completion = time.time() - last_completion_time
                        
                        # If completed within last 6hr, skip download
                        if time_since_completion < 21600:  # 6 hours
                            print(f"[DEBUG] ABS downloads completed {time_since_completion:.1f} seconds ago, skipping re-download")
                            result['abs_result'] = {
                                'needs_download': False,
                                'new_items': [],
                                'changed_items': [],
                                'removed_count': 0,
                                'server_offline': False,
                                'error': None,
                                'skipped_recent_completion': True
                            }
                            return result
                    except (IOError, ValueError) as e:
                        print(f"[DEBUG] Could not read ABS completion timestamp: {e}")
                
                # For now, assume ABS needs download if enabled
                result['abs_result'] = {
                    'needs_download': True,
                    'new_items': [],
                    'changed_items': [],
                    'removed_count': 0,
                    'server_offline': False,
                    'error': None
                }
                result['abs_needs_download'] = True
        
        print(f"[DEBUG] Download needs determined: Plex={result['plex_needs_download']}, ABS={result['abs_needs_download']}")
        print(f"[DEBUG] Totals: {result['total_new']} new, {result['total_changed']} changed, {result['total_removed']} removed")
        
        return result
    
    def _smart_check_library_posters(self, library_id, plex_url, headers):
        """
        Smart check for library poster downloads.
        
        Args:
            library_id: Library ID
            plex_url: Plex server URL
            headers: Request headers
            
        Returns:
            dict: Smart check result
        """
        try:
            # Try to connect to Plex server
            url = f"{plex_url}/library/sections/{library_id}/all"
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code != 200:
                return {
                    'needs_download': False,
                    'new_items': [],
                    'changed_items': [],
                    'removed_count': 0,
                    'server_offline': True,
                    'error': f"Server returned {response.status_code}"
                }
            
            # Parse XML response
            root = ET.fromstring(response.text)
            
            # Get existing posters
            existing_keys = self.get_existing_poster_rating_keys(library_id)
            
            # Collect current items
            current_items = []
            current_rating_keys = set()
            
            for el in root.findall(".//Video"):
                thumb = el.attrib.get("thumb")
                rating_key = el.attrib.get("ratingKey")
                title = el.attrib.get("title")
                year = el.attrib.get("year")
                if thumb and rating_key:
                    item = {
                        "thumb": thumb,
                        "ratingKey": rating_key,
                        "title": title,
                        "year": year
                    }
                    current_items.append(item)
                    current_rating_keys.add(rating_key)
            
            for el in root.findall(".//Directory"):
                thumb = el.attrib.get("thumb")
                rating_key = el.attrib.get("ratingKey")
                title = el.attrib.get("title")
                if thumb and rating_key and not any(i["ratingKey"] == rating_key for i in current_items):
                    item = {
                        "thumb": thumb,
                        "ratingKey": rating_key,
                        "title": title
                    }
                    current_items.append(item)
                    current_rating_keys.add(rating_key)
            
            # Clean up deleted posters
            removed_count = self.cleanup_deleted_posters(library_id, current_rating_keys)
            
            # Determine new and changed items
            new_items = []
            changed_items = []
            
            for item in current_items:
                rating_key = item["ratingKey"]
                
                if rating_key not in existing_keys:
                    new_items.append(item)
                else:
                    # Check if metadata changed (simplified - just add to changed for now)
                    # In a full implementation, this would compare metadata files
                    changed_items.append(item)
            
            needs_download = len(new_items) > 0 or len(changed_items) > 0
            
            print(f"[DEBUG] Smart check for library {library_id}: {len(new_items)} new, {len(changed_items)} changed, {removed_count} removed")
            
            return {
                'needs_download': needs_download,
                'new_items': new_items,
                'changed_items': changed_items,
                'removed_count': removed_count,
                'server_offline': False,
                'error': None
            }
            
        except requests.exceptions.RequestException as e:
            return {
                'needs_download': False,
                'new_items': [],
                'changed_items': [],
                'removed_count': 0,
                'server_offline': True,
                'error': str(e)
            }
        except Exception as e:
            return {
                'needs_download': False,
                'new_items': [],
                'changed_items': [],
                'removed_count': 0,
                'server_offline': False,
                'error': str(e)
            }
    
    def start_smart_poster_download(self, library, smart_result):
        """
        Start smart poster download for a library using pre-determined results.
        
        Args:
            library: Library dictionary with key and title
            smart_result: Smart check result
            
        Returns:
            bool: True if started successfully, False otherwise
        """
        try:
            library_id = library["key"]
            library_name = library["title"]
            
            # Combine new and changed items
            items_to_download = smart_result['new_items'] + smart_result['changed_items']
            
            if not items_to_download:
                print(f"[DEBUG] No items to download for {library_name}")
                return True
            
            # Initialize progress tracking
            with self.download_lock:
                self.download_progress[library_id] = {
                    "status": "downloading",
                    "total": len(items_to_download),
                    "downloaded": 0,
                    "message": f"Downloading posters for {library_name}",
                    "library_name": library_name,
                    "start_time": time.time()
                }
            
            # Add to download queue with smart data
            self.download_queue.append(('smart_library', {
                'library': library,
                'items': items_to_download,
                'smart_result': smart_result
            }))
            
            print(f"[INFO] Added smart download for library {library_name}: {len(items_to_download)} items")
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to start smart poster download for library {library_id}: {e}")
            return False
    
    def start_abs_poster_download(self, force_download=False):
        """
        Start ABS poster download by adding it to the queue.
        
        Args:
            force_download: Whether to force download even if files exist
            
        Returns:
            bool: True if started successfully, False otherwise
        """
        try:
            # Initialize progress tracking for ABS
            with self.download_lock:
                self.download_progress['abs'] = {
                    "status": "downloading",
                    "total": 1,
                    "downloaded": 0,
                    "message": "Downloading Audiobookshelf posters...",
                    "library_name": "Audiobookshelf",
                    "start_time": time.time()
                }
            
            # Add to download queue
            self.download_queue.append(('abs_download', {
                'force_download': force_download
            }))
            
            print(f"[INFO] Added ABS poster download to queue")
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to start ABS poster download: {e}")
            return False
    
    def _download_smart_library_posters(self, library, items, smart_result):
        """
        Download posters for a library using smart pre-determined items.
        
        Args:
            library (dict): Library information with 'key' and 'title'
            items (list): List of items to download
            smart_result (dict): Smart check result
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
            
            print(f"[INFO] Found {len(items)} items to download for {library_name}")
            
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
            
            # Create completion timestamp file
            completion_file = os.path.join(lib_dir, ".last_completion")
            try:
                with open(completion_file, 'w') as f:
                    f.write(str(time.time()))
                print(f"[INFO] Created completion timestamp for library {library_name}")
            except Exception as e:
                print(f"[WARN] Failed to create completion timestamp for library {library_name}: {e}")
            
            print(f"[INFO] Completed smart poster downloads for library {library_name}: {successful_downloads}/{len(items)}")
            
        except Exception as e:
            print(f"[ERROR] Failed to download smart posters for library {library_id}: {e}")
            with self.download_lock:
                self.download_progress[library_id] = {
                    "status": "error",
                    "message": f"Error downloading posters for {library_name}: {str(e)}",
                    "library_name": library_name,
                    "end_time": time.time()
                } 

    def _download_abs_posters(self, force_download=False):
        """Download ABS posters (internal method for background worker)"""
        try:
            # Call the existing method
            success = self.download_abs_audiobook_posters(check_local_first=not force_download)
            
            # Update progress
            with self.download_lock:
                if 'abs' in self.download_progress:
                    if success:
                        self.download_progress['abs'].update({
                            "status": "completed",
                            "downloaded": 1,
                            "message": "ABS poster downloads completed",
                            "end_time": time.time()
                        })
                    else:
                        self.download_progress['abs'].update({
                            "status": "error",
                            "message": "ABS poster downloads failed",
                            "end_time": time.time()
                        })
            
            return success
            
        except Exception as e:
            print(f"[ERROR] Failed to download ABS posters: {e}")
            with self.download_lock:
                if 'abs' in self.download_progress:
                    self.download_progress['abs'].update({
                        "status": "error",
                        "message": f"ABS poster download error: {str(e)}",
                        "end_time": time.time()
                    })
            return False
    
    def download_abs_audiobook_posters(self, check_local_first=False):
        """Download audiobook posters from ABS API"""
        try:
            abs_url = self.config.get("AUDIOBOOKSHELF_URL")
            if not abs_url:
                print("[WARN] ABS enabled but AUDIOBOOKSHELF_URL not set")
                return False
            
            print(f"[INFO] Starting ABS audiobook poster download from: {abs_url}")
            
            # Check if posters need refreshing (skip if check_local_first is enabled)
            if not check_local_first and not self.should_refresh_abs_posters():
                print("[DEBUG] Skipping ABS poster download - posters are recent")
                return True
            
            audiobook_dir = os.path.join("static", "posters", "audiobooks")
            os.makedirs(audiobook_dir, exist_ok=True)
            
            print(f"[DEBUG] Using audiobook directory: {audiobook_dir}")
            
            # Get ABS headers
            headers = self._get_abs_headers()
            if not headers:
                print("[ERROR] Failed to get ABS headers")
                return False
            
            # Get ABS libraries
            libraries = self._fetch_abs_libraries(abs_url, headers)
            if not libraries:
                print("[WARN] No ABS libraries found or failed to fetch libraries")
                return False
            
            poster_count = 0
            book_libraries = [lib for lib in libraries if isinstance(lib, dict) and lib.get("mediaType") == "book"]
            
            print(f"[DEBUG] Found {len(book_libraries)} book libraries in ABS")
            
            # Update progress to show ABS download is starting
            with self.download_lock:
                self.download_progress['abs'] = {
                    'current': 0,
                    'total': len(book_libraries),
                    'library_name': 'Audiobooks',
                    'type': 'abs',
                    'status': 'in_progress'
                }
                
                # Update unified progress to show ABS is in progress
                if 'unified' in self.download_progress:
                    self.download_progress['unified']['status'] = 'abs_downloading'
                    self.download_progress['unified']['message'] = 'Downloading Audiobook posters...'
                    self.download_progress['unified']['current'] = 0
                    self.download_progress['unified']['total'] = len(book_libraries)
                    self.download_progress['unified']['last_update'] = time.time()
            
            for i, library in enumerate(book_libraries):
                library_id = library.get("id")
                library_name = library.get("name", f"Library {library_id}")
                
                print(f"[DEBUG] Processing ABS library: {library_name} (ID: {library_id})")
                
                # Update progress - always show "Audiobooks" instead of individual library names
                with self.download_lock:
                    if 'abs' in self.download_progress:
                        self.download_progress['abs']['current'] = i + 1
                        self.download_progress['abs']['library_name'] = 'Audiobooks'
                    
                    # Update unified progress - always show "Audiobooks"
                    if 'unified' in self.download_progress:
                        self.download_progress['unified']['current'] = i + 1
                        self.download_progress['unified']['message'] = 'Downloading Audiobook posters...'
                
                books = self._fetch_abs_books(abs_url, library_id, headers)
                
                if books:
                    print(f"[DEBUG] Processing {len(books)} books from ABS library {library_name}")
                    
                    for book in books:
                        poster_count = self._download_abs_book_poster(
                            abs_url, book, library_id, audiobook_dir, poster_count, headers
                        )
                else:
                    print(f"[WARN] No books found in ABS library {library_name}")
            
            print(f"[INFO] Completed ABS audiobook poster download: {poster_count} posters downloaded")
            
            # Mark as complete
            with self.download_lock:
                if 'abs' in self.download_progress:
                    self.download_progress['abs']['status'] = 'completed'
                    self.download_progress['abs']['message'] = f'ABS downloads completed ({poster_count} posters)'
                    self.download_progress['abs']['end_time'] = time.time()
                
                # Update unified progress
                if 'unified' in self.download_progress:
                    self.download_progress['unified']['status'] = 'completed'
                    self.download_progress['unified']['message'] = f'ABS downloads completed ({poster_count} posters)'
                    self.download_progress['unified']['end_time'] = time.time()
            
            # Save completion timestamp to prevent unnecessary re-downloads
            try:
                abs_completion_file = os.path.join(audiobook_dir, ".last_completion")
                os.makedirs(os.path.dirname(abs_completion_file), exist_ok=True)
                with open(abs_completion_file, 'w') as f:
                    f.write(str(time.time()))
                print(f"[DEBUG] Saved ABS completion timestamp to {abs_completion_file}")
            except Exception as e:
                print(f"[WARN] Failed to save ABS completion timestamp: {e}")
            
            return True
            
        except Exception as e:
            print(f"[ERROR] Error downloading ABS audiobook posters: {e}")
            import traceback
            traceback.print_exc()
            
            # Mark as failed
            with self.download_lock:
                if 'abs' in self.download_progress:
                    self.download_progress['abs']['status'] = 'failed'
                    self.download_progress['abs']['message'] = f'ABS download failed: {str(e)}'
                    self.download_progress['abs']['end_time'] = time.time()
            
            return False
    
    def _get_abs_headers(self):
        """Get headers for ABS API requests"""
        try:
            abs_token = self.config.get("AUDIOBOOKSHELF_TOKEN")
            if not abs_token:
                print("[WARN] No ABS token available")
                return None
            
            return {
                "Authorization": f"Bearer {abs_token}"
            }
        except Exception as e:
            print(f"[ERROR] Failed to get ABS headers: {e}")
            return None
    
    def _fetch_abs_libraries(self, abs_url, headers):
        """Fetch ABS libraries"""
        try:
            url = f"{abs_url}/api/libraries"
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            return data.get('libraries', [])
        except Exception as e:
            print(f"[ERROR] Failed to fetch ABS libraries: {e}")
            return []
    
    def _fetch_abs_books(self, abs_url, library_id, headers):
        """Fetch books from ABS library"""
        try:
            url = f"{abs_url}/api/libraries/{library_id}/items"
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            return data.get('results', [])
        except Exception as e:
            print(f"[ERROR] Failed to fetch ABS books for library {library_id}: {e}")
            return []
    
    def _download_abs_book_poster(self, abs_url, book, library_id, audiobook_dir, poster_count, headers):
        """Download a single ABS book poster"""
        try:
            book_id = book.get('id')
            if not book_id:
                return poster_count
            
            # Get book metadata
            media = book.get('media', {})
            metadata = media.get('metadata', {})
            title = metadata.get('title', 'Unknown')
            author = metadata.get('authorName', '')
            
            print(f"[DEBUG] Processing ABS book: {title} by {author} (ID: {book_id})")
            
            # Use the correct cover URL format like the old app
            cover_url = f"{abs_url}/api/items/{book_id}/cover"
            print(f"[DEBUG] Downloading cover for ABS book: {title} from {cover_url}")
            
            # Create unique filename using the old app's naming convention
            out_path = os.path.join(audiobook_dir, f"audiobook{poster_count+1}.webp")
            meta_path = os.path.join(audiobook_dir, f"audiobook{poster_count+1}.json")
            
            # Skip if already exists and recent
            if os.path.exists(out_path) and os.path.exists(meta_path):
                file_age = time.time() - os.path.getmtime(out_path)
                if file_age < 43200:  # 12 hours
                    return poster_count + 1
            
            # Download cover image
            response = requests.get(cover_url, headers=headers, timeout=10, stream=True)
            if response.status_code == 200:
                # Check content length for size limit
                content_length = response.headers.get('content-length')
                max_size_bytes = self.POSTER_DOWNLOAD_LIMITS['max_download_size_mb'] * 1024 * 1024
                
                if content_length and int(content_length) > max_size_bytes:
                    print(f"[WARN] ABS poster too large ({content_length} bytes) for {title}")
                    return poster_count
                
                # Stream download to check size and save
                content = b""
                for chunk in response.iter_content(chunk_size=8192):
                    content += chunk
                    if len(content) > max_size_bytes:
                        print(f"[WARN] ABS poster download exceeded size limit for {title}")
                        return poster_count
                
                with open(out_path, "wb") as f:
                    f.write(content)
                
                # Save metadata using the old app's format
                meta = {
                    "title": title,
                    "author": author,
                    "id": book_id,
                    "library_id": library_id
                }
                
                with open(meta_path, "w", encoding="utf-8") as f:
                    json.dump(meta, f, ensure_ascii=False, indent=2)
                
                poster_count += 1
                print(f"[DEBUG] Successfully downloaded poster and metadata for ABS book: {title}")
                
                # Rate limiting - small delay between requests
                time.sleep(0.1)
            else:
                print(f"[ERROR] Failed to download ABS poster for {title}: HTTP {response.status_code}")
            
            return poster_count
            
        except Exception as e:
            print(f"[ERROR] Failed to download ABS poster for {book.get('title', 'Unknown')}: {e}")
            return poster_count
    
    def get_random_posters(self, library_id, count=10):
        """
        Get random posters for a specific library.
        
        Args:
            library_id: Library ID
            count: Number of posters to return
            
        Returns:
            list: List of poster data
        """
        try:
            lib_dir = self._get_library_poster_dir(library_id)
            posters = []
            
            if os.path.exists(lib_dir):
                # Get all image files
                image_files = [f for f in os.listdir(lib_dir) if f.lower().endswith(('.webp', '.jpg', '.jpeg', '.png'))]
                
                if image_files:
                    # Randomly select posters
                    selected_files = random.sample(image_files, min(count, len(image_files)))
                    
                    for fname in selected_files:
                        poster_path = f"/static/posters/{library_id}/{fname}"
                        
                        # Load metadata
                        json_path = os.path.join(lib_dir, fname.rsplit('.', 1)[0] + '.json')
                        metadata = {}
                        
                        if os.path.exists(json_path):
                            try:
                                with open(json_path, 'r', encoding='utf-8') as f:
                                    metadata = json.load(f)
                            except Exception as e:
                                print(f"[WARN] Failed to load metadata for {fname}: {e}")
                        
                        posters.append({
                            'poster_url': poster_path,
                            'title': metadata.get('title', 'Unknown'),
                            'year': metadata.get('year'),
                            'imdb_id': metadata.get('guids', {}).get('imdb'),
                            'rating_key': metadata.get('ratingKey')
                        })
            
            return posters
            
        except Exception as e:
            print(f"[ERROR] Failed to get random posters for library {library_id}: {e}")
            return []
    
    def get_random_posters_all(self, count=10):
        """
        Get random posters from all libraries.
        
        Args:
            count: Number of posters to return
            
        Returns:
            list: List of poster data
        """
        try:
            # Get all library directories
            posters_dir = os.path.join("static", "posters")
            all_posters = []
            
            if os.path.exists(posters_dir):
                for lib_dir in os.listdir(posters_dir):
                    lib_path = os.path.join(posters_dir, lib_dir)
                    
                    # Skip non-directories and audiobooks directory
                    if not os.path.isdir(lib_path) or lib_dir == "audiobooks":
                        continue
                    
                    # Get posters from this library
                    lib_posters = self.get_random_posters(lib_dir, count)
                    all_posters.extend(lib_posters)
            
            # Randomly select from all posters
            if all_posters:
                return random.sample(all_posters, min(count, len(all_posters)))
            
            return []
            
        except Exception as e:
            print(f"[ERROR] Failed to get random posters from all libraries: {e}")
            return []
    
    def get_random_audiobook_posters(self, count=10):
        """
        Get random audiobook posters.
        
        Args:
            count: Number of posters to return
            
        Returns:
            list: List of poster data
        """
        try:
            audiobook_dir = os.path.join("static", "posters", "audiobooks")
            posters = []
            
            if os.path.exists(audiobook_dir):
                # Get all image files
                image_files = [f for f in os.listdir(audiobook_dir) if f.lower().endswith(('.webp', '.jpg', '.jpeg', '.png'))]
                
                if image_files:
                    # Randomly select posters
                    selected_files = random.sample(image_files, min(count, len(image_files)))
                    
                    for fname in selected_files:
                        poster_path = f"/static/posters/audiobooks/{fname}"
                        
                        # Load metadata
                        json_path = os.path.join(audiobook_dir, fname.rsplit('.', 1)[0] + '.json')
                        metadata = {}
                        
                        if os.path.exists(json_path):
                            try:
                                with open(json_path, 'r', encoding='utf-8') as f:
                                    metadata = json.load(f)
                            except Exception as e:
                                print(f"[WARN] Failed to load metadata for {fname}: {e}")
                        
                        posters.append({
                            'poster_url': poster_path,
                            'title': metadata.get('title', 'Unknown'),
                            'author': metadata.get('author', ''),
                            'series': metadata.get('series', ''),
                            'book_id': metadata.get('id'),
                            'library_id': metadata.get('library_id')
                        })
            
            return posters
            
        except Exception as e:
            print(f"[ERROR] Failed to get random audiobook posters: {e}")
            return []
    
    def get_posters_by_letter(self, library_id, letter, limit=50):
        """
        Get posters filtered by letter for a library.
        
        Args:
            library_id: Library ID
            letter: Letter to filter by
            limit: Maximum number of posters to return
            
        Returns:
            list: List of poster data
        """
        try:
            lib_dir = self._get_library_poster_dir(library_id)
            posters = []
            
            if os.path.exists(lib_dir):
                # Get all image files
                image_files = [f for f in os.listdir(lib_dir) if f.lower().endswith(('.webp', '.jpg', '.jpeg', '.png'))]
                
                for fname in image_files:
                    # Load metadata to check title
                    json_path = os.path.join(lib_dir, fname.rsplit('.', 1)[0] + '.json')
                    metadata = {}
                    
                    if os.path.exists(json_path):
                        try:
                            with open(json_path, 'r', encoding='utf-8') as f:
                                metadata = json.load(f)
                        except Exception as e:
                            print(f"[WARN] Failed to load metadata for {fname}: {e}")
                            continue
                    
                    title = metadata.get('title', '')
                    if title and title.lower().startswith(letter.lower()):
                        poster_path = f"/static/posters/{library_id}/{fname}"
                        posters.append({
                            'poster_url': poster_path,
                            'title': title,
                            'year': metadata.get('year'),
                            'imdb_id': metadata.get('guids', {}).get('imdb'),
                            'rating_key': metadata.get('ratingKey')
                        })
                        
                        if len(posters) >= limit:
                            break
            
            return posters
            
        except Exception as e:
            print(f"[ERROR] Failed to get posters by letter for library {library_id}: {e}")
            return [] 

    def process_smart_library_download(self, lib, smart_result):
        """
        Process smart library downloads using pre-determined smart check results.
        
        Args:
            lib: Library dictionary with key and title
            smart_result: Smart check result from smart_check_library_posters
        """
        section_id = lib["key"]
        library_name = lib["title"]
        
        log_debug("poster_service", f"Processing smart download for {library_name}: {len(smart_result['new_items'])} new, {len(smart_result['changed_items'])} changed")
        
        # Get Plex credentials
        plex_token = self.config.get("PLEX_TOKEN")
        plex_url = self.config.get("PLEX_URL")
        
        if not plex_token or not plex_url:
            log_error("poster_service", f"No Plex credentials available for smart download of {library_name}")
            return
        
        headers = {"X-Plex-Token": plex_token}
        lib_dir = self._get_library_poster_dir(section_id)
        os.makedirs(lib_dir, exist_ok=True)
        
        # Combine new and changed items
        items_to_download = smart_result['new_items'] + smart_result['changed_items']
        
        if not items_to_download:
            log_debug("poster_service", f"No items to download for {library_name}")
            return
        
        # Download items with ThreadPoolExecutor
        successful_downloads = 0
        
        with ThreadPoolExecutor(max_workers=self.poster_download_limits['max_concurrent_downloads']) as executor:
            futures = []
            for i, item in enumerate(items_to_download):
                future = executor.submit(self._download_single_poster_with_metadata, item, lib_dir, i, headers)
                futures.append(future)
            
            # Wait for completion and update progress
            for i, future in enumerate(as_completed(futures)):
                if future.result():
                    successful_downloads += 1
                
                # Update progress
                with self.poster_download_lock:
                    lib_id = lib["key"]
                    if lib_id in self.poster_download_progress:
                        self.poster_download_progress[lib_id].update({
                            'current': successful_downloads,
                            'last_update': time.time()
                        })
        
        log_debug("poster_service", f"Smart download for {library_name}: Downloaded {successful_downloads}/{len(items_to_download)} posters")
        
        # Save completion timestamp to prevent unnecessary re-downloads
        try:
            plex_completion_file = os.path.join(lib_dir, ".last_completion")
            with open(plex_completion_file, 'w') as f:
                f.write(str(time.time()))
            log_debug("poster_service", f"Saved Plex completion timestamp for library {section_id} to {plex_completion_file}")
        except Exception as e:
            log_debug("poster_service", f"Could not save Plex completion timestamp for library {section_id}: {e}")
    
    def process_smart_abs_download(self, smart_result):
        """
        Process smart ABS downloads using pre-determined smart check results.
        
        Args:
            smart_result: Smart check result from smart_check_abs_posters
        """
        log_debug("poster_service", f"Processing smart ABS download: {len(smart_result['new_items'])} new, {len(smart_result['changed_items'])} changed")
        
        # Get ABS credentials
        abs_url = self.config.get("AUDIOBOOKSHELF_URL")
        if not abs_url:
            log_error("poster_service", "No ABS URL available for smart download")
            return
        
        headers = self._get_abs_headers()
        audiobook_dir = os.path.join("static", "posters", "audiobooks")
        os.makedirs(audiobook_dir, exist_ok=True)
        
        # Combine new and changed items
        items_to_download = smart_result['new_items'] + smart_result['changed_items']
        
        if not items_to_download:
            log_debug("poster_service", "No ABS items to download")
            return
        
        # Download items
        successful_downloads = 0
        
        for item in items_to_download:
            try:
                library_id = item['library_id']
                book_id = item['book_id']
                book = item['book']
                
                # Download the book poster
                if self._download_abs_book_poster(abs_url, book, library_id, audiobook_dir, successful_downloads, headers):
                    successful_downloads += 1
            except Exception as e:
                log_error("poster_service", f"Failed to download ABS poster for book {item.get('book_id', 'unknown')}: {e}")
        
        log_debug("poster_service", f"Smart ABS download: Downloaded {successful_downloads}/{len(items_to_download)} posters")
        
        # Save completion timestamp to prevent unnecessary re-downloads
        try:
            abs_completion_file = os.path.join(audiobook_dir, ".last_completion")
            with open(abs_completion_file, 'w') as f:
                f.write(str(time.time()))
            log_debug("poster_service", f"Saved ABS completion timestamp to {abs_completion_file}")
        except Exception as e:
            log_debug("poster_service", f"Could not save ABS completion timestamp: {e}")
    
    def should_refresh_posters(self, library_id, incremental_mode=False):
        """
        Check if posters for a library need refreshing based on age or missing metadata.
        Returns True if posters should be refreshed, False otherwise.
        
        Args:
            library_id: The library ID to check
            incremental_mode: If True, only check for missing metadata, not age
        """
        poster_dir = self._get_library_poster_dir(library_id)
        if not os.path.exists(poster_dir):
            return True
        
        # Check if any poster files exist
        poster_files = [f for f in os.listdir(poster_dir) if f.lower().endswith(('.webp', '.jpg', '.jpeg', '.png'))]
        if not poster_files:
            return True
        
        # Check for missing metadata files - if any poster is missing metadata, refresh is needed
        for poster_file in poster_files:
            if poster_file.startswith('poster_') and poster_file.endswith('.webp'):
                meta_file = poster_file.replace('.webp', '.json')
                meta_path = os.path.join(poster_dir, meta_file)
                if not os.path.exists(meta_path):
                    log_debug("poster_service", f"Missing metadata for {poster_file}, triggering refresh for library {library_id}")
                    return True
        
        # In incremental mode, don't check age - only refresh if metadata is missing
        if incremental_mode:
            return False
        
        # Check the age of the most recent poster file
        most_recent_time = max(os.path.getmtime(os.path.join(poster_dir, f)) for f in poster_files)
        current_time = time.time()
        
        # Return True if posters are older than POSTER_REFRESH_INTERVAL
        return (current_time - most_recent_time) > self.config.get_int("POSTER_REFRESH_INTERVAL", 86400)
    
    def get_existing_poster_rating_keys(self, library_id):
        """
        Get a set of rating keys for existing posters in a library.
        
        Args:
            library_id: The library ID to check
            
        Returns:
            set: Set of rating keys for existing posters
        """
        poster_dir = self._get_library_poster_dir(library_id)
        if not os.path.exists(poster_dir):
            return set()
        
        existing_keys = set()
        for fname in os.listdir(poster_dir):
            if fname.startswith('poster_') and fname.endswith('.webp'):
                # Extract rating key from filename (poster_12345.webp -> 12345)
                rating_key = fname[7:-5]  # Remove 'poster_' prefix and '.webp' suffix
                if rating_key.isdigit():
                    existing_keys.add(rating_key)
        
        return existing_keys
    
    def cleanup_deleted_posters(self, library_id, current_rating_keys):
        """
        Remove posters for items that no longer exist in the Plex library.
        
        Args:
            library_id: The library ID to clean up
            current_rating_keys: Set of rating keys that currently exist in Plex
            
        Returns:
            int: Number of posters removed
        """
        poster_dir = self._get_library_poster_dir(library_id)
        if not os.path.exists(poster_dir):
            return 0
        
        removed_count = 0
        existing_keys = self.get_existing_poster_rating_keys(library_id)
        
        # Find keys that exist locally but not in Plex
        deleted_keys = existing_keys - current_rating_keys
        
        for rating_key in deleted_keys:
            poster_file = os.path.join(poster_dir, f"poster_{rating_key}.webp")
            meta_file = os.path.join(poster_dir, f"poster_{rating_key}.json")
            
            # Remove poster file
            if os.path.exists(poster_file):
                try:
                    os.remove(poster_file)
                    log_debug("poster_service", f"Removed deleted poster: poster_{rating_key}.webp")
                    removed_count += 1
                except Exception as e:
                    log_error("poster_service", f"Failed to remove poster {poster_file}: {e}")
            
            # Remove metadata file
            if os.path.exists(meta_file):
                try:
                    os.remove(meta_file)
                    log_debug("poster_service", f"Removed deleted metadata: poster_{rating_key}.json")
                except Exception as e:
                    log_error("poster_service", f"Failed to remove metadata {meta_file}: {e}")
        
        if removed_count > 0:
            log_debug("poster_service", f"Cleaned up {removed_count} deleted posters for library {library_id}")
        else:
            log_debug("poster_service", f"No deleted posters found for library {library_id}")
        
        return removed_count 
    
    def process_library_posters_incremental(self, lib, plex_url, headers, background=False):
        """
        Process poster downloads for a single library in incremental mode.
        Only downloads new posters and removes deleted ones.
        
        Args:
            lib: Library dictionary with key and title
            plex_url: Plex server URL
            headers: Request headers with token
            background: Whether running in background mode
            
        Returns:
            tuple: (new_downloads, removed_count)
        """
        section_id = lib["key"]
        library_name = lib["title"]
        
        # Check if posters need refreshing (incremental mode)
        if not self.should_refresh_posters(section_id, incremental_mode=True):
            log_debug("poster_service", f"Skipping incremental poster refresh for {library_name} - no missing metadata")
            return 0, 0
        
        lib_dir = self._get_library_poster_dir(section_id)
        os.makedirs(lib_dir, exist_ok=True)
        
        try:
            # Fetch library items
            url = f"{plex_url}/library/sections/{section_id}/all"
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            root = ET.fromstring(response.content)
            
            # Collect current items from Plex
            current_items = []
            current_rating_keys = set()
            
            for el in root.findall(".//Video"):
                thumb = el.attrib.get("thumb")
                rating_key = el.attrib.get("ratingKey")
                title = el.attrib.get("title")
                year = el.attrib.get("year")
                if thumb and rating_key:
                    current_items.append({"thumb": thumb, "ratingKey": rating_key, "title": title, "year": year})
                    current_rating_keys.add(rating_key)
            
            for el in root.findall(".//Directory"):
                thumb = el.attrib.get("thumb")
                rating_key = el.attrib.get("ratingKey")
                title = el.attrib.get("title")
                if thumb and rating_key and not any(i["ratingKey"] == rating_key for i in current_items):
                    current_items.append({"thumb": thumb, "ratingKey": rating_key, "title": title})
                    current_rating_keys.add(rating_key)
            
            # Clean up deleted posters
            removed_count = self.cleanup_deleted_posters(section_id, current_rating_keys)
            
            # Get existing poster rating keys
            existing_keys = self.get_existing_poster_rating_keys(section_id)
            
            # Find new items that need posters
            new_items = []
            for item in current_items:
                if item["ratingKey"] not in existing_keys:
                    new_items.append(item)
            
            log_debug("poster_service", f"Incremental refresh for {library_name}: {len(new_items)} new items, {removed_count} removed")
            
            if not new_items:
                return 0, removed_count
            
            # Update status to indicate processing has started
            if background:
                with self.poster_download_lock:
                    # Initialize or update progress for this library with library name
                    if section_id not in self.poster_download_progress:
                        self.poster_download_progress[section_id] = {}
                    self.poster_download_progress[section_id].update({
                        'current': 0,
                        'total': len(new_items),
                        'successful': 0,
                        'status': 'processing_incremental',
                        'library_name': library_name,
                        'last_update': time.time()
                    })
                    
                    # Update unified progress for Plex downloads
                    if 'unified' in self.poster_download_progress and self.poster_download_progress['unified']['status'] == 'plex_downloading':
                        # Calculate overall progress across all libraries
                        total_libraries = self.poster_download_progress['unified'].get('total', 1)
                        current_library = self.poster_download_progress['unified'].get('current', 0)
                        self.poster_download_progress['unified']['message'] = f'Downloading posters for {library_name}...'
            
            # Download new posters with ThreadPoolExecutor
            successful_downloads = 0
            
            with ThreadPoolExecutor(max_workers=self.poster_download_limits['max_concurrent_downloads']) as executor:
                futures = []
                for i, item in enumerate(new_items):
                    future = executor.submit(self._download_single_poster_with_metadata, item, lib_dir, i, headers)
                    futures.append(future)
                
                # Wait for completion with progress tracking
                for i, future in enumerate(as_completed(futures)):
                    if future.result():
                        successful_downloads += 1
                    if background and i % 5 == 0:  # Update progress every 5 items
                        with self.poster_download_lock:
                            if section_id in self.poster_download_progress:
                                self.poster_download_progress[section_id].update({
                                    'current': i + 1,
                                    'total': len(new_items),
                                    'successful': successful_downloads,
                                    'status': 'processing_incremental',
                                    'library_name': library_name,
                                    'last_update': time.time()
                                })
                            
                            # Update unified progress for Plex downloads
                            if 'unified' in self.poster_download_progress and self.poster_download_progress['unified']['status'] == 'plex_downloading':
                                self.poster_download_progress['unified']['message'] = f'Downloading {library_name} ({i + 1}/{len(new_items)})'
            
            log_debug("poster_service", f"Incremental refresh for {library_name}: Downloaded {successful_downloads}/{len(new_items)} new posters, removed {removed_count} deleted posters")
            
            # Clear progress for this library when complete
            with self.poster_download_lock:
                if section_id in self.poster_download_progress:
                    del self.poster_download_progress[section_id]
            
            return successful_downloads, removed_count
            
        except Exception as e:
            log_error("poster_service", f"Error in incremental poster refresh for section {section_id}: {e}")
            return 0, 0
    
    def should_refresh_abs_posters(self):
        """
        Check if ABS audiobook posters need refreshing based on age.
        Returns True if posters should be refreshed, False otherwise.
        """
        audiobook_dir = os.path.join("static", "posters", "audiobooks")
        if not os.path.exists(audiobook_dir):
            log_debug("poster_service", "ABS poster directory does not exist, refresh needed")
            return True
        
        # Check if any poster files exist
        poster_files = [f for f in os.listdir(audiobook_dir) if f.lower().endswith(('.webp', '.jpg', '.jpeg', '.png'))]
        if not poster_files:
            log_debug("poster_service", "No ABS poster files found, refresh needed")
            return True
        
        # Check the age of the most recent poster file
        most_recent_time = max(os.path.getmtime(os.path.join(audiobook_dir, f)) for f in poster_files)
        current_time = time.time()
        age_hours = (current_time - most_recent_time) / 3600
        
        # Return True if posters are older than POSTER_REFRESH_INTERVAL
        needs_refresh = (current_time - most_recent_time) > self.config.get_int("POSTER_REFRESH_INTERVAL", 86400)
        
        log_debug("poster_service", f"ABS posters age: {age_hours:.1f} hours, refresh needed: {needs_refresh}")
        
        return needs_refresh
    
    def fix_missing_metadata_files(self):
        """Check for and fix missing metadata files for existing posters"""
        try:
            log_debug("poster_service", "Checking for missing metadata files...")
            
            # Get Plex credentials
            plex_token = self.config.get("PLEX_TOKEN")
            plex_url = self.config.get("PLEX_URL")
            
            if not plex_token or not plex_url:
                log_error("poster_service", "Plex credentials not available for metadata fix")
                return False
            
            headers = {"X-Plex-Token": plex_token}
            fixed_count = 0
            
            # Check each library directory
            for lib_dir in ["posters/movies", "posters/shows"]:
                if not os.path.exists(lib_dir):
                    continue
        
                log_debug("poster_service", f"Checking library directory: {lib_dir}")
                
                # Find all poster files
                poster_files = [f for f in os.listdir(lib_dir) if f.endswith('.webp')]
                
                for poster_file in poster_files:
                    # Extract rating key from filename
                    if poster_file.startswith('poster_') and poster_file.endswith('.webp'):
                        rating_key = poster_file[7:-5]  # Remove 'poster_' prefix and '.webp' suffix
                        meta_file = poster_file.replace('.webp', '.json')
                        meta_path = os.path.join(lib_dir, meta_file)
                        
                        # If metadata file is missing, try to recreate it
                        if not os.path.exists(meta_path):
                            log_debug("poster_service", f"Missing metadata for poster: {poster_file}, ratingKey: {rating_key}")
                            
                            try:
                                # Try to fetch metadata from Plex
                                meta_url = f"{plex_url}/library/metadata/{rating_key}"
                                meta_resp = requests.get(meta_url, headers=headers, timeout=10)
                                
                                if meta_resp.status_code == 200:
                                    meta_root = ET.fromstring(meta_resp.content)
                                    
                                    # Extract basic info
                                    title_elem = meta_root.find(".//title")
                                    year_elem = meta_root.find(".//year")
                                    
                                    title = title_elem.text if title_elem is not None else f"Unknown_{rating_key}"
                                    year = year_elem.text if year_elem is not None else None
                                    
                                    # Extract GUIDs
                                    guids = {"imdb": None, "tmdb": None, "tvdb": None}
                                    for guid in meta_root.findall(".//Guid"):
                                        gid = guid.attrib.get("id", "")
                                        if gid.startswith("imdb://"):
                                            guids["imdb"] = gid.replace("imdb://", "")
                                        elif gid.startswith("tmdb://"):
                                            guids["tmdb"] = gid.replace("tmdb://", "")
                                        elif gid.startswith("tvdb://"):
                                            guids["tvdb"] = gid.replace("tvdb://", "")
                                    
                                    # Create metadata
                                    meta = {
                                        "title": title,
                                        "ratingKey": rating_key,
                                        "year": year,
                                        "imdb": guids["imdb"],
                                        "tmdb": guids["tmdb"],
                                        "tvdb": guids["tvdb"],
                                        "poster": poster_file
                                    }
                                    
                                    # Save metadata
                                    with open(meta_path, "w", encoding="utf-8") as f:
                                        json.dump(meta, f, indent=2)
                                    
                                    fixed_count += 1
                                    log_debug("poster_service", f"Fixed metadata for: {title} (ratingKey: {rating_key})")
                                
                            except Exception as e:
                                log_error("poster_service", f"Failed to fix metadata for {poster_file}: {e}")
            
            log_debug("poster_service", f"Metadata fix complete. Fixed {fixed_count} missing metadata files.")
            
            return fixed_count > 0
            
        except Exception as e:
            log_error("poster_service", f"Error in fix_missing_metadata_files: {e}")
            return False
    
    def compare_local_vs_server_metadata(self, local_meta, server_item):
        """
        Compare local metadata with server metadata to detect changes.
        Returns True if metadata has changed and needs re-download.
        
        Args:
            local_meta: Local metadata dictionary
            server_item: Server item dictionary with attributes
            
        Returns:
            bool: True if metadata has changed
        """
        if not local_meta or not server_item:
            return True
        
        # Compare key metadata fields - only thumb changes should trigger re-download
        # Title and year changes are usually just metadata updates, not poster changes
        thumb_local = local_meta.get('thumb', '')
        thumb_server = server_item.get('thumb', '')
        
        # If local metadata doesn't have thumb field, it's an old format file
        # We should only trigger re-download if the server has a thumb and local doesn't
        if not thumb_local and thumb_server:
            log_debug("poster_service", f"Old metadata format detected, adding thumb field: '{thumb_server}'")
            return True
        
        # Only trigger re-download if the thumb URL has actually changed
        if str(thumb_local).strip() != str(thumb_server).strip():
            log_debug("poster_service", f"Thumb URL change detected: '{thumb_local}' -> '{thumb_server}'")
            return True
        
        return False
    
    def _smart_check_abs_posters(self, abs_url, headers):
        """
        Smart check for ABS posters - compares local files with server and determines what needs updating.
        
        Args:
            abs_url: ABS server URL
            headers: Request headers with token
            
        Returns:
            dict: {
                'needs_download': bool,
                'new_items': list,
                'changed_items': list,
                'removed_count': int,
                'server_offline': bool,
                'error': str
            }
        """
        result = {
            'needs_download': False,
            'new_items': [],
            'changed_items': [],
            'removed_count': 0,
            'server_offline': False,
            'error': None
        }
        
        try:
            # Check if server is reachable
            test_url = f"{abs_url}/api/libraries"
            response = requests.get(test_url, headers=headers, timeout=5)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            log_debug("poster_service", f"ABS server offline: {e}")
            result['server_offline'] = True
            return result
        
        try:
            # Get ABS libraries
            response = requests.get(test_url, headers=headers, timeout=10)
            response.raise_for_status()
            libraries_data = response.json()
            
            # Extract libraries from the response
            libraries = libraries_data.get('libraries', [])
            if not isinstance(libraries, list):
                log_debug("poster_service", f"Unexpected libraries format: {type(libraries)}")
                return result
            
            audiobook_dir = os.path.join("static", "posters", "audiobooks")
            os.makedirs(audiobook_dir, exist_ok=True)
            
            # Get existing ABS poster files - use the actual file naming convention
            existing_books = set()
            if os.path.exists(audiobook_dir):
                # Load all existing audiobook metadata to get book IDs
                for f in os.listdir(audiobook_dir):
                    if f.endswith('.json'):
                        try:
                            meta_path = os.path.join(audiobook_dir, f)
                            with open(meta_path, 'r', encoding='utf-8') as meta_file:
                                meta = json.load(meta_file)
                                book_id = meta.get('id')
                                library_id = meta.get('library_id')
                                if book_id and library_id:
                                    book_key = f"abs_book_{library_id}_{book_id}"
                                    existing_books.add(book_key)
                        except (IOError, json.JSONDecodeError):
                            continue
                
                log_debug("poster_service", f"Found {len(existing_books)} existing ABS books")
                if len(existing_books) > 0:
                    log_debug("poster_service", f"Sample existing books: {list(existing_books)[:5]}")
            
            # Check each library
            for library in libraries:
                library_id = library.get('id')
                if not library_id:
                    continue
                
                # Get books in this library
                books_url = f"{abs_url}/api/libraries/{library_id}/items"
                books_response = requests.get(books_url, headers=headers, timeout=10)
                books_response.raise_for_status()
                books_data = books_response.json()
                
                current_books = set()
                
                for book in books_data.get('results', []):
                    book_id = book.get('id')
                    if not book_id:
                        continue
                    
                    book_key = f"abs_book_{library_id}_{book_id}"
                    current_books.add(book_key)
                    
                    if book_key not in existing_books:
                        # New book - needs download
                        log_debug("poster_service", f"New ABS book detected: {book_key}")
                        result['new_items'].append({
                            'library_id': library_id,
                            'book_id': book_id,
                            'book': book
                        })
                        result['needs_download'] = True
                    else:
                        # Existing book - check if metadata changed
                        meta_file = os.path.join(audiobook_dir, f"{book_key}.json")
                        if os.path.exists(meta_file):
                            try:
                                with open(meta_file, 'r', encoding='utf-8') as f:
                                    local_meta = json.load(f)
                                
                                # Compare key metadata fields - use same field paths as when saving
                                server_title = book.get('title', '')
                                # Extract author from the same nested structure as when saving
                                media = book.get('media', {})
                                metadata = media.get('metadata', {})
                                server_author = metadata.get('authorName', '')
                                local_title = local_meta.get('title', '')
                                local_author = local_meta.get('author', '')
                                
                                # Add debug logging to see what's being compared
                                if (server_title != local_title or server_author != local_author):
                                    log_debug("poster_service", f"Metadata mismatch for book {book_id}:")
                                    log_debug("poster_service", f"  Server title: '{server_title}' vs Local title: '{local_title}'")
                                    log_debug("poster_service", f"  Server author: '{server_author}' vs Local author: '{local_author}'")
                                else:
                                    log_debug("poster_service", f"Metadata match for book {book_id}: '{server_title}' by '{server_author}'")
                                
                                if (server_title != local_title or server_author != local_author):
                                    result['changed_items'].append({
                                        'library_id': library_id,
                                        'book_id': book_id,
                                        'book': book
                                    })
                                    result['needs_download'] = True
                            except (IOError, json.JSONDecodeError):
                                result['changed_items'].append({
                                    'library_id': library_id,
                                    'book_id': book_id,
                                    'book': book
                                })
                                result['needs_download'] = True
                        else:
                            # Missing metadata file
                            result['changed_items'].append({
                                'library_id': library_id,
                                'book_id': book_id,
                                'book': book
                            })
                            result['needs_download'] = True
                
                # Clean up deleted books - this is more complex with the current file naming
                # For now, we'll skip cleanup to avoid breaking existing files
                # TODO: Implement proper cleanup when file naming is standardized
                pass
            
            log_debug("poster_service", f"Smart check for ABS: {len(result['new_items'])} new, {len(result['changed_items'])} changed, {result['removed_count']} removed")
            if result['server_offline']:
                log_debug("poster_service", "ABS server is offline")
            if result['error']:
                log_debug("poster_service", f"ABS check error: {result['error']}")
            
        except Exception as e:
            log_error("poster_service", f"Error in smart ABS check: {e}")
            log_debug("poster_service", f"Smart ABS check error details: {e}")
            result['error'] = str(e)
        
        return result
    
    def cleanup_poster_progress(self):
        """Clean up poster download progress to prevent memory leaks"""
        with self.poster_download_lock:
            # Remove completed downloads older than 1 hour
            current_time = time.time()
            cutoff_time = current_time - 3600
            
            # Clean up progress entries
            if len(self.poster_download_progress) > self.POSTER_DOWNLOAD_LIMITS['max_progress_entries']:
                # Remove oldest entries if we exceed the limit
                sorted_entries = sorted(self.poster_download_progress.items(), 
                                      key=lambda x: x[1].get('start_time', 0))
                entries_to_remove = len(self.poster_download_progress) - self.POSTER_DOWNLOAD_LIMITS['max_progress_entries']
                for i in range(entries_to_remove):
                    if sorted_entries:
                        del self.poster_download_progress[sorted_entries[i][0]]
            
            if self.config.get_bool("FLASK_DEBUG", False):
                if self.poster_download_progress:
                    print(f"[DEBUG] Cleaned up poster progress, {len(self.poster_download_progress)} entries remaining")
                    print(f"[DEBUG] Active progress entries: {list(self.poster_download_progress.keys())}")
                # Only log when there's actually something to report, not when there's nothing to clean up 

    def smart_refresh_posters(self, force_download=False):
        """
        Smart refresh that only downloads new posters and removes deleted ones.
        This prevents unnecessary re-downloading of existing posters.
        """
        try:
            log_info("poster_service", "Starting smart poster refresh")
            
            # Get all libraries
            libraries = self.get_ordered_libraries()
            if not libraries:
                log_warning("poster_service", "No libraries found for smart refresh")
                return
            
            total_downloaded = 0
            total_removed = 0
            
            for library in libraries:
                library_id = library["key"]
                library_name = library["title"]
                
                log_debug("poster_service", f"Smart refreshing posters for {library_name}")
                
                # Get current local posters
                poster_dir = self.get_library_poster_dir(library_id)
                local_posters = set()
                if os.path.exists(poster_dir):
                    local_posters = {
                        f.rsplit('.', 1)[0] for f in os.listdir(poster_dir) 
                        if f.lower().endswith(('.webp', '.jpg', '.jpeg', '.png'))
                    }
                
                # Get current remote posters from Plex
                try:
                    remote_items = self._get_library_items(library_id)
                    remote_posters = set()
                    
                    for item in remote_items:
                        if hasattr(item, 'ratingKey'):
                            remote_posters.add(str(item.ratingKey))
                    
                    # Find new posters to download
                    new_posters = remote_posters - local_posters
                    # Find deleted posters to remove
                    deleted_posters = local_posters - remote_posters
                    
                    log_debug("poster_service", f"{library_name}: {len(new_posters)} new, {len(deleted_posters)} deleted")
                    
                    # Download new posters
                    if new_posters and not force_download:
                        downloaded = self._download_specific_posters(library, new_posters)
                        total_downloaded += downloaded
                    
                    # Remove deleted posters
                    if deleted_posters:
                        removed = self._remove_deleted_posters(library_id, deleted_posters)
                        total_removed += removed
                        
                except Exception as e:
                    log_error("poster_service", f"Error smart refreshing {library_name}", {"library_id": library_id}, e)
                    continue
            
            log_info("poster_service", f"Smart refresh complete: {total_downloaded} new, {total_removed} removed")
            return total_downloaded, total_removed
            
        except Exception as e:
            log_error("poster_service", "Error in smart poster refresh", {}, e)
            return 0, 0
    
    def _download_specific_posters(self, library, poster_ids):
        """Download specific posters by their IDs"""
        library_id = library["key"]
        library_name = library["title"]
        downloaded = 0
        
        try:
            # Get Plex connection
            plex_url = self.config.get("PLEX_URL")
            plex_token = self.config.get("PLEX_TOKEN")
            
            if not plex_url or not plex_token:
                log_error("poster_service", "Plex credentials not configured", {"library_id": library_id})
                return 0
            
            from plexapi.server import PlexServer
            plex = PlexServer(plex_url, plex_token)
            
            # Get library
            plex_library = plex.library.sectionByID(library_id)
            if not plex_library:
                log_error("poster_service", f"Library {library_name} not found in Plex", {"library_id": library_id})
                return 0
            
            # Download each poster
            for poster_id in poster_ids:
                try:
                    item = plex_library.fetchItem(poster_id)
                    if item and hasattr(item, 'posterUrl'):
                        success = self._download_single_poster(item, library_id)
                        if success:
                            downloaded += 1
                except Exception as e:
                    log_debug("poster_service", f"Error downloading poster {poster_id}", {"library_id": library_id}, e)
                    continue
            
            log_debug("poster_service", f"Downloaded {downloaded}/{len(poster_ids)} specific posters for {library_name}")
            return downloaded
            
        except Exception as e:
            log_error("poster_service", f"Error downloading specific posters for {library_name}", {"library_id": library_id}, e)
            return 0
    
    def _remove_deleted_posters(self, library_id, poster_ids):
        """Remove posters that no longer exist in Plex"""
        poster_dir = self.get_library_poster_dir(library_id)
        removed = 0
        
        try:
            for poster_id in poster_ids:
                # Find and remove all files for this poster
                if os.path.exists(poster_dir):
                    for filename in os.listdir(poster_dir):
                        if filename.startswith(f"{poster_id}."):
                            file_path = os.path.join(poster_dir, filename)
                            try:
                                os.remove(file_path)
                                removed += 1
                                log_debug("poster_service", f"Removed deleted poster: {filename}")
                            except Exception as e:
                                log_debug("poster_service", f"Error removing {filename}", {}, e)
            
            log_debug("poster_service", f"Removed {removed} deleted posters from library {library_id}")
            return removed
            
        except Exception as e:
            log_error("poster_service", f"Error removing deleted posters from {library_id}", {}, e)
            return 0
    
    def _get_library_items(self, library_id):
        """Get all items from a Plex library"""
        try:
            plex_url = self.config.get("PLEX_URL")
            plex_token = self.config.get("PLEX_TOKEN")
            
            if not plex_url or not plex_token:
                log_error("poster_service", "Plex credentials not configured", {"library_id": library_id})
                return []
            
            from plexapi.server import PlexServer
            plex = PlexServer(plex_url, plex_token)
            
            # Get library
            plex_library = plex.library.sectionByID(library_id)
            if not plex_library:
                log_error("poster_service", f"Library {library_id} not found in Plex")
                return []
            
            # Get all items
            items = plex_library.all()
            log_debug("poster_service", f"Retrieved {len(items)} items from library {library_id}")
            return items
            
        except Exception as e:
            log_error("poster_service", f"Error getting items from library {library_id}", {}, e)
            return []
    
    def fix_missing_poster_fields(self):
        """
        Fix existing metadata files that are missing the poster field.
        This function should be called once to update old metadata files.
        
        Returns:
            int: Number of files fixed
        """
        fixed_count = 0
        
        try:
            # Get all library directories
            posters_dir = os.path.join("static", "posters")
            
            if not os.path.exists(posters_dir):
                return 0
            
            for lib_dir in os.listdir(posters_dir):
                lib_path = os.path.join(posters_dir, lib_dir)
                
                # Skip non-directories and audiobooks directory
                if not os.path.isdir(lib_path) or lib_dir == "audiobooks":
                    continue
                
                # Get all JSON files in this library directory
                json_files = [f for f in os.listdir(lib_path) if f.endswith('.json')]
                
                for json_file in json_files:
                    json_path = os.path.join(lib_path, json_file)
                    
                    try:
                        # Load existing metadata
                        with open(json_path, 'r', encoding='utf-8') as f:
                            meta = json.load(f)
                        
                        # Check if poster field is missing
                        if 'poster' not in meta:
                            # Extract rating key from filename (poster_123456.json -> poster_123456.webp)
                            rating_key = json_file.replace('.json', '')
                            poster_filename = f"{rating_key}.webp"
                            
                            # Check if the poster file exists
                            poster_path = os.path.join(lib_path, poster_filename)
                            if os.path.exists(poster_path):
                                # Add poster field to metadata
                                meta['poster'] = poster_filename
                                
                                # Save updated metadata
                                with open(json_path, 'w', encoding='utf-8') as f:
                                    json.dump(meta, f, indent=2)
                                
                                fixed_count += 1
                                print(f"Fixed metadata for: {meta.get('title', 'Unknown')} (ratingKey: {meta.get('ratingKey', 'Unknown')})")
                    
                    except Exception as e:
                        print(f"Error fixing metadata for {json_file}: {e}")
                        continue
            
            print(f"Metadata fix complete. Fixed {fixed_count} missing poster fields.")
            return fixed_count
            
        except Exception as e:
            print(f"Error in fix_missing_poster_fields: {e}")
            return 0