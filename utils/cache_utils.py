"""
Cache utilities for Onboarderr application.

This module provides caching functionality for API responses, library data,
and other frequently accessed data to improve performance.
"""

import time
import json
import os
from typing import Any, Optional, Dict, List
from threading import Lock
from datetime import datetime, timedelta
from utils.logging_utils import log_debug, log_warning, log_error


class Cache:
    """
    Simple in-memory cache with TTL support.
    """
    
    def __init__(self, default_ttl: int = 3600):
        """
        Initialize cache.
        
        Args:
            default_ttl: Default time-to-live in seconds
        """
        self._cache = {}
        self._timestamps = {}
        self._default_ttl = default_ttl
        self._lock = Lock()
    
    def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if not found/expired
        """
        with self._lock:
            if key not in self._cache:
                return None
            
            # Check if expired
            if self._is_expired(key):
                self._remove(key)
                return None
            
            return self._cache[key]
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """
        Set value in cache.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time-to-live in seconds (uses default if None)
        """
        with self._lock:
            self._cache[key] = value
            self._timestamps[key] = time.time()
            if ttl is not None:
                self._cache[f"{key}_ttl"] = ttl
    
    def delete(self, key: str) -> bool:
        """
        Delete value from cache.
        
        Args:
            key: Cache key
            
        Returns:
            True if key was found and deleted, False otherwise
        """
        with self._lock:
            return self._remove(key)
    
    def clear(self) -> None:
        """
        Clear all cached data.
        """
        with self._lock:
            self._cache.clear()
            self._timestamps.clear()
    
    def cleanup_expired(self) -> int:
        """
        Remove expired entries from cache.
        
        Returns:
            Number of entries removed
        """
        with self._lock:
            expired_keys = [key for key in list(self._cache.keys()) 
                          if not key.endswith('_ttl') and self._is_expired(key)]
            
            for key in expired_keys:
                self._remove(key)
            
            return len(expired_keys)
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with cache statistics
        """
        with self._lock:
            total_entries = len([k for k in self._cache.keys() if not k.endswith('_ttl')])
            expired_entries = len([k for k in self._cache.keys() 
                                 if not k.endswith('_ttl') and self._is_expired(k)])
            
            return {
                "total_entries": total_entries,
                "expired_entries": expired_entries,
                "valid_entries": total_entries - expired_entries,
                "default_ttl": self._default_ttl
            }
    
    def _is_expired(self, key: str) -> bool:
        """
        Check if cache entry is expired.
        
        Args:
            key: Cache key
            
        Returns:
            True if expired, False otherwise
        """
        if key not in self._timestamps:
            return True
        
        ttl = self._cache.get(f"{key}_ttl", self._default_ttl)
        return time.time() - self._timestamps[key] > ttl
    
    def _remove(self, key: str) -> bool:
        """
        Remove key from cache.
        
        Args:
            key: Cache key
            
        Returns:
            True if key was found and removed, False otherwise
        """
        if key in self._cache:
            del self._cache[key]
            if key in self._timestamps:
                del self._timestamps[key]
            if f"{key}_ttl" in self._cache:
                del self._cache[f"{key}_ttl"]
            return True
        return False


# Global cache instances
library_cache = Cache(default_ttl=43200)  # 12 hours
api_cache = Cache(default_ttl=3600)       # 1 hour
session_cache = Cache(default_ttl=1800)   # 30 minutes


def cache_library_data(library_id: str, data: Any, ttl: Optional[int] = None) -> None:
    """
    Cache library data.
    
    Args:
        library_id: Library identifier
        data: Library data to cache
        ttl: Time-to-live in seconds
    """
    key = f"library_{library_id}"
    library_cache.set(key, data, ttl)
    log_debug("cache", f"Cached library data for {library_id}")


def get_cached_library_data(library_id: str) -> Optional[Any]:
    """
    Get cached library data.
    
    Args:
        library_id: Library identifier
        
    Returns:
        Cached library data or None if not found/expired
    """
    key = f"library_{library_id}"
    data = library_cache.get(key)
    if data:
        log_debug("cache", f"Cache hit for library {library_id}")
    return data


def cache_api_response(api_type: str, endpoint: str, params: Dict[str, Any], 
                      response: Any, ttl: Optional[int] = None) -> None:
    """
    Cache API response.
    
    Args:
        api_type: Type of API (PLEX, ABS, etc.)
        endpoint: API endpoint
        params: Request parameters
        response: API response to cache
        ttl: Time-to-live in seconds
    """
    # Create cache key from API type, endpoint, and parameters
    param_str = json.dumps(params, sort_keys=True) if params else ""
    key = f"api_{api_type}_{endpoint}_{hash(param_str)}"
    api_cache.set(key, response, ttl)
    log_debug("cache", f"Cached API response for {api_type} {endpoint}")


def get_cached_api_response(api_type: str, endpoint: str, params: Dict[str, Any]) -> Optional[Any]:
    """
    Get cached API response.
    
    Args:
        api_type: Type of API (PLEX, ABS, etc.)
        endpoint: API endpoint
        params: Request parameters
        
    Returns:
        Cached API response or None if not found/expired
    """
    param_str = json.dumps(params, sort_keys=True) if params else ""
    key = f"api_{api_type}_{endpoint}_{hash(param_str)}"
    response = api_cache.get(key)
    if response:
        log_debug("cache", f"Cache hit for API {api_type} {endpoint}")
    return response


def cache_session_data(session_id: str, data: Any, ttl: Optional[int] = None) -> None:
    """
    Cache session data.
    
    Args:
        session_id: Session identifier
        data: Session data to cache
        ttl: Time-to-live in seconds
    """
    key = f"session_{session_id}"
    session_cache.set(key, data, ttl)
    log_debug("cache", f"Cached session data for {session_id}")


def get_cached_session_data(session_id: str) -> Optional[Any]:
    """
    Get cached session data.
    
    Args:
        session_id: Session identifier
        
    Returns:
        Cached session data or None if not found/expired
    """
    key = f"session_{session_id}"
    data = session_cache.get(key)
    if data:
        log_debug("cache", f"Cache hit for session {session_id}")
    return data


def clear_library_cache() -> None:
    """
    Clear all library cache data.
    """
    library_cache.clear()
    log_debug("cache", "Cleared library cache")


def clear_api_cache() -> None:
    """
    Clear all API cache data.
    """
    api_cache.clear()
    log_debug("cache", "Cleared API cache")


def clear_session_cache() -> None:
    """
    Clear all session cache data.
    """
    session_cache.clear()
    log_debug("cache", "Cleared session cache")


def clear_all_caches() -> None:
    """
    Clear all cache data.
    """
    library_cache.clear()
    api_cache.clear()
    session_cache.clear()
    log_debug("cache", "Cleared all caches")


def cleanup_expired_cache_entries() -> Dict[str, int]:
    """
    Clean up expired entries from all caches.
    
    Returns:
        Dictionary with number of entries removed from each cache
    """
    library_removed = library_cache.cleanup_expired()
    api_removed = api_cache.cleanup_expired()
    session_removed = session_cache.cleanup_expired()
    
    total_removed = library_removed + api_removed + session_removed
    if total_removed > 0:
        log_debug("cache", f"Cleaned up {total_removed} expired cache entries")
    
    return {
        "library": library_removed,
        "api": api_removed,
        "session": session_removed,
        "total": total_removed
    }


def get_cache_stats() -> Dict[str, Dict[str, Any]]:
    """
    Get statistics for all caches.
    
    Returns:
        Dictionary with statistics for each cache
    """
    return {
        "library": library_cache.get_stats(),
        "api": api_cache.get_stats(),
        "session": session_cache.get_stats()
    }


def cache_file_data(file_path: str, data: Any, ttl: Optional[int] = None) -> None:
    """
    Cache file-based data with file modification time checking.
    
    Args:
        file_path: Path to the file
        data: Data to cache
        ttl: Time-to-live in seconds
    """
    try:
        # Get file modification time
        mtime = os.path.getmtime(file_path)
        cache_key = f"file_{file_path}_{mtime}"
        
        # Cache with file modification time in key
        library_cache.set(cache_key, data, ttl)
        log_debug("cache", f"Cached file data for {file_path}")
    except OSError as e:
        log_warning("cache", f"Could not get modification time for {file_path}: {e}")


def get_cached_file_data(file_path: str) -> Optional[Any]:
    """
    Get cached file data, checking if file has been modified.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Cached file data or None if not found/expired/modified
    """
    try:
        # Get current file modification time
        mtime = os.path.getmtime(file_path)
        cache_key = f"file_{file_path}_{mtime}"
        
        data = library_cache.get(cache_key)
        if data:
            log_debug("cache", f"Cache hit for file {file_path}")
        return data
    except OSError as e:
        log_warning("cache", f"Could not get modification time for {file_path}: {e}")
        return None


def cache_with_condition(key: str, data: Any, condition: bool, ttl: Optional[int] = None) -> None:
    """
    Cache data only if condition is met.
    
    Args:
        key: Cache key
        data: Data to cache
        condition: Condition that must be True to cache
        ttl: Time-to-live in seconds
    """
    if condition:
        library_cache.set(key, data, ttl)
        log_debug("cache", f"Cached data for {key} (condition met)")
    else:
        log_debug("cache", f"Skipped caching for {key} (condition not met)")


def get_cache_memory_usage() -> Dict[str, int]:
    """
    Estimate memory usage of caches.
    
    Returns:
        Dictionary with estimated memory usage for each cache
    """
    def estimate_size(obj):
        """Rough estimate of object size in bytes."""
        try:
            return len(json.dumps(obj))
        except (TypeError, ValueError):
            return 0
    
    library_size = sum(estimate_size(v) for v in library_cache._cache.values())
    api_size = sum(estimate_size(v) for v in api_cache._cache.values())
    session_size = sum(estimate_size(v) for v in session_cache._cache.values())
    
    return {
        "library": library_size,
        "api": api_size,
        "session": session_size,
        "total": library_size + api_size + session_size
    } 