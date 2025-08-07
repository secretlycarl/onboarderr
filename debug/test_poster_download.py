#!/usr/bin/env python3
"""
Test script to debug poster downloading issue
This script helps verify that poster downloading works correctly after setup
"""

import os
import sys
import json
import requests
import xml.etree.ElementTree as ET
from dotenv import load_dotenv

# Add the parent directory to the path so we can import from app.py
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load environment variables
load_dotenv()

def test_poster_download():
    """Test the poster downloading functionality"""
    
    print("=== Poster Download Debug Test ===\n")
    
    # Check environment variables
    plex_token = os.getenv("PLEX_TOKEN")
    plex_url = os.getenv("PLEX_URL")
    library_ids = os.getenv("LIBRARY_IDS", "")
    setup_complete = os.getenv("SETUP_COMPLETE", "0")
    
    print(f"SETUP_COMPLETE: {setup_complete}")
    print(f"PLEX_TOKEN: {'Set' if plex_token else 'Not set'}")
    print(f"PLEX_URL: {plex_url or 'Not set'}")
    print(f"LIBRARY_IDS: {library_ids or 'Not set'}")
    print()
    
    if not plex_token or not plex_url:
        print("❌ Plex token or URL not configured")
        return False
    
    if setup_complete != "1":
        print("❌ Setup not complete")
        return False
    
    if not library_ids:
        print("❌ No library IDs configured")
        return False
    
    # Test fetching libraries
    try:
        from app import get_plex_libraries
        libraries = get_plex_libraries()
        
        if not libraries:
            print("❌ No libraries found")
            return False
        
        print(f"✅ Found {len(libraries)} libraries:")
        for lib in libraries:
            print(f"  - {lib['title']} (ID: {lib['key']}, Type: {lib.get('media_type', 'unknown')}")
        print()
        
        # Test poster downloading for first library
        selected_ids = [i.strip() for i in library_ids.split(",") if i.strip()]
        test_library = None
        
        for lib in libraries:
            if lib["key"] in selected_ids:
                test_library = lib
                break
        
        if not test_library:
            print("❌ No selected libraries found")
            return False
        
        print(f"Testing poster download for library: {test_library['title']}")
        
        # Test the poster downloading function
        from app import download_and_cache_posters_for_libraries
        
        # Test with a small limit to avoid downloading too many posters
        result = download_and_cache_posters_for_libraries([test_library], limit=3, background=False)
        
        if result > 0:
            print(f"✅ Successfully downloaded {result} posters")
            
            # Check if poster directory was created
            poster_dir = os.path.join("static", "posters", test_library["key"])
            if os.path.exists(poster_dir):
                poster_files = [f for f in os.listdir(poster_dir) if f.endswith('.webp')]
                json_files = [f for f in os.listdir(poster_dir) if f.endswith('.json')]
                print(f"✅ Poster directory created: {poster_dir}")
                print(f"  - Poster files: {len(poster_files)}")
                print(f"  - Metadata files: {len(json_files)}")
                
                # Show some metadata
                if json_files:
                    with open(os.path.join(poster_dir, json_files[0]), 'r') as f:
                        metadata = json.load(f)
                    print(f"  - Sample metadata: {metadata.get('title', 'Unknown')}")
            else:
                print("❌ Poster directory not created")
                return False
        else:
            print("❌ No posters downloaded")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_poster_download()
    sys.exit(0 if success else 1) 