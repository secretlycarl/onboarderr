#!/usr/bin/env python3
"""
Test script to debug library titles issue
This script helps verify that library titles are being fetched correctly from Plex
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

def test_library_titles():
    """Test the library titles fetching functionality"""
    
    print("=== Library Titles Debug Test ===\n")
    
    # Check environment variables
    plex_token = os.getenv("PLEX_TOKEN")
    plex_url = os.getenv("PLEX_URL")
    library_ids = os.getenv("LIBRARY_IDS", "")
    
    print(f"PLEX_TOKEN: {'Set' if plex_token else 'Not set'}")
    print(f"PLEX_URL: {plex_url or 'Not set'}")
    print(f"LIBRARY_IDS: {library_ids or 'Not set'}")
    print()
    
    if not plex_token or not plex_url:
        print("❌ Plex token or URL not configured")
        return False
    
    # Test fetching libraries from Plex
    try:
        headers = {"X-Plex-Token": plex_token}
        url = f"{plex_url}/library/sections"
        print(f"Fetching libraries from: {url}")
        
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        root = ET.fromstring(response.text)
        libraries = []
        for directory in root.findall(".//Directory"):
            title = directory.attrib.get("title")
            key = directory.attrib.get("key")
            if title and key:
                libraries.append({"title": title, "key": key})
        
        print(f"✅ Successfully fetched {len(libraries)} libraries from Plex:")
        for lib in libraries:
            print(f"  - {lib['title']} (ID: {lib['key']})")
        print()
        
        # Check selected libraries
        if library_ids:
            selected_ids = [i.strip() for i in library_ids.split(",") if i.strip()]
            print(f"Selected library IDs: {selected_ids}")
            
            # Create mapping
            id_to_title = {lib["key"]: lib["title"] for lib in libraries}
            
            print("\nChecking selected libraries:")
            for lib_id in selected_ids:
                title = id_to_title.get(lib_id)
                if title:
                    print(f"  ✅ {title} (ID: {lib_id})")
                else:
                    print(f"  ❌ Unknown library (ID: {lib_id})")
            
            # Test the load_library_notes function
            print("\n=== Testing load_library_notes function ===")
            from app import load_library_notes
            
            notes = load_library_notes()
            print(f"Loaded {len(notes)} library notes")
            
            for lib_id in selected_ids:
                if lib_id in notes:
                    title = notes[lib_id].get('title', 'No title')
                    desc = notes[lib_id].get('description', 'No description')
                    print(f"  - {lib_id}: {title} - {desc}")
                else:
                    print(f"  - {lib_id}: Not in library_notes.json")
        
        return True
        
    except Exception as e:
        print(f"❌ Error fetching libraries: {e}")
        return False

if __name__ == "__main__":
    success = test_library_titles()
    sys.exit(0 if success else 1) 