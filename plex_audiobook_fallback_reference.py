# Plex Audiobook Fallback Reference
# This file contains the old Plex fallback logic that was removed from app.py
# It's kept for reference in case you want to implement a complete Plex fallback later

import os
import requests
import xml.etree.ElementTree as ET
import random

def plex_audiobook_fallback_logic(plex_token, plex_url, audiobooks_section_id, audiobook_dir):
    """
    OLD LOGIC: Plex fallback for audiobook posters when ABS is disabled
    This was incomplete and inconsistent with the frontend routes
    
    Args:
        plex_token: Plex API token
        plex_url: Plex server URL
        audiobooks_section_id: Plex library section ID for audiobooks
        audiobook_dir: Directory to save audiobook posters
    """
    headers = {'X-Plex-Token': plex_token}
    
    def save_images(section_id, out_dir, tag, limit):
        """Nested function that was extracted from download_and_cache_posters"""
        url = f"{plex_url}/library/sections/{section_id}/all"
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print(f"Failed to fetch from section {section_id}")
            return

        root = ET.fromstring(response.content)
        posters = []
        if section_id == audiobooks_section_id:
            # For audiobooks, fetch all authors, then fetch their children (audiobooks)
            for author in root.findall(".//Directory"):
                author_key = author.attrib.get("key")
                if author_key:
                    author_url = f"{plex_url}{author_key}?X-Plex-Token={plex_token}"
                    author_resp = requests.get(author_url, headers=headers)
                    if author_resp.status_code == 200:
                        author_root = ET.fromstring(author_resp.content)
                        # Each audiobook is a Directory (album/book)
                        for book in author_root.findall(".//Directory"):
                            thumb = book.attrib.get("thumb")
                            if thumb:
                                posters.append(thumb)
        else:
            # Movies: .//Video, Shows: .//Directory
            # (No longer used for movies or shows)
            pass
        random.shuffle(posters)

        for i, rel_path in enumerate(posters[:limit]):
            img_url = f"{plex_url}{rel_path}?X-Plex-Token={plex_token}"
            out_path = os.path.join(out_dir, f"{tag}{i+1}.webp")
            try:
                r = requests.get(img_url, headers=headers)
                with open(out_path, "wb") as f:
                    f.write(r.content)
            except Exception as e:
                print(f"Error saving {img_url}: {e}")

    # Execute the fallback logic
    save_images(audiobooks_section_id, audiobook_dir, "audiobook", 25)

# Usage example (for reference):
# if os.getenv("ABS_ENABLED", "yes") != "yes":
#     plex_audiobook_fallback_logic(plex_token, plex_url, AUDIOBOOKS_SECTION_ID, audiobook_dir) 