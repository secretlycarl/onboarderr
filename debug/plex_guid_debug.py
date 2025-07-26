import os
import requests
import xml.etree.ElementTree as ET
import json
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv(".env")

PLEX_TOKEN = os.getenv("PLEX_TOKEN")
PLEX_URL = os.getenv("PLEX_URL")
# Set your test library section ID here:
LIBRARY_SECTION_ID = "2"  # e.g., '1' or '2' or whatever your Plex section is
OUTPUT_DIR = "debug_posters"

os.makedirs(OUTPUT_DIR, exist_ok=True)

headers = {"X-Plex-Token": PLEX_TOKEN}


def fetch_library_items(section_id):
    url = f"{PLEX_URL}/library/sections/{section_id}/all"
    response = requests.get(url, headers=headers, timeout=10)
    response.raise_for_status()
    root = ET.fromstring(response.content)
    items = []
    for el in root.findall(".//Video"):
        items.append(el)
    for el in root.findall(".//Directory"):
        if el not in items:
            items.append(el)
    return items


def fetch_guids_and_poster(rating_key, thumb):
    meta_url = f"{PLEX_URL}/library/metadata/{rating_key}"
    response = requests.get(meta_url, headers=headers, timeout=10)
    response.raise_for_status()
    root = ET.fromstring(response.content)
    guids = {"imdb": None, "tmdb": None, "tvdb": None}
    for guid in root.findall(".//Guid"):
        gid = guid.attrib.get("id", "")
        if gid.startswith("imdb://"):
            guids["imdb"] = gid.replace("imdb://", "")
        elif gid.startswith("tmdb://"):
            guids["tmdb"] = gid.replace("tmdb://", "")
        elif gid.startswith("tvdb://"):
            guids["tvdb"] = gid.replace("tvdb://", "")
    # Download poster
    poster_path = None
    if thumb:
        poster_url = f"{PLEX_URL}{thumb}?X-Plex-Token={PLEX_TOKEN}"
        poster_path = os.path.join(OUTPUT_DIR, f"{rating_key}.webp")
        try:
            r = requests.get(poster_url, headers=headers, timeout=10)
            with open(poster_path, "wb") as f:
                f.write(r.content)
        except Exception as e:
            print(f"Error downloading poster for {rating_key}: {e}")
            poster_path = None
    return guids, poster_path


def main():
    if not PLEX_TOKEN or not PLEX_URL or not LIBRARY_SECTION_ID or LIBRARY_SECTION_ID == "REPLACE_WITH_SECTION_ID":
        print("Please set PLEX_TOKEN, PLEX_URL, and LIBRARY_SECTION_ID in the script (not .env) for testing.")
        return
    print(f"Fetching items from library section {LIBRARY_SECTION_ID}...")
    items = fetch_library_items(LIBRARY_SECTION_ID)
    print(f"Found {len(items)} items.")
    for idx, item in enumerate(items, 1):
        title = item.attrib.get("title", "(no title)")
        rating_key = item.attrib.get("ratingKey")
        thumb = item.attrib.get("thumb")
        print(f"[{idx}/{len(items)}] {title}")
        if not rating_key:
            print("  Skipping: No ratingKey.")
            continue
        guids, poster_path = fetch_guids_and_poster(rating_key, thumb)
        # Save metadata JSON
        meta = {
            "title": title,
            "ratingKey": rating_key,
            "imdb": guids["imdb"],
            "tmdb": guids["tmdb"],
            "tvdb": guids["tvdb"],
            "poster": os.path.basename(poster_path) if poster_path else None
        }
        json_path = os.path.join(OUTPUT_DIR, f"{rating_key}.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
        print(f"  Saved poster: {poster_path}")
        print(f"  Saved metadata: {json_path}")

if __name__ == "__main__":
    main() 