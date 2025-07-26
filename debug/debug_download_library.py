import os
from dotenv import load_dotenv
import requests
import xml.etree.ElementTree as ET
import re
import json

load_dotenv(dotenv_path=".env")

PLEX_TOKEN = os.getenv("PLEX_TOKEN")
PLEX_URL = os.getenv("PLEX_URL")
SECTION_ID = "2"  # Library to test
POSTER_DIR = os.path.join("static", "posters", SECTION_ID)
os.makedirs(POSTER_DIR, exist_ok=True)

headers = {"X-Plex-Token": PLEX_TOKEN}
url = f"{PLEX_URL}/library/sections/{SECTION_ID}/all"
response = requests.get(url, headers=headers)
if response.status_code != 200:
    print(f"Failed to fetch from section {SECTION_ID}")
    exit(1)

root = ET.fromstring(response.content)
elements = root.findall(".//Directory" if SECTION_ID != os.getenv("MOVIES_SECTION_ID") else ".//Video")
posters = [el.attrib.get("thumb") for el in elements if el.attrib.get("thumb")]

for i, rel_path in enumerate(posters):
    img_url = f"{PLEX_URL}{rel_path}?X-Plex-Token={PLEX_TOKEN}"
    out_path = os.path.join(POSTER_DIR, f"poster{i+1}.webp")
    meta_path = os.path.join(POSTER_DIR, f"poster{i+1}.json")
    try:
        r = requests.get(img_url, headers=headers)
        with open(out_path, "wb") as f:
            f.write(r.content)
        # Save metadata
        el = elements[i] if i < len(elements) else None
        meta = {}
        if el is not None:
            meta["title"] = el.attrib.get("title", "")
            guid = el.attrib.get("guid", "")
            imdb_id = None
            if guid and "imdb" in guid:
                m = re.search(r'(tt\\d+)', guid)
                if m:
                    imdb_id = m.group(1)
            meta["imdb_id"] = imdb_id
        with open(meta_path, "w", encoding="utf-8") as mf:
            json.dump(meta, mf)
        print(f"Saved: {out_path} | Title: {meta.get('title')} | IMDB: {meta.get('imdb_id')}")
    except Exception as e:
        print(f"Error saving {img_url}: {e}") 