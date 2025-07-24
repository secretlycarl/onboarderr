#!/usr/bin/env python3
import requests
import os
import json
from dotenv import load_dotenv

load_dotenv()

abs_url = os.getenv("AUDIOBOOKSHELF_URL")
abs_token = os.getenv("AUDIOBOOKSHELF_TOKEN")

print(f"AUDIOBOOKSHELF_URL: {abs_url}")
print(f"AUDIOBOOKSHELF_TOKEN: {'set' if abs_token else 'not set'}")

headers = {}
if abs_token:
    headers["Authorization"] = f"Bearer {abs_token}"

books = {}

try:
    resp = requests.get(f"{abs_url}/api/libraries", headers=headers, timeout=10)
    print(f"/api/libraries status: {resp.status_code}")
    print("Raw response:", resp.text[:1000])
    data = resp.json()
    libraries = data.get("libraries", data)
    print(f"Found {len(libraries)} libraries")
    for lib in libraries:
        print("\nLibrary:", json.dumps(lib, indent=2))
        lib_id = lib.get("id")
        lib_type = lib.get("type")
        lib_media_type = lib.get("mediaType")
        print(f"  id: {lib_id}, type: {lib_type}, mediaType: {lib_media_type}")
        if lib_media_type == "book":
            print(f"  -> Attempting to fetch items for library {lib_id}")
            items_url = f"{abs_url}/api/libraries/{lib_id}/items"
            items_resp = requests.get(items_url, headers=headers, timeout=10)
            print(f"    /items status: {items_resp.status_code}")
            if items_resp.status_code == 200:
                items_data = items_resp.json()
                results = items_data.get("results", items_data)
                print(f"    Found {len(results)} items")
                for i, item in enumerate(results):
                    media = item.get("media", {})
                    title = media.get("metadata", {}).get("title") or item.get("title")
                    author = media.get("metadata", {}).get("authorName") or item.get("author")
                    print(f"    {i+1}. Title: {title} | Author: {author}")
                    if author and title:
                        if author not in books:
                            books[author] = []
                        books[author].append(title)
                    if i >= 9:
                        print("    ... (truncated)")
                        break
            else:
                print(f"    Error fetching items: {items_resp.text[:200]}")
except Exception as e:
    print("Error during ABS API test:", e)

print("\nSummary audiobooks dict (author: [titles]):")
print(json.dumps(books, indent=2, ensure_ascii=False)) 