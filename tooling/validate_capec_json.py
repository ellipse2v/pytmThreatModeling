#!/usr/bin/env python
# Copyright 2025 ellipse2v
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This script validates the descriptions in stride_to_capec.json against the official
MITRE CAPEC website.
"""

import json
import re
import time
from pathlib import Path
import requests

def get_capec_name_from_html(html_content: str, capec_id_num: str) -> str:
    """Extracts the CAPEC name from the HTML content."""
    # First, confirm the page is for the correct CAPEC ID
    id_anchor = f"Attack Pattern ID: {capec_id_num}"
    if id_anchor not in html_content:
        return ""

    # Find the name, which is usually in an H1 tag like <h1>CAPEC-123: Some Name</h1>
    # We will use a more flexible regex to avoid strict tag dependency.
    name_match = re.search(f'>CAPEC-{capec_id_num}:\s*([^<]+)<\/h1', html_content, re.IGNORECASE)
    if name_match:
        return name_match.group(1).strip()
    
    # Fallback to title tag which is also quite reliable
    title_match = re.search(r'<title>.*?CAPEC-\d+:\s*(.*?)\s*\(Version.*</title>', html_content, re.IGNORECASE | re.DOTALL)
    if title_match:
        return title_match.group(1).strip()

    return ""

def main():
    """Main function to validate the JSON file."""
    json_path = Path(__file__).resolve().parents[1] / "threat_analysis" / "external_data" / "stride_to_capec.json"
    base_url = "https://capec.mitre.org/data/definitions/{}.html"
    mismatches = []
    total_checked = 0

    print(f"Loading local data from {json_path}...")
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error: Could not load or parse {json_path}. {e}")
        return

    print("Starting validation against capec.mitre.org...")

    for stride_category, capec_list in data.items():
        for capec_entry in capec_list:
            capec_id_full = capec_entry['capec_id']
            local_description = capec_entry['description']
            capec_id_num = capec_id_full.split('-')[1]
            url = base_url.format(capec_id_num)
            total_checked += 1

            try:
                print(f"Checking {capec_id_full}...", end='', flush=True)
                response = requests.get(url, timeout=15)
                response.raise_for_status()

                online_name = get_capec_name_from_html(response.text, capec_id_num)

                if not online_name:
                    print(f" ❌ WARN: Could not parse name for {capec_id_full} at {url}")
                elif online_name.lower() != local_description.lower():
                    mismatches.append({
                        'capec_id': capec_id_full,
                        'local': local_description,
                        'online': online_name
                    })
                    print(f" ❌ MISMATCH")
                else:
                    print(" ✅ OK")

            except requests.exceptions.RequestException as e:
                print(f" ❌ ERROR: Could not fetch {url}. {e}")
            
            time.sleep(0.1)

    print("\n--- Validation Complete ---")
    print(f"Total CAPEC entries checked: {total_checked}")
    if not mismatches:
        print("✅ All entries match the online descriptions.")
    else:
        print(f"❌ Found {len(mismatches)} mismatches:")
        for item in mismatches:
            print(f"  - {item['capec_id']}:")
            print(f"    Local:  '{item['local']}'")
            print(f"    Online: '{item['online']}'")

if __name__ == "__main__":
    main()
