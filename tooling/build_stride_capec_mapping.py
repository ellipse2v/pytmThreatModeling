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

import json
import re
import requests
from collections import defaultdict

# This dictionary contains manual corrections for descriptions that are often scraped incorrectly.
CORRECTIONS = {
    "CAPEC-16": "Dictionary-based Password Attack",
    "CAPEC-18": "XSS Targeting Non-Script Elements",
    "CAPEC-32": "XSS Through HTTP Query Strings",
    "CAPEC-35": "Leverage Executable Code in Non-Executable Files",
    "CAPEC-36": "Using Unpublished Interfaces or Functionality",
    "CAPEC-549": "Local Execution of Code",
    "CAPEC-564": "Run Software at Logon",
    "CAPEC-629": "DEPRECATED: Unauthorized Use of Device Resources",
    "CAPEC-653": "Use of Known Operating System Credentials",
    "CAPEC-143": "Detect Unpublicized Web Pages",
    "CAPEC-144": "Detect Unpublicized Web Services",
    "CAPEC-217": "Exploiting Incorrectly Configured SSL/TLS",
    "CAPEC-290": "Enumerate Mail Exchange (MX) Records",
    "CAPEC-37": "Retrieve Embedded Sensitive Data",
    "CAPEC-57": "Utilizing REST's Trust in the System Resource to Obtain Sensitive Data",
    "CAPEC-81": "Web Server Logs Tampering",
    "CAPEC-443": "Malicious Logic Inserted Into Product by Authorized Developer",
    "CAPEC-446": "Malicious Logic Insertion into Product via Inclusion of Third-Party Component",
    "CAPEC-481": "Contradictory Destinations in Traffic Routing Schemes",
    "CAPEC-536": "Data Injected During Configuration",
    "CAPEC-548": "Contaminate Resource",
    "CAPEC-663": "Exploitation of Transient Instruction Execution",
    "CAPEC-677": "Server Motherboard Compromise",
    "CAPEC-73": "User-Controlled Filename",
}

# This dictionary adds high-quality mappings that might be missing from the scraped data.
SUPPLEMENTAL_MAPPINGS = {
    "Elevation of Privilege": [
        {"capec_id": "CAPEC-122", "description": "Privilege Abuse"},
        {"capec_id": "CAPEC-233", "description": "Privilege Escalation"},
        {"capec_id": "CAPEC-644", "description": "Use of Captured Hashes (Pass The Hash)"},
        {"capec_id": "CAPEC-645", "description": "Use of Captured Tickets (Pass The Ticket)"},
        {"capec_id": "CAPEC-509", "description": "Kerberoasting"}
    ],
    "Information Disclosure": [
        {"capec_id": "CAPEC-116", "description": "Excavation"},
        {"capec_id": "CAPEC-157", "description": "Sniffing Attacks"},
        {"capec_id": "CAPEC-545", "description": "Pull Data From System Resources"},
        {"capec_id": "CAPEC-169", "description": "Footprinting"}
    ]
}

def get_stride_category_from_url(url):
    name = url.split('/')[-1].replace('.md', '').replace('-', ' ').title()
    if name == "Information Disclosure": return "Information Disclosure"
    if name == "Denial Of Service": return "Denial of Service"
    if name == "Elevation Of Privilege": return "Elevation of Privilege"
    return name

def main():
    urls = [
        "https://www.ostering.com/media/files/docs/tampering.md",
        "https://www.ostering.com/media/files/docs/repudiation.md",
        "https://www.ostering.com/media/files/docs/information-disclosure.md",
        "https://www.ostering.com/media/files/docs/denial-of-service.md",
        "https://www.ostering.com/media/files/docs/elevation-of-privilege.md",
        "https://www.ostering.com/media/files/docs/spoofing.md"
    ]

    stride_to_capec = defaultdict(list)
    capec_pattern = re.compile(r'\[(CAPEC-\d+):\s*([^\\\]]+)\]')

    print("Step 1: Scraping initial data from ostering.com...")
    for url in urls:
        try:
            response = requests.get(url)
            response.raise_for_status()
            content = response.text
            stride_category = get_stride_category_from_url(url)
            matches = capec_pattern.findall(content)
            unique_matches = sorted(list(set(matches)))
            for capec_id, description in unique_matches:
                stride_to_capec[stride_category].append({
                    "capec_id": capec_id,
                    "description": description.strip(),
                    "source": "scraped"
                })
        except requests.exceptions.RequestException as e:
            print(f"  Error downloading {url}: {e}")
    print("Scraping complete.")

    print("\nStep 2: Applying manual corrections...")
    for _, capec_list in stride_to_capec.items():
        for capec_entry in capec_list:
            if capec_entry['capec_id'] in CORRECTIONS:
                capec_entry['description'] = CORRECTIONS[capec_entry['capec_id']]
    print("Corrections applied.")

    print("\nStep 3: Adding supplemental mappings...")
    for category, mappings in SUPPLEMENTAL_MAPPINGS.items():
        existing_ids = {m['capec_id'] for m in stride_to_capec[category]}
        for new_mapping in mappings:
            if new_mapping['capec_id'] not in existing_ids:
                new_mapping['source'] = 'manual'
                stride_to_capec[category].append(new_mapping)
    print("Supplemental mappings added.")

    output_file = 'threat_analysis/external_data/stride_to_capec.json'
    print(f"\nStep 4: Writing final corrected and enriched data to {output_file}...")
    with open(output_file, 'w') as f:
        json.dump(stride_to_capec, f, indent=4, sort_keys=True)

    print(f"\nSuccessfully created {output_file}")

if __name__ == "__main__":
    main()
