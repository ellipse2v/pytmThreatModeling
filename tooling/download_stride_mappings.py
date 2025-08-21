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

def get_stride_category_from_url(url):
    # Extract the last part of the URL, remove .md, replace dashes, and title case it.
    name = url.split('/')[-1].replace('.md', '').replace('-', ' ').title()
    if name == "Information Disclosure":
        return "Information Disclosure"
    elif name == "Denial Of Service":
        return "Denial of Service"
    elif name == "Elevation Of Privilege":
        return "Elevation of Privilege"
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
    capec_pattern = re.compile(r'\[(CAPEC-\d+):\s*([^\]]+)\]')

    for url in urls:
        try:
            response = requests.get(url)
            response.raise_for_status()
            content = response.text
            stride_category = get_stride_category_from_url(url)
            
            matches = capec_pattern.findall(content)
            
            # Remove duplicates by converting to a set of tuples
            unique_matches = sorted(list(set(matches)))
            
            for capec_id, description in unique_matches:
                stride_to_capec[stride_category].append({
                    "capec_id": capec_id,
                    "description": description.strip()
                })
        except requests.exceptions.RequestException as e:
            print(f"Error downloading {url}: {e}")

    


    # The script assumes it is run from the root of the project directory.
    output_file = 'threat_analysis/external_data/stride_to_capec.json'
    with open(output_file, 'w') as f:
        json.dump(stride_to_capec, f, indent=4, sort_keys=True)

    print(f"Successfully updated {output_file}")

if __name__ == "__main__":
    main()