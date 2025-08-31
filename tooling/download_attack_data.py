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
This script downloads the latest MITRE ATT&CK enterprise data from the official STIX data repository.
"""

import requests
import os
from pathlib import Path


def main():
    """Main function to download the ATT&CK data."""
    # Original URL for enterprise-attack.json
    # url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    # output_file_name = "enterprise-attack.json"

    # URL for CAPEC CSV
    url = "https://capec.mitre.org/data/csv/2000.csv"
    output_file_name = "CAPEC_VIEW_ATT&CK_Related_Patterns.csv"
    
    # Calculate the project root and the target directory
    project_root = Path(__file__).resolve().parents[1]
    output_dir = project_root / "threat_analysis" / "external_data"
    output_file = output_dir / output_file_name

    print(f"Downloading data from {url}...")

    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)

        output_dir.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(response.text)
        
        print(f"Successfully downloaded and saved to {output_file}")

    except requests.exceptions.RequestException as e:
        print(f"Error downloading the file: {e}")
    except IOError as e:
        print(f"Error saving the file: {e}")

if __name__ == "__main__":
    main()