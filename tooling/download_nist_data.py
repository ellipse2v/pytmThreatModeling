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
This script downloads the NIST 800-53 R5 mappings from the official repository.
"""

import requests
from pathlib import Path

NIST_EXCEL_URL = "https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings/raw/main/frameworks/attack_12_1/nist800_53_r5/nist800-53-r5-mappings.xlsx"
NIST_EXCEL_FILENAME = "nist800-53-r5-mappings.xlsx"
DATA_DIR = Path(__file__).parent.parent / 'threat_analysis' / 'external_data'

def download_nist_mappings():
    """Downloads the NIST 800-53 R5 mappings Excel file."""
    excel_path = DATA_DIR / NIST_EXCEL_FILENAME
    
    if not DATA_DIR.exists():
        DATA_DIR.mkdir(parents=True)

    try:
        print(f"Downloading NIST mappings from {NIST_EXCEL_URL}...")
        response = requests.get(NIST_EXCEL_URL, timeout=60)
        response.raise_for_status()
        with open(excel_path, 'wb') as f:
            f.write(response.content)
        print(f"✅ Successfully downloaded NIST mappings to {excel_path}")
    except requests.exceptions.RequestException as e:
        print(f"Error downloading NIST Excel file: {e}")

if __name__ == "__main__":
    download_nist_mappings()
