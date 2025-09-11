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
#!/usr/bin/env python3

import json
import os
import re
import pandas as pd

def _generate_cis_url(cis_id: str, cis_name: str) -> str:
    """
    Generates a specific URL for a given CIS control ID and name.
    Example: 2.5 -> https://cas.docs.cisecurity.org/en/latest/source/Controls2/#25-allowlist-authorized-software
    """
    try:
        major_num = cis_id.split('.')[0]
        anchor_id = cis_id.replace('.', '')
        
        # Slugify the name
        slug = cis_name.lower()
        slug = re.sub(r'[^a-z0-9\s-]', '', slug) # Remove non-alphanumeric characters
        slug = re.sub(r'[\s-]+', '-', slug).strip('-') # Replace spaces/hyphens with a single hyphen

        return f"https://cas.docs.cisecurity.org/en/latest/source/Controls{major_num}/#{anchor_id}-{slug}"
    except Exception:
        # Fallback to the generic URL if anything goes wrong
        return "https://www.cisecurity.org/controls/cis-controls-v8"

def parse_cis_to_mitre_mapping(input_path, output_path):
    """
    Parses the CIS Controls to MITRE ATT&CK mapping from an Excel file
    and converts it to a structured JSON file.
    """
    print(f"Reading Excel file from: {input_path}")
    try:
        df = pd.read_excel(input_path, sheet_name='V8-ATT&CK Low Mit. & (Sub-)Tech')
    except Exception as e:
        print(f"Error reading Excel file: {e}")
        return

    cis_id_col = 'CIS Safeguard'
    cis_name_col = 'Title'
    technique_id_col = 'Combined ATT&CK (Sub-)Technique ID'
    fallback_technique_id_col = 'ATT&CK Technique ID'
    
    mapping = {}

    print("Processing data...")
    for _, row in df.iterrows():
        cis_id = row[cis_id_col]
        cis_name = row[cis_name_col]
        
        # Prioritize combined technique ID, then fallback
        technique_id = row[technique_id_col]
        if pd.isna(technique_id):
            technique_id = row[fallback_technique_id_col]

        # Ensure all data is valid
        if pd.isna(cis_id) or pd.isna(technique_id) or pd.isna(cis_name):
            continue
            
        cis_id = str(cis_id).strip()
        cis_name = str(cis_name).strip()
        technique_id = str(technique_id).strip()

        if cis_id not in mapping:
            url = _generate_cis_url(cis_id, cis_name)
            mapping[cis_id] = {
                "name": cis_name,
                "url": url,
                "techniques": []
            }
        
        if technique_id not in mapping[cis_id]["techniques"]:
            mapping[cis_id]["techniques"].append(technique_id)

    print(f"Writing JSON output to: {output_path}")
    with open(output_path, 'w') as f:
        json.dump(mapping, f, indent=4)
    print("Conversion complete.")

if __name__ == "__main__":
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
    
    INPUT_FILE = "CIS_Controls_v8_to_Enterprise_ATTCK_v82_Master_Mapping__5262021.xlsx"
    OUTPUT_FILE = "cis_to_mitre_mapping.json"
    
    INPUT_PATH = os.path.join(
        PROJECT_ROOT, 'threat_analysis', 'external_data', INPUT_FILE
    )
    OUTPUT_PATH = os.path.join(
        PROJECT_ROOT, 'threat_analysis', 'external_data', OUTPUT_FILE
    )
    
    parse_cis_to_mitre_mapping(INPUT_PATH, OUTPUT_PATH)
