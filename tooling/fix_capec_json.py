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
This script corrects the descriptions in stride_to_capec.json based on the output
of the validation script.
"""

import json
from pathlib import Path

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

def main():
    """Main function to correct the JSON file."""
    json_path = Path(__file__).resolve().parents[1] / "threat_analysis" / "external_data" / "stride_to_capec.json"
    
    print(f"Loading local data from {json_path}...")
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error: Could not load or parse {json_path}. {e}")
        return

    print("Applying corrections...")
    correction_count = 0

    for stride_category, capec_list in data.items():
        for capec_entry in capec_list:
            capec_id = capec_entry['capec_id']
            if capec_id in CORRECTIONS:
                new_description = CORRECTIONS[capec_id]
                if capec_entry['description'] != new_description:
                    capec_entry['description'] = new_description
                    correction_count += 1
                    print(f"  Updated {capec_id}")

    print(f"Applied {correction_count} corrections.")

    print(f"Writing corrected data back to {json_path}...")
    try:
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        print("Successfully updated the file.")
    except IOError as e:
        print(f"Error writing to file: {e}")

if __name__ == "__main__":
    main()
