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
This module is responsible for loading and parsing external threat data files.
"""

import pandas as pd
import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Any, Optional

import xml.etree.ElementTree as ET



def load_capec_to_mitre_mapping() -> Dict[str, List[str]]:
    """Initializes CAPEC to MITRE ATT&CK mapping from the CSV file."""
    capec_to_mitre = {}
    xml_path = Path(__file__).parent.parent / 'external_data' / 'CAPEC_VIEW_ATT&CK_Related_Patterns.xml'
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()

        # Define the namespace
        namespace = {'capec': 'http://capec.mitre.org/capec-3'}

        for attack_pattern in root.findall('.//capec:Attack_Pattern', namespace):
            capec_id = attack_pattern.get('ID')
            if capec_id:
                mitre_ids = []
                for taxonomy_mapping in attack_pattern.findall('.//capec:Taxonomy_Mapping', namespace):
                    if taxonomy_mapping.get('Taxonomy_Name') == 'ATTACK':
                        entry_id = taxonomy_mapping.find('capec:Entry_ID', namespace)
                        if entry_id is not None and entry_id.text:
                            mitre_ids.append(f"T{entry_id.text}")
                if mitre_ids:
                    capec_to_mitre[capec_id] = sorted(list(set(mitre_ids)))
    except FileNotFoundError:
        logging.error(f"Error: CAPEC to MITRE mapping file not found at {xml_path}.")
    except Exception as e:
        logging.error(f"Error processing CAPEC to MITRE mapping file: {e}")
    return capec_to_mitre

def load_stride_to_capec_map() -> Dict[str, List[Dict[str, str]]]:
    """Loads the STRIDE to CAPEC mapping from the JSON file."""
    capec_mapping_path = Path(__file__).parent.parent / 'external_data' / 'stride_to_capec.json'
    try:
        with open(capec_mapping_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        logging.error(f"Error: stride_to_capec.json not found at {capec_mapping_path}.")
        return {}
    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON from {capec_mapping_path}.")
        return {}

def load_d3fend_mapping() -> Dict[str, Dict[str, str]]:
    """
    Initializes D3FEND mitigations by loading from d3fend.csv.
    
    Returns:
        Dict[str, Dict[str, str]]: Dictionary mapping D3FEND IDs to their details.
            Format: {
                "D3F-ID": {
                    "name": "D3FEND Technique Name",
                    "description": "Technique description"
                }
            }
    
    Raises:
        None: Errors are logged but not raised to ensure graceful degradation.
    """
    d3fend_details = {}
    csv_file_path = Path(__file__).parent.parent / 'external_data' / 'd3fend.csv'
    
    try:
        # File validation
        if not csv_file_path.exists():
            logging.warning(f"D3FEND CSV file not found at {csv_file_path}")
            return d3fend_details
        
        if csv_file_path.stat().st_size == 0:
            logging.warning(f"D3FEND CSV file is empty: {csv_file_path}")
            return d3fend_details
        
        # Loading with more specific error handling
        try:
            df = pd.read_csv(csv_file_path, encoding='utf-8')
        except UnicodeDecodeError:
            # Fallback for files with different encoding
            df = pd.read_csv(csv_file_path, encoding='latin-1')
            logging.info("Used latin-1 encoding for d3fend.csv")
        
        # Required columns validation
        required_columns = ['ID', 'D3FEND Technique', 'Definition']
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            logging.error(f"Missing required columns in d3fend.csv: {missing_columns}")
            return d3fend_details
        
        if df.empty:
            logging.warning("D3FEND CSV file contains no data rows")
            return d3fend_details
        
        # Data processing with validation
        for index, row in df.iterrows():
            try:
                d3fend_id = _clean_string(row['ID'])
                if not d3fend_id:
                    logging.warning(f"Empty or invalid ID at row {index + 1}, skipping")
                    continue
                
                d3fend_name = (_clean_string(row['D3FEND Technique']) 
                              if pd.notna(row['D3FEND Technique']) 
                              else d3fend_id)
                
                d3fend_description = (_clean_string(row['Definition']) 
                                    if pd.notna(row['Definition']) 
                                    else "")
                
                d3fend_details[d3fend_id] = {
                    "name": d3fend_name,
                    "description": d3fend_description
                }
                
            except Exception as row_error:
                logging.warning(f"Error processing row {index + 1}: {row_error}")
                continue
        
        logging.info(f"Successfully loaded {len(d3fend_details)} D3FEND techniques from {csv_file_path}")
        
    except pd.errors.EmptyDataError:
        logging.error(f"D3FEND CSV file is empty or corrupted: {csv_file_path}")
    except pd.errors.ParserError as e:
        logging.error(f"Error parsing D3FEND CSV file: {e}")
    except PermissionError:
        logging.error(f"Permission denied accessing D3FEND CSV file: {csv_file_path}")
    except Exception as e:
        logging.error(f"Unexpected error loading d3fend.csv: {e}")
    
    return d3fend_details


def _clean_string(value: Optional[str]) -> str:
    """
    Cleans and validates a string value.
    
    Args:
        value: Value to clean
        
    Returns:
        str: Cleaned string or empty string if invalid
    """
    if pd.isna(value) or value is None:
        return ""
    
    cleaned = str(value).strip()
    return cleaned if cleaned and cleaned.lower() not in ['nan', 'null', 'none'] else ""


# Alternative version with caching for performance optimization
import functools

@functools.lru_cache(maxsize=1)
def load_d3fend_mapping_cached() -> Dict[str, Dict[str, str]]:
    """
    Cached version of load_d3fend_mapping to avoid repeated file loading.
    Uses LRU cache with single entry for repeated calls.
    """
    return load_d3fend_mapping()


# Utility function to validate loaded mapping
def validate_d3fend_mapping(mapping: Dict[str, Dict[str, str]]) -> bool:
    """
    Validates the structure of the loaded D3FEND mapping.
    
    Args:
        mapping: D3FEND mapping dictionary to validate
        
    Returns:
        bool: True if mapping is valid, False otherwise
    """
    if not isinstance(mapping, dict):
        return False
    
    for d3fend_id, details in mapping.items():
        if not isinstance(d3fend_id, str) or not d3fend_id.strip():
            return False
        
        if not isinstance(details, dict):
            return False
        
        required_keys = ['name', 'description']
        if not all(key in details for key in required_keys):
            return False
        
        if not isinstance(details['name'], str):
            return False
    
    return True

