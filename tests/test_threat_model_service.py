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

import pytest
import os
from unittest.mock import patch, MagicMock, mock_open
from io import BytesIO
import datetime

from threat_analysis.server.threat_model_service import ThreatModelService
from threat_analysis import config

@pytest.fixture
def service():
    return ThreatModelService()

def test_export_files_logic_invalid_format(service):
    """Test export_files_logic with an invalid format."""
    mock_markdown = "# Test Model"
    with pytest.raises(ValueError, match="Invalid export format"):\
        service.export_files_logic(mock_markdown, "invalid_format")

def test_export_files_logic_missing_data(service):
    """Test export_files_logic with missing markdown or format."""
    with pytest.raises(ValueError, match="Missing markdown content or export format"):\
        service.export_files_logic("", "svg")
    with pytest.raises(ValueError, match="Missing markdown content or export format"):\
        service.export_files_logic("# Test", "")

def test_export_all_files_logic_missing_markdown(service):
    """Test export_all_files_logic with missing markdown content."""
    with pytest.raises(ValueError, match="Missing markdown content"):\
        service.export_all_files_logic("")