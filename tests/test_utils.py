
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
from pathlib import Path
from threat_analysis.utils import _validate_path_within_project

# Define project root for testing purposes
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_validate_path_within_project_valid():
    # Create a dummy file inside the project for testing
    dummy_file = PROJECT_ROOT / "dummy_file.txt"
    dummy_file.touch()

    validated_path = _validate_path_within_project(str(dummy_file), base_dir=PROJECT_ROOT)
    assert validated_path == dummy_file.resolve()

    # Clean up the dummy file
    dummy_file.unlink()


def test_validate_path_does_not_exist():
    non_existent_file = PROJECT_ROOT / "non_existent_file.txt"
    with pytest.raises(ValueError, match="Path does not exist"):
        _validate_path_within_project(str(non_existent_file), base_dir=PROJECT_ROOT)


def test_validate_path_outside_project():
    # Create a dummy file outside the project for testing
    outside_file = Path("/tmp/outside_file.txt")
    outside_file.touch()

    with pytest.raises(ValueError, match="Path is outside the allowed project directory"):
        _validate_path_within_project(str(outside_file), base_dir=PROJECT_ROOT)

    # Clean up the dummy file
    outside_file.unlink()
