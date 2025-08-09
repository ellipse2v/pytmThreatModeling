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

from threat_analysis.mitigation_suggestions import get_mitigation_suggestions


def test_get_mitigation_suggestions_empty():
    """Test get_mitigation_suggestions with an empty list of technique IDs."""
    suggestions = get_mitigation_suggestions([])
    assert suggestions == []


def test_get_mitigation_suggestions_no_match():
    """Test get_mitigation_suggestions with a technique ID that has no mapping."""
    suggestions = get_mitigation_suggestions(["T9999"])
    assert suggestions == []


def test_get_mitigation_suggestions_single_match():
    """Test get_mitigation_suggestions with a single matching technique ID."""
    suggestions = get_mitigation_suggestions(["T1190"])
    assert len(suggestions) == 3
    assert any("OWASP" in s["name"] for s in suggestions)
    assert any("NIST" in s["name"] for s in suggestions)
    assert any("CIS" in s["name"] for s in suggestions)


def test_get_mitigation_suggestions_multiple_matches():
    """Test get_mitigation_suggestions with multiple matching technique IDs."""
    suggestions = get_mitigation_suggestions(["T1190", "T1566"])
    assert len(suggestions) == 5  # 3 for T1190, 2 for T1566
    assert any("OWASP" in s["name"] for s in suggestions)
    assert any("NIST" in s["name"] for s in suggestions)
    assert any("CIS" in s["name"] for s in suggestions)
