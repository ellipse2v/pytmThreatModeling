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

from threat_analysis.mitigation_suggestions import get_stix_mitigation_suggestions


def test_get_stix_mitigation_suggestions_empty():
    """Test get_stix_mitigation_suggestions with an empty list of technique IDs."""
    suggestions = get_stix_mitigation_suggestions([])
    assert suggestions == []


def test_get_stix_mitigation_suggestions_no_match():
    """Test get_stix_mitigation_suggestions with a technique ID that has no mapping."""
    suggestions = get_stix_mitigation_suggestions(["T9999"])
    assert suggestions == []
