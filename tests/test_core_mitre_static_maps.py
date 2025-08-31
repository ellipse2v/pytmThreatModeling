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

from threat_analysis.core.mitre_static_maps import (
    ATTACK_D3FEND_MAPPING,
    STATIC_TECHNIQUE_MAPPING,
    THREAT_PATTERNS,
)


def test_attack_d3fend_mapping():
    """Test ATTACK_D3FEND_MAPPING."""
    assert isinstance(ATTACK_D3FEND_MAPPING, dict)
    assert "M1013 Application Developer Guidance" in ATTACK_D3FEND_MAPPING


def test_static_technique_mapping():
    """Test STATIC_TECHNIQUE_MAPPING."""
    assert isinstance(STATIC_TECHNIQUE_MAPPING, dict)
    assert "Spoofing" in STATIC_TECHNIQUE_MAPPING


def test_threat_patterns():
    """Test THREAT_PATTERNS."""
    assert isinstance(THREAT_PATTERNS, dict)
    assert "T1566" in THREAT_PATTERNS