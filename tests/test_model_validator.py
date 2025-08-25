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
Tests for the ModelValidator.
"""

import pytest
from threat_analysis.core.models_module import ThreatModel
from threat_analysis.core.model_validator import ModelValidator
from pytm import Actor, Server, Dataflow, Boundary

@pytest.fixture
def sample_threat_model():
    """Provides a sample ThreatModel for testing."""
    tm = ThreatModel("Test Model", "A model for testing validation")
    tm.add_actor("User", "Internet")
    tm.add_server("WebServer", "DMZ")
    return tm

def test_validator_with_valid_model(sample_threat_model):
    """Tests that a valid model passes validation."""
    # Add a valid dataflow
    user = sample_threat_model.get_element_by_name("User")
    webserver = sample_threat_model.get_element_by_name("WebServer")
    sample_threat_model.add_dataflow(user, webserver, "Valid Flow", "HTTPS")

    validator = ModelValidator(sample_threat_model)
    assert not validator.validate()
    assert not validator.errors

def test_validator_with_invalid_dataflow_source(sample_threat_model):
    """Tests that a dataflow with an undefined source fails validation."""
    # Create a fake source that is not in the model
    fake_source = Actor("Fake Actor")
    webserver = sample_threat_model.get_element_by_name("WebServer")
    
    # Manually create and add the invalid dataflow
    invalid_df = Dataflow(fake_source, webserver, "Invalid Source Flow")
    sample_threat_model.dataflows.append(invalid_df)

    validator = ModelValidator(sample_threat_model)
    assert validator.validate()
    assert len(validator.errors) == 1
    assert "Dataflow 'Invalid Source Flow' refers to a non-existent 'from' element: 'Fake Actor'." in validator.errors[0]

def test_validator_with_invalid_dataflow_sink(sample_threat_model):
    """Tests that a dataflow with an undefined sink fails validation."""
    user = sample_threat_model.get_element_by_name("User")
    # Create a fake sink that is not in the model
    fake_sink = Server("Fake Server")

    # Manually create and add the invalid dataflow
    invalid_df = Dataflow(user, fake_sink, "Invalid Sink Flow")
    sample_threat_model.dataflows.append(invalid_df)

    validator = ModelValidator(sample_threat_model)
    assert validator.validate()
    assert len(validator.errors) == 1
    assert "Dataflow 'Invalid Sink Flow' refers to a non-existent 'to' element: 'Fake Server'." in validator.errors[0]

def test_validator_with_dataflow_to_boundary(sample_threat_model):
    """Tests that a dataflow to a boundary fails validation."""
    user = sample_threat_model.get_element_by_name("User")
    # Get a boundary object
    boundary = Boundary("Internet")

    # Manually create and add the invalid dataflow
    invalid_df = Dataflow(user, boundary, "Invalid Boundary Flow")
    sample_threat_model.dataflows.append(invalid_df)

    validator = ModelValidator(sample_threat_model)
    errors = validator.validate()
    assert errors
    assert "Dataflow 'Invalid Boundary Flow' cannot terminate directly at a boundary. The destination must be an actor or a server." in errors

def test_validator_with_dataflow_from_boundary(sample_threat_model):
    """Tests that a dataflow originating from a boundary fails validation."""
    # Get a boundary object
    boundary = Boundary("Internet")
    webserver = sample_threat_model.get_element_by_name("WebServer")

    # Manually create and add the invalid dataflow
    invalid_df = Dataflow(boundary, webserver, "Invalid Boundary Source Flow")
    sample_threat_model.dataflows.append(invalid_df)

    validator = ModelValidator(sample_threat_model)
    errors = validator.validate()
    assert errors
    assert "Dataflow 'Invalid Boundary Source Flow' cannot originate directly from a boundary. The source must be an actor or a server." in errors
