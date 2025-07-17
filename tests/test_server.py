import pytest
import json
import os
from unittest.mock import patch, MagicMock, mock_open
import base64

# This is a bit tricky. We need to add the project root to the path
# BEFORE we import the app, so the app can find its own modules.
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Now we can import the app
from threat_analysis.server.server import app, run_gui, DEFAULT_EMPTY_MARKDOWN

@pytest.fixture
def client():
    """Create a test client for the Flask app."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_index_route(client):
    """Test the main route that serves the web interface."""
    response = client.get('/')
    assert response.status_code == 200
    assert b'Threat Model Editor' in response.data

def test_update_api_success(client):
    """Test the /api/update endpoint with valid markdown."""
    # We patch the dependencies of the API endpoint to avoid running the full logic
    with patch('threat_analysis.server.server.diagram_generator') as mock_diagram_gen:
        # Configure the mocks to return expected values
        mock_diagram_gen._generate_manual_dot.return_value = "digraph G {}"
        mock_diagram_gen.generate_diagram_from_dot.return_value = "/fake/path/to/live_preview.svg"
        mock_diagram_gen._generate_legend_html.return_value = "<div>Legend</div>"
        mock_diagram_gen._create_complete_html.return_value = "<html>Diagram</html>"

        # Mock the file system
        with patch('json.load', return_value={}): # Mock json.load to prevent pytm from trying to read files
             with patch('os.path.exists', return_value=True):
                with patch('builtins.open', mock_open(read_data="<svg>mocked svg</svg>")):
                    markdown_payload = {'markdown': """## Actors
- User"""}
                    response = client.post('/api/update', data=json.dumps(markdown_payload), content_type='application/json')

                assert response.status_code == 200
                json_data = response.get_json()
                assert 'diagram_html' in json_data
                assert json_data['diagram_html'] == "<html>Diagram</html>"

def test_update_api_empty_markdown(client):
    """Test the /api/update endpoint with empty markdown content."""
    markdown_payload = {'markdown': ''}
    response = client.post('/api/update', data=json.dumps(markdown_payload), content_type='application/json')
    assert response.status_code == 400
    json_data = response.get_json()
    assert 'error' in json_data
    assert json_data['error'] == 'Markdown content is empty'

import sys

@pytest.mark.parametrize("export_format", ["svg", "diagram", "report"])
def test_export_api_success(client, export_format):
    """Test the /api/export endpoint for all supported formats."""
    # Save original sys.argv and temporarily set it to avoid argparse conflicts with pytm
    original_argv = sys.argv
    sys.argv = [original_argv[0]] # Set to script name only

    try:
        # We need to patch all generators and file system interactions
        with patch('threat_analysis.server.server.diagram_generator'), \
             patch('threat_analysis.server.server.report_generator'), \
             patch('threat_analysis.server.server.send_from_directory') as mock_send, \
             patch('os.makedirs'):

            mock_send.return_value = MagicMock(status_code=200)
            markdown_payload = {'markdown': '## Actors\n- User', 'format': export_format}
            response = client.post('/api/export', data=json.dumps(markdown_payload), content_type='application/json')

            # The actual response is mocked by mock_send, but we can check if it was called
            assert response.status_code == 200
            mock_send.assert_called()
    finally:
        # Restore original sys.argv
        sys.argv = original_argv


def test_export_api_invalid_format(client):
    """Test the /api/export endpoint with an invalid format."""
    markdown_payload = {'markdown': '## Actors\n- User', 'format': 'invalid_format'}
    response = client.post('/api/export', data=json.dumps(markdown_payload), content_type='application/json')
    assert response.status_code == 400
    json_data = response.get_json()
    assert 'error' in json_data
    assert json_data['error'] == 'Invalid export format'

def test_export_api_missing_data(client):
    """Test the /api/export endpoint with missing markdown or format."""
    # Missing format
    payload_no_format = {'markdown': 'some content'}
    response = client.post('/api/export', data=json.dumps(payload_no_format), content_type='application/json')
    assert response.status_code == 400

    # Missing markdown
    payload_no_markdown = {'format': 'svg'}
    response = client.post('/api/export', data=json.dumps(payload_no_markdown), content_type='application/json')
    assert response.status_code == 400

def test_run_gui_with_no_model_file(client):
    """Test that run_gui starts with DEFAULT_EMPTY_MARKDOWN if no model file is provided."""
    with patch('os.path.exists', return_value=False): # Simulate file not found
        with patch('threat_analysis.server.server.app.run'): # Prevent Flask from actually running
            with patch('threat_analysis.server.server.render_template') as mock_render_template:
                run_gui(model_filepath=None)
                # After run_gui, the global initial_markdown_content should be set
                # We then make a request to the index route to get the rendered HTML
                client.get('/') # This will call the real index route, which calls render_template
                mock_render_template.assert_called_once_with('web_interface.html', initial_markdown=base64.b64encode(DEFAULT_EMPTY_MARKDOWN.encode('utf-8')).decode('utf-8'))

def test_run_gui_with_non_existent_model_file(client):
    """Test that run_gui starts with DEFAULT_EMPTY_MARKDOWN if a non-existent model file is provided."""
    with patch('os.path.exists', return_value=False): # Simulate file not found
        with patch('threat_analysis.server.server.app.run'): # Prevent Flask from actually running
            with patch('threat_analysis.server.server.render_template') as mock_render_template:
                run_gui(model_filepath='/non/existent/path/to/model.md')
                client.get('/') # This will call the real index route, which calls render_template
                mock_render_template.assert_called_once_with('web_interface.html', initial_markdown=base64.b64encode(DEFAULT_EMPTY_MARKDOWN.encode('utf-8')).decode('utf-8'))

def test_run_gui_with_existing_model_file(client):
    """Test that run_gui loads content from an existing model file."""
    mock_file_content = "# Threat Model: Test Model\n## Description\nA test model."
    with patch('os.path.exists', return_value=True):
        with patch('builtins.open', mock_open(read_data=mock_file_content)) as mock_file:
            with patch('threat_analysis.server.server.app.run'):
                with patch('threat_analysis.server.server.render_template') as mock_render_template:
                    run_gui(model_filepath='/path/to/existing/model.md')
                    client.get('/')
                    expected_encoded_markdown = base64.b64encode(mock_file_content.encode('utf-8')).decode('utf-8')
                    mock_render_template.assert_called_once_with('web_interface.html', initial_markdown=expected_encoded_markdown)
                    mock_file.assert_called_once_with('/path/to/existing/model.md', "r", encoding="utf-8")

def test_export_all_api_success(client):
    """Test the /api/export_all endpoint for successful ZIP file generation."""
    mock_markdown = "# Test Model"
    with patch('os.makedirs'), \
         patch('zipfile.ZipFile') as mock_zipfile, \
         patch('shutil.rmtree'), \
         patch('threat_analysis.server.server.send_file') as mock_send_file, \
         patch('threat_analysis.server.server.create_threat_model') as mock_create_threat_model, \
         patch('threat_analysis.server.server.diagram_generator') as mock_diagram_generator, \
         patch('threat_analysis.server.server.report_generator') as mock_report_generator, \
         patch('builtins.open', mock_open()):

        # Mock create_threat_model to return a mock threat_model object
        mock_threat_model = MagicMock()
        mock_threat_model.process_threats.return_value = {}
        mock_create_threat_model.return_value = mock_threat_model

        # Mock diagram_generator methods
        mock_diagram_generator._generate_manual_dot.return_value = "digraph G {}"
        mock_diagram_generator.generate_diagram_from_dot.return_value = "/fake/path/to/diagram.svg"
        mock_diagram_generator._generate_html_with_legend.return_value = None

        # Mock report_generator methods
        mock_report_generator.generate_html_report.return_value = None
        mock_report_generator.generate_json_analysis.return_value = None

        # Mock the BytesIO object that zipfile.ZipFile will use
        mock_zip_buffer = MagicMock()
        mock_zipfile.return_value.__enter__.return_value = MagicMock()

        # Mock send_file to return a dummy response
        mock_send_file.return_value = MagicMock(status_code=200, data=b'zip_content')

        markdown_payload = {'markdown': mock_markdown}
        response = client.post('/api/export_all', data=json.dumps(markdown_payload), content_type='application/json')

        assert response.status_code == 200
        mock_create_threat_model.assert_called_once()
        mock_diagram_generator._generate_manual_dot.assert_called_once()
        mock_diagram_generator.generate_diagram_from_dot.assert_called_once()
        mock_diagram_generator._generate_html_with_legend.assert_called_once()
        mock_threat_model.process_threats.assert_called_once()
        mock_report_generator.generate_html_report.assert_called_once()
        mock_report_generator.generate_json_analysis.assert_called_once()
        mock_zipfile.assert_called_once()
        mock_send_file.assert_called_once()

def test_export_all_api_missing_markdown(client):
    """Test the /api/export_all endpoint with missing markdown content."""
    response = client.post('/api/export_all', data=json.dumps({}), content_type='application/json')
    assert response.status_code == 400
    json_data = response.get_json()
    assert 'error' in json_data
    assert json_data['error'] == 'Missing markdown content'

def test_update_api_with_full_model_content(client):
    """Test the /api/update endpoint with a full threat model content (simulating paste)."""
    full_markdown_content = """
# Threat Model: Example System

## Description
A simple example system.

## Boundaries
- **Internet**: color=red

## Actors
- **External User**: boundary=Internet

## Servers
- **Web Server**: boundary=Internet

## Dataflows
- **Request**: from="External User", to="Web Server", protocol="HTTPS"
"""

