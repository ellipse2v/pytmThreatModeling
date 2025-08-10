import unittest
import tempfile
import shutil
import logging
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

from threat_analysis.generation.report_generator import ReportGenerator
from threat_analysis.severity_calculator_module import SeverityCalculator
from threat_analysis.core.mitre_mapping_module import MitreMapping
from threat_analysis.generation.diagram_generator import DiagramGenerator

class TestProjectGeneration(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.project_path = Path(self.test_dir) / "test_project"
        self.output_path = Path(self.test_dir) / "output"
        self.project_path.mkdir()
        self.output_path.mkdir()
        logging.basicConfig(level=logging.INFO, stream=sys.stdout)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _run_generator(self):
        severity_calculator = SeverityCalculator()
        mitre_mapping = MitreMapping()
        report_generator = ReportGenerator(severity_calculator, mitre_mapping)
        report_generator.generate_project_reports(self.project_path, self.output_path)

    @patch('threat_analysis.generation.diagram_generator.DiagramGenerator.add_links_to_svg')
    @patch('threat_analysis.generation.diagram_generator.DiagramGenerator.generate_diagram_from_dot')
    def test_single_level_project(self, mock_generate_diagram, mock_add_links):
        # Arrange
        def create_mock_svg(dot_code, output_file, format):
            svg_path = Path(output_file)
            with open(svg_path, "w") as f:
                f.write("<svg></svg>")
            return str(svg_path)
        mock_generate_diagram.side_effect = create_mock_svg
        mock_add_links.return_value = """
<svg>
<g id="WebApp" class="node">
<title>WebApp</title>
<a xlink:href="sub_A/model_diagram.html">
<ellipse fill="none" stroke="black" cx="49" cy="-18" rx="49" ry="18"/>
<text text-anchor="middle" x="49" y="-14.3" font-family="Times,serif" font-size="14.00">WebApp</text>
</a>
</g>
</svg>
"""
        sub_project_path = self.project_path / "sub_A"
        sub_project_path.mkdir(parents=True)
        with open(self.project_path / "main.md", "w") as f:
            f.write("## Servers\n- **WebApp**: submodel=./sub_A/model.md")
        with open(sub_project_path / "model.md", "w") as f:
            f.write("## Servers\n- **WebServer**:")

        # Act
        self._run_generator()

        # Assert
        main_html = self.output_path / "main_diagram.html"
        sub_html = self.output_path / "sub_A" / "model_diagram.html"

        # The paths in the new implementation are different
        main_html_new = self.output_path / "main_diagram.html"
        sub_html_new = self.output_path / "sub_A" / "model_diagram.html"

        self.assertTrue(main_html_new.exists())
        self.assertTrue(sub_html_new.exists())

        main_content = main_html_new.read_text()
        self.assertIn('xlink:href="sub_A/model_diagram.html"', main_content)

        sub_content = sub_html_new.read_text()
        self.assertIn('href="../main_diagram.html"', sub_content)
        self.assertIn('<a href="../main_diagram.html">test_project</a>', sub_content)
        self.assertIn('<a href="model_diagram.html">sub_A</a>', sub_content)

    @patch('threat_analysis.generation.diagram_generator.DiagramGenerator.add_links_to_svg')
    @patch('threat_analysis.generation.diagram_generator.DiagramGenerator.generate_diagram_from_dot')
    def test_nested_project_and_dataflows(self, mock_generate_diagram, mock_add_links):
        # Arrange
        def create_mock_svg(dot_code, output_file, format):
            svg_path = Path(output_file)
            with open(svg_path, "w") as f:
                f.write("<svg></svg>")
            return str(svg_path)
        mock_generate_diagram.side_effect = create_mock_svg
        mock_add_links.return_value = """
<svg>
<g id="ProductDB" class="node">
<title>ProductDB</title>
<a xlink:href="database/model_diagram.html">
<ellipse fill="none" stroke="black" cx="49" cy="-90" rx="49" ry="18"/>
<text text-anchor="middle" x="49" y="-86.3" font-family="Times,serif" font-size="14.00">ProductDB</text>
</a>
</g>
</svg>
"""
        frontend_path = self.project_path / "frontend"
        backend_path = self.project_path / "backend"
        db_path = backend_path / "database"
        db_path.mkdir(parents=True)
        frontend_path.mkdir()

        with open(self.project_path / "main.md", "w") as f:
            f.write("""
## Servers
- **WebApp**: submodel=./frontend/model.md
- **Backend**: submodel=./backend/model.md
## Dataflows
- **WebToBackend**: from=WebApp, to=Backend, protocol=TCP
            """)
        with open(frontend_path / "model.md", "w") as f:
            f.write("## Servers\n- **WebServer**:")
        with open(backend_path / "model.md", "w") as f:
            f.write("## Servers\n- **APIGateway**:\n- **ProductDB**: submodel=./database/model.md")
        with open(db_path / "model.md", "w") as f:
            f.write("## Servers\n- **PrimaryDB**:")

        # Act
        self._run_generator()

        # Assert
        backend_html = self.output_path / "backend" / "model_diagram.html"
        db_html = self.output_path / "backend" / "database" / "model_diagram.html"
        self.assertTrue(backend_html.exists())
        self.assertTrue(db_html.exists())

        backend_content = backend_html.read_text()
        self.assertIn('xlink:href="database/model_diagram.html"', backend_content)

        db_content = db_html.read_text()
        self.assertIn('href="../model_diagram.html"', db_content)
        self.assertIn('<a href="../../main_diagram.html">test_project</a>', db_content)
        self.assertIn('<a href="../model_diagram.html">backend</a>', db_content)
        self.assertIn('<a href="model_diagram.html">database</a>', db_content)

    @patch('threat_analysis.generation.diagram_generator.DiagramGenerator.add_links_to_svg')
    @patch('threat_analysis.generation.diagram_generator.DiagramGenerator.generate_diagram_from_dot')
    def test_project_with_protocol_styles(self, mock_generate_diagram, mock_add_links):
        # Arrange
        def create_mock_svg(dot_code, output_file, format):
            svg_path = Path(output_file)
            with open(svg_path, "w") as f:
                f.write("<svg></svg>")
            return str(svg_path)
        mock_generate_diagram.side_effect = create_mock_svg
        mock_add_links.return_value = "<svg></svg>"
        with open(self.project_path / "main.md", "w") as f:
            f.write("""
## Servers
- **ServerA**:
- **ServerB**:
## Dataflows
- **AToB**: from=ServerA, to=ServerB, protocol=HTTP
## Protocol Styles
- **HTTP**: color=red
            """)

        # Act
        self._run_generator()

        # Assert
        main_html = self.output_path / "main_diagram.html"
        self.assertTrue(main_html.exists())
        main_content = main_html.read_text()
        self.assertIn("Protocoles:", main_content)
        self.assertIn("HTTP", main_content)
        self.assertIn("red", main_content)

if __name__ == '__main__':
    unittest.main()
