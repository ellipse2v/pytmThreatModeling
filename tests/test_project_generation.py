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

import unittest
import tempfile
import shutil
import logging
import sys
from pathlib import Path

from threat_analysis.generation.report_generator import ReportGenerator
from threat_analysis.severity_calculator_module import SeverityCalculator
from threat_analysis.core.mitre_mapping_module import MitreMapping


class TestProjectGeneration(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.project_path = Path(self.test_dir) / "test_project"
        self.output_path = Path(self.test_dir) / "output"
        # Configure logging to be visible during tests
        logging.basicConfig(level=logging.INFO, stream=sys.stdout)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _run_generator(self):
        severity_calculator = SeverityCalculator()
        mitre_mapping = MitreMapping()
        report_generator = ReportGenerator(severity_calculator, mitre_mapping)

        import sys
        original_argv = sys.argv
        sys.argv = [original_argv[0]]
        try:
            report_generator.generate_project_reports(self.project_path, self.output_path)
        finally:
            sys.argv = original_argv

    def test_single_level_project(self):
        # Arrange
        sub_project_path = self.project_path / "sub_A"
        sub_project_path.mkdir(parents=True)
        with open(self.project_path / "main.md", "w") as f:
            f.write("## Servers\n- **WebApp**: submodel=./sub_A/model.md")
        with open(sub_project_path / "model.md", "w") as f:
            f.write("## Servers\n- **WebServer**:")

        # Act
        self._run_generator()

        # Assert
        main_html = self.output_path / "test_project" / "main_diagram.html"
        sub_html = self.output_path / "test_project" / "sub_A" / "model_diagram.html"
        self.assertTrue(main_html.exists())
        self.assertTrue(sub_html.exists())

        main_content = main_html.read_text()
        self.assertIn('xlink:href="sub_A/model_diagram.html"', main_content)

        sub_content = sub_html.read_text()
        self.assertIn('href="../main_diagram.html"', sub_content) # Back button
        self.assertIn('<a href="../main_diagram.html">test_project</a>', sub_content) # Breadcrumb
        self.assertIn('<a href="model_diagram.html">sub_A</a>', sub_content) # Breadcrumb

    def test_nested_project_and_dataflows(self):
        # Arrange
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
        backend_html = self.output_path / "test_project" / "backend" / "model_diagram.html"
        db_html = self.output_path / "test_project" / "backend" / "database" / "model_diagram.html"
        self.assertTrue(backend_html.exists())
        self.assertTrue(db_html.exists())

        backend_content = backend_html.read_text()
        self.assertIn('xlink:href="database/model_diagram.html"', backend_content) # Link to nested

        db_content = db_html.read_text()
        self.assertIn('href="../model_diagram.html"', db_content) # Back button
        self.assertIn('<a href="../../main_diagram.html">test_project</a>', db_content)
        self.assertIn('<a href="../model_diagram.html">backend</a>', db_content)
        self.assertIn('<a href="model_diagram.html">database</a>', db_content)


if __name__ == '__main__':
    unittest.main()
