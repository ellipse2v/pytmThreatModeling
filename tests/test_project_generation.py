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
from pathlib import Path

from threat_analysis.generation.report_generator import ReportGenerator
from threat_analysis.severity_calculator_module import SeverityCalculator
from threat_analysis.core.mitre_mapping_module import MitreMapping


class TestProjectGeneration(unittest.TestCase):

    def setUp(self):
        # Create a temporary directory for the project source and output
        self.test_dir = tempfile.mkdtemp()
        self.project_path = Path(self.test_dir) / "test_project"
        self.output_path = Path(self.test_dir) / "output"

        # Create project structure
        self.sub_project_path = self.project_path / "sub_project_A"
        self.sub_project_path.mkdir(parents=True)

        # Create main model file
        with open(self.project_path / "main.md", "w") as f:
            f.write("""
## Servers
- **APIService**: submodel=./sub_project_A/model.md
- **NormalService**:
            """)

        # Create sub-model file
        with open(self.sub_project_path / "model.md", "w") as f:
            f.write("""
## Servers
- **Database**:
            """)

    def tearDown(self):
        # Remove the temporary directory
        shutil.rmtree(self.test_dir)

    def test_project_generation_creates_files_and_links_correctly(self):
        # Arrange
        severity_calculator = SeverityCalculator()
        mitre_mapping = MitreMapping()
        report_generator = ReportGenerator(severity_calculator, mitre_mapping)

        # Act
        # HACK: The underlying pytm library inappropriately parses sys.argv.
        # We need to temporarily clear them to avoid crashing pytest-cov.
        import sys
        original_argv = sys.argv
        sys.argv = [original_argv[0]]
        try:
            report_generator.generate_project_reports(self.project_path, self.output_path)
        finally:
            sys.argv = original_argv

        # Assert
        # Check that the output directories and files were created
        main_diagram_html = self.output_path / "test_project" / "main_diagram.html"
        sub_diagram_html = self.output_path / "test_project" / "sub_project_A" / "model_diagram.html"

        self.assertTrue(main_diagram_html.exists())
        self.assertTrue(sub_diagram_html.exists())

        # Check the link in the main diagram
        with open(main_diagram_html, "r") as f:
            main_html_content = f.read()
            # Check for a link to the sub-project directory and file
            self.assertIn('xlink:href="sub_project_A/model_diagram.html"', main_html_content)

        # Check the back button and breadcrumbs in the sub-diagram
        with open(sub_diagram_html, "r") as f:
            sub_html_content = f.read()
            # Check for the back button link
            self.assertIn('href="../main_diagram.html"', sub_html_content)
            # Check for the breadcrumb links
            self.assertIn('<a href="../main_diagram.html">test_project</a>', sub_html_content)
            self.assertIn('<a href="model_diagram.html">sub_project_A</a>', sub_html_content)

    def test_nested_project_generation(self):
        # Arrange
        # Create a nested sub-project
        nested_sub_path = self.sub_project_path / "nested_B"
        nested_sub_path.mkdir()
        with open(self.sub_project_path / "model.md", "w") as f:
            f.write("""
## Servers
- **NestedService**: submodel=./nested_B/nested_model.md
            """)
        with open(nested_sub_path / "nested_model.md", "w") as f:
            f.write("""
## Servers
- **FinalService**:
            """)

        severity_calculator = SeverityCalculator()
        mitre_mapping = MitreMapping()
        report_generator = ReportGenerator(severity_calculator, mitre_mapping)

        # Act
        import sys
        original_argv = sys.argv
        sys.argv = [original_argv[0]]
        try:
            report_generator.generate_project_reports(self.project_path, self.output_path)
        finally:
            sys.argv = original_argv

        # Assert
        nested_diagram_html = self.output_path / "test_project" / "sub_project_A" / "nested_B" / "nested_model_diagram.html"
        self.assertTrue(nested_diagram_html.exists())

        with open(nested_diagram_html, "r") as f:
            nested_html = f.read()
            # Check back button to level 2
            self.assertIn('href="../model_diagram.html"', nested_html)
            # Check breadcrumbs
            self.assertIn('<a href="../../main_diagram.html">test_project</a>', nested_html)
            self.assertIn('<a href="../model_diagram.html">sub_project_A</a>', nested_html)
            self.assertIn('<a href="nested_model_diagram.html">nested_B</a>', nested_html)


if __name__ == '__main__':
    unittest.main()
