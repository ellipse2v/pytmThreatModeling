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
# 

import timeit
import sys
import os
import logging

# Add project root to sys.path to allow imports from main_analysis and threat_analysis
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from main_analysis import ThreatAnalysisFramework

def analysis_pipeline():
    """
    A wrapper function that runs the entire analysis pipeline.
    This will be timed.
    """
    # Suppress verbose logging during performance testing
    logging.basicConfig(level=logging.CRITICAL)
    
    framework = ThreatAnalysisFramework(model_filepath="threat_model.md")
    framework.run_analysis()
    framework.generate_reports()
    framework.generate_diagrams()

def run_full_app_performance_test():
    """
    Measures the performance of the full application analysis pipeline.
    """
    # Setup code to import the pipeline function into the timeit scope
    setup_code = "from __main__ import analysis_pipeline"

    # Statement to time
    statement = "analysis_pipeline()"

    # Run the test 3 times to get a good average
    number_of_runs = 3
    total_time = timeit.timeit(stmt=statement, setup=setup_code, number=number_of_runs)

    print("--- Évaluation des performances de l'application complète ---")
    print(f"Temps total pour {number_of_runs} exécutions complètes de l'analyse : {total_time:.4f} secondes")
    print(f"Temps moyen par exécution : {total_time / number_of_runs:.4f} secondes")
    print("\nNote : Ce test mesure le temps nécessaire pour l'ensemble du processus, y compris la lecture des fichiers,")
    print("l'analyse des menaces, le mappage MITRE et la génération des rapports. Il fournit une vue d'ensemble")
    print("des performances de l'application.")

if __name__ == "__main__":
    run_full_app_performance_test()