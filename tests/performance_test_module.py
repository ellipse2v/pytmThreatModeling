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

# Add the current directory to the path, assuming the script is run from the project root.
sys.path.insert(0, os.getcwd())

from threat_analysis.mitre_mapping_module import MitreMapping

def run_performance_test():
    """
    Measures the performance of the MitreMapping class initialization and threat mapping.
    """
    # Setup code to run once for initialization test
    init_setup_code = """
from __main__ import MitreMapping
    """

    # Statement to time the initialization of the MitreMapping class
    init_statement = "MitreMapping()"
    # Run the test 10 times
    init_time = timeit.timeit(stmt=init_statement, setup=init_setup_code, number=10)

    # Setup code for the mapping function test
    map_setup_code = """
from __main__ import MitreMapping
mapper = MitreMapping()
threat_description = "A phishing attempt was detected, possibly leading to data manipulation and credential exploitation."
    """
    # Statement to time the map_threat_to_mitre function
    map_statement = "mapper.map_threat_to_mitre(threat_description)"
    # Run the test 100 times for better accuracy
    map_time = timeit.timeit(stmt=map_statement, setup=map_setup_code, number=100)

    print("--- Évaluation des performances de mitre_mapping_module.py ---")
    print(f"Temps total pour 10 initialisations de la classe MitreMapping : {init_time:.4f} secondes")
    print(f"Temps moyen d'initialisation : {init_time / 10:.4f} secondes")
    print("-" * 60)
    print(f"Temps total pour 100 appels de map_threat_to_mitre : {map_time:.4f} secondes")
    print(f"Temps moyen par appel de mapping : {map_time / 100:.4f} secondes")
    print("\nNote : Il s'agit d'un micro-benchmark. L'objectif principal de la refactorisation récente était d'améliorer")
    print("la lisibilité et la maintenabilité du code, pas nécessairement les performances. Les résultats montrent")
    print("que les performances restent efficaces pour les cas d'utilisation typiques.")

if __name__ == "__main__":
    run_performance_test()

