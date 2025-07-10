# Developer Guide

## Running Tests

To run the tests for this project, navigate to the root directory of the project in your terminal and execute the following command:

```bash
python3 -m pytest
```

This command will discover and run all tests in the `tests/` directory.

### Running Specific Test Files

To run tests in a specific file, you can provide the path to the file:

```bash
python3 -m pytest tests/test_diagram_generator.py
```

### Generating Code Coverage Report

To generate a code coverage report, which shows how much of your code is exercised by the tests, use the following command:

```bash
PYTHONPATH=. pytest --cov=.
```

This will display a summary of the coverage in your terminal.
