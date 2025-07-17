# Code Style Guide

This document describes the code style conventions to follow for this project. The goal is to ensure code consistency, readability, and maintainability.

## 1. Linting with Flake8

We use `flake8` for static Python code analysis and to enforce style conventions.

### Flake8 Configuration

The `flake8` configuration is defined in the `.flake8` file at the root of the project. Here are the main rules:

- **Maximum line length:** 120 characters.
- **Exclusions:** Certain directories and files are excluded from `flake8` analysis because they contain generated code, caches, or specific configurations.

```ini
[flake8]
max-line-length = 120
exclude =
    .git,
    __pycache__,
    .pytest_cache,
    output,
    licence,
    .vscode,
    .idea,
    .mypy_cache,
    .venv,
    .env,
    .DS_Store,
    .coverage,
    README.md,
    .flake8,
    .gitignore,
    developer.md,
    requirements.txt,
    threat_model.md
```

### Run Flake8

To check your code with `flake8`, run the following command at the root of the project:

```bash
flake8 .
```

It is recommended to run this command regularly during development to identify and fix style issues.

## 2. General Conventions

### Naming

- **Modules and packages:** Short names, all lowercase, with underscores if necessary (e.g., `my_module`, `my_package`).
- **Classes:** `CamelCase` names (e.g., `MyClass`).
- **Functions and methods:** All lowercase names, with underscores if necessary (e.g., `my_function`, `my_method`).
- **Variables:** All lowercase names, with underscores if necessary (e.g., `my_variable`).
- **Constants:** All uppercase names, with underscores if necessary (e.g., `MY_CONSTANT`).

### Spacing

- Use 4 spaces for indentation. Do not use tabs.
- Leave one blank line between function and class definitions.
- Leave two blank lines between top-level class definitions.

### Comments

- Comments should be concise, relevant, and up-to-date.
- Explain the "why" rather than the "what". Code should be self-documenting as much as possible.
- Use docstrings for modules, classes, and functions.

### Imports

- Import modules at the top of the file, after the module docstrings and `__future__` comments (if present).
- Group imports in the following order:
    1. Standard library imports.
    2. Third-party library imports.
    3. Local/project module imports.
- Separate each group with a blank line.
- Use absolute imports rather than relative imports.

### Functions and Methods

- Functions should be short and do only one thing.
- Avoid functions with too many parameters.
- Use named arguments to improve the readability of complex function calls.

### Error Handling

- Use exceptions to handle errors.
- Be specific when catching exceptions. Avoid bare `except Exception:`.

By following these guidelines, we can maintain a clean, consistent, and easy-to-understand codebase for all contributors.