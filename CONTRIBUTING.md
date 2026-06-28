# Contributing to WaveHunter

We welcome contributions of all forms, including bug reports, new feature suggestions, pull requests, and documentation improvements.

## Development Setup

1. Fork and clone the repository.
2. Setup a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```
3. Install development dependencies:
   ```bash
   pip install -r requirements.txt
   pip install -e .
   ```
4. Run tests:
   ```bash
   pytest
   ```

## Pull Request Guidelines

- Ensure your code follows PEP 8 and contains clear type hints.
- Write tests verifying new extractors or scanners.
- Maintain documentation and update the changelog if necessary.
- Submit your pull request to the main branch.
