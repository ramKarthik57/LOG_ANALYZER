# Contributing to SENTINEL

Thank you for your interest in contributing to SENTINEL! We welcome contributions from the community.

## How to Contribute

### Reporting Issues

- Use the [GitHub Issues](https://github.com/ramKarthik57/LOG_ANALYZER/issues) to report bugs or request features
- Provide detailed information including steps to reproduce, expected behavior, and actual behavior
- Include relevant log files or screenshots if applicable

### Development Setup

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/your-username/LOG_ANALYZER.git
   cd LOG_ANALYZER
   ```
3. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   pip install -e .  # For development
   ```

### Making Changes

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. Make your changes following the coding standards
3. Add tests for new functionality
4. Run the test suite:
   ```bash
   python test_sentinel.py
   ```
5. Run linting:
   ```bash
   flake8 sentinel/
   black sentinel/
   isort sentinel/
   ```

### Code Standards

- Follow PEP 8 style guidelines
- Use type hints where appropriate
- Write docstrings for all functions and classes
- Keep functions small and focused
- Add comments for complex logic

### Testing

- Write unit tests for new features
- Ensure all tests pass before submitting
- Test on multiple Python versions if possible
- Include integration tests for complex features

### Submitting Changes

1. Commit your changes:
   ```bash
   git commit -m "Add feature: description of changes"
   ```
2. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```
3. Create a Pull Request on GitHub
4. Wait for review and address any feedback

### Pull Request Guidelines

- Provide a clear description of the changes
- Reference any related issues
- Ensure CI checks pass
- Keep PRs focused on a single feature or fix
- Update documentation if needed

## Code of Conduct

This project follows a code of conduct to ensure a welcoming environment for all contributors. By participating, you agree to:

- Be respectful and inclusive
- Focus on constructive feedback
- Accept responsibility for mistakes
- Show empathy towards other contributors
- Help create a positive community

## License

By contributing to this project, you agree that your contributions will be licensed under the same MIT License that covers the project.