# Contributing to Post-Quantum MCP Server

Thank you for your interest in contributing! This project aims to make post-quantum cryptography accessible through the Model Context Protocol.

## How to Contribute

### Reporting Issues

- Check existing issues before creating a new one
- Include your Python version, liboqs version, and OS
- Provide minimal reproduction steps
- Include full error messages and stack traces

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Add tests if applicable
5. Run the test suite: `python -m pytest`
6. Format code: `python -m black pqc_mcp_server/`
7. Commit with a clear message
8. Push and create a Pull Request

### Code Style

- Follow PEP 8
- Use type hints
- Add docstrings to public functions
- Keep functions focused and small

### Adding New Tools

To add a new MCP tool:

1. Add the tool definition in `list_tools()`
2. Implement the handler in `call_tool()`
3. Add tests
4. Update README.md with usage examples

### Algorithm Support

When adding new algorithms:

- Verify they are supported by your liboqs version
- Add appropriate security level documentation
- Include performance characteristics if known
- Note any experimental/non-standard status

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/post-quantum-mcp.git
cd post-quantum-mcp

# Create virtual environment
uv venv --python 3.10 .venv
source .venv/bin/activate

# Install dev dependencies
uv pip install liboqs-python "mcp>=1.0.0" pytest black mypy

# Run tests
python -m pytest

# Check types
python -m mypy pqc_mcp_server/
```

## Questions?

Open an issue or discussion for any questions about contributing.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
