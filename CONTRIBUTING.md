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
5. Run the test suite: `uv run pytest tests/ -v`
6. Format code: `uv run black pqc_mcp_server/ tests/`
7. Type check: `uv run mypy pqc_mcp_server/`
8. Commit with a clear message
9. Push and create a Pull Request

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

# Install all dependencies (creates .venv automatically)
uv sync --all-extras

# Run tests
uv run pytest tests/ -v

# Format code
uv run black pqc_mcp_server/ tests/

# Type check
uv run mypy pqc_mcp_server/
```

## Questions?

Open an issue or discussion for any questions about contributing.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
