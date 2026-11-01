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
5. Run the test suite: `uv run --frozen pytest tests/ -v`
6. Format code: `uv run --frozen black pqc_mcp_server/ tests/`
7. Type check: `uv run --frozen mypy pqc_mcp_server/`
8. Commit with a clear message
9. Push and create a Pull Request

### Code Style

- Follow PEP 8
- Use type hints
- Add docstrings to public functions
- Keep functions focused and small

### Adding New Tools

To add a new MCP tool:

1. Add the tool definition in `pqc_mcp_server/tools.py` (relay definitions live in `relay_tools.py`)
2. Implement a typed handler and register it in `pqc_mcp_server/__init__.py`
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
uv sync --frozen --all-extras

# Run tests
uv run --frozen pytest tests/ -v

# Format code
uv run --frozen black pqc_mcp_server/ tests/

# Type check
uv run --frozen mypy pqc_mcp_server/
```

## Questions?

Open an issue or discussion for any questions about contributing.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Reproducible checks

Install liboqs 0.16.0 with `scripts/install-liboqs.sh`; `run.sh` prefers `.vendor/liboqs-0.16`.
Hypothesis is a required dev dependency: ordinary property tests must not skip.
Tests use isolated replay databases and must never reset the operator's state.

Ordinary pytest excludes the `e2e` marker. External integration requires an explicit
disposable endpoint and admin credential; see README. Do not hard-code a public relay.
Run `npm ci`, `npm run typecheck`, `npm test`, and `npm run build` inside
`deploy/relay/worker` with Node 24 or later. Both lockfiles belong in dependency changes.
