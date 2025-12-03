# compio-py

High-performance Python `asyncio` alternative event loop powered by Rust's `compio` library.

## Development

### Setup

Install dependencies including `test` extras:

```bash
uv sync --extra test
```

### Testing

Run the test suite:

```bash
cargo test
uv run -m unittest -v
```
