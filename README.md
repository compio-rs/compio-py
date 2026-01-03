# <img src="docs/logo.svg" height="40px" align="right">  kLoop

High-performance Python `asyncio` alternative event loop powered by Rust's `compio` library.
"k" as in "completion" reflecting that `compio` drives completion-based I/O, or "k" as in
"kernel" reflecting kernel features like io_uring and kTLS.

## Development

### Setup

Install dependencies (only needed once):

```bash
uv sync
```

Or switch to enable logging support:

```bash
MATURIN_PEP517_ARGS="--features enable_log" uv sync --reinstall-package kloop
```

### Testing

Run the test suite:

```bash
cargo test
uv run -m unittest -v
```

If `enable_log` feature is on, you can set `RUST_LOG` environment variable to see debug/tracing logs.

## License

Licensed under either of

* Apache License, Version 2.0
* Mulan Permissive Software License, Version 2

at your option.

`SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0`
