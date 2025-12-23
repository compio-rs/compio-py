# <img src="docs/logo.svg" height="40px" align="right">  kLoop

High-performance Python `asyncio` alternative event loop powered by Rust's `compio` library.
"k" as in "completion" reflecting that `compio` drives completion-based I/O, or "k" as in
"kernel" reflecting kernel features like io_uring and kTLS.

## Development

### Setup

Install dependencies including `test` extras:

```bash
uv sync
```

### Testing

Run the test suite:

```bash
cargo test
uv run -m unittest -v
```

## License

Licensed under either of

* Apache License, Version 2.0
* Mulan Permissive Software License, Version 2

at your option.

`SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0`
