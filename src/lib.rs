// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2025 Fantix King

use pyo3::prelude::*;

mod event_loop;
mod future;
mod handle;
mod import;
mod owned;
mod runtime;
mod send_wrapper;
mod task;
mod thread;

/// A Python module implemented in Rust. The name of this module must match
/// the `lib.name` setting in the `Cargo.toml`, else Python will not be able to
/// import the module.
#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    event_loop::register(m)?;
    handle::register(m)?;
    future::register(m)?;
    task::register(m)?;
    Ok(())
}
