// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2025 Fantix King

use pyo3::prelude::*;

mod event_loop;
mod handle;
mod import;
mod owned;
mod runtime;
mod send_wrapper;
mod thread;

/// A Python module implemented in Rust. The name of this module must match
/// the `lib.name` setting in the `Cargo.toml`, else Python will not be able to
/// import the module.
#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    #[cfg(feature = "enable_log")]
    {
        use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

        let _ = tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(std::io::stderr)
                    .with_target(true)
                    .with_level(true),
            )
            .with(EnvFilter::from_default_env())
            .try_init();
    }

    event_loop::register(m)?;
    handle::register(m)?;
    Ok(())
}
