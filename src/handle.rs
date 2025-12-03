// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2025 Fantix King

use std::{sync::Arc, sync::atomic::AtomicBool};

use pyo3::{IntoPyObjectExt, prelude::*, types::PyTuple};

pub struct Handle {
    callback: Py<PyAny>,
    args: Py<PyTuple>,
    context: Py<PyAny>,
    cancelled: AtomicBool,
}

impl Handle {
    pub fn new(
        py: Python,
        callback: Py<PyAny>,
        args: Py<PyTuple>,
        context: Option<Py<PyAny>>,
    ) -> PyResult<Arc<Self>> {
        // If no context is provided, copy the current context
        let context = match context {
            Some(ctx) => ctx,
            None => crate::import::copy_context(py)?.unbind(),
        };
        Ok(Arc::new(Self {
            callback,
            args,
            context,
            cancelled: AtomicBool::new(false),
        }))
    }

    pub fn run(&self) -> PyResult<()> {
        // Equivalent to: self.context.run(callback, *args)
        Python::attach(|py| {
            // Build argument list: [callback, arg1, arg2, ...]
            let args = std::iter::once(self.callback.bind(py).clone())
                .chain(self.args.bind(py).iter())
                .collect::<Vec<_>>();
            // Call the context.run() method
            self.context
                .bind(py)
                .getattr("run")?
                .call1(PyTuple::new(py, args)?)
                .map(drop)
        })
    }

    #[inline]
    pub fn cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::Acquire)
    }

    pub fn into_py<'py>(self: Arc<Self>, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        PyHandle(self).into_bound_py_any(py)
    }
}

#[pyclass(name = "Handle")]
struct PyHandle(Arc<Handle>);

#[pymethods]
impl PyHandle {
    fn cancel(&self) {
        self.0
            .cancelled
            .store(true, std::sync::atomic::Ordering::Release);
    }

    fn cancelled(&self) -> bool {
        self.0.cancelled()
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyHandle>()?;
    Ok(())
}
