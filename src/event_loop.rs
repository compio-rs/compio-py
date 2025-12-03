// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2025 Fantix King

use std::sync::{Arc, atomic::AtomicBool};

use pyo3::{
    exceptions::PyRuntimeError,
    prelude::*,
    types::{PyTuple, PyWeakrefReference},
};

use crate::{
    handle::Handle,
    owned::{self, OwnedRefCell},
    runtime::Runtime,
};

#[pyclass(subclass)]
#[derive(Default)]
pub struct CompioLoop {
    runtime: OwnedRefCell<Runtime>,
    stopping: Arc<AtomicBool>,
}

#[pymethods]
impl CompioLoop {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn __init__(slf: &Bound<Self>, py: Python) -> PyResult<()> {
        let stopping = slf.borrow().stopping.clone();
        let pyloop = PyWeakrefReference::new(slf)?.unbind();
        let runtime = py.detach(|| Runtime::new(pyloop, stopping))?;
        slf.borrow_mut()
            .runtime
            .init(runtime)
            .expect("uninitialized");
        Ok(())
    }

    fn is_running(&self) -> bool {
        match self.runtime.acquire(false) {
            Ok(_) => false,
            _ => true,
        }
    }

    fn is_closed(&self) -> bool {
        match self.runtime.get() {
            Ok(None) => true,
            _ => false,
        }
    }

    fn get_driver_type(&self) -> PyResult<String> {
        Ok(format!("{:?}", self.runtime()?.driver_type()))
    }

    #[pyo3(signature = (callback, *args, context=None))]
    fn call_soon<'py>(
        &self,
        py: Python<'py>,
        callback: Py<PyAny>,
        args: Py<PyTuple>,
        context: Option<Py<PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let runtime = self.runtime()?;
        let handle = Handle::new(py, callback, args, context)?;
        runtime.push_ready(handle.clone());
        handle.into_py(py)
    }

    fn run_forever(&self, py: Python) -> PyResult<()> {
        py.detach(|| {
            let _guard = self.runtime.acquire(false).map_err(|_| {
                PyErr::new::<PyRuntimeError, _>("This event loop is already running")
            })?;
            let _clear_stopping_guard = StoreFalseGuard(self.stopping.clone());
            self.runtime()?.run()
        })
    }

    fn stop(&self) {
        self.stopping
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn close(slf: &Bound<Self>) -> PyResult<()> {
        if let Some(runtime) = slf
            .try_borrow_mut()
            .map_err(|_| PyErr::new::<PyRuntimeError, _>("Cannot close a running event loop"))?
            .runtime
            .take()
        {
            drop(runtime);
        }
        Ok(())
    }
}

impl CompioLoop {
    #[inline]
    fn runtime(&self) -> PyResult<owned::Ref<'_, Runtime>> {
        match self.runtime.get() {
            Ok(Some(rv)) => Ok(rv),
            Ok(None) => Err(PyErr::new::<PyRuntimeError, _>("CompioLoop is closed")),
            Err(_) => Err(PyErr::new::<PyRuntimeError, _>(
                "Non-thread-safe operation invoked on an event loop other than the current one",
            )),
        }
    }
}

struct StoreFalseGuard(Arc<AtomicBool>);

impl Drop for StoreFalseGuard {
    #[inline]
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<CompioLoop>()?;
    Ok(())
}
