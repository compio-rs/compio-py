// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2025 Fantix King

use crate::future::PyFuture;
use crate::{
    handle,
    handle::{Handle, TimerHandle},
    owned::{self, OwnedRefCell},
    runtime::{self, Runtime},
};
use compio::driver::op::Recv;
use pyo3::buffer::PyBuffer;
use pyo3::exceptions::PyValueError;
use pyo3::{
    IntoPyObjectExt,
    exceptions::PyRuntimeError,
    prelude::*,
    types::{PyTuple, PyWeakrefReference},
};
use std::os::fd::{FromRawFd, OwnedFd};
use std::sync::{
    Arc,
    atomic::{self, AtomicBool},
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
        let shared = handle::Shared::new(py, callback, args, context)?;
        let x = runtime.spawner()(async { Python::attach(|py| {}) });
        let handle = Handle::new(shared)?;
        let rv = handle.as_py_any(py)?;
        runtime.push_ready(handle);
        Ok(rv)
    }

    #[pyo3(signature = (when, callback, *args, context=None))]
    fn call_at<'py>(
        &self,
        py: Python<'py>,
        when: f64,
        callback: Py<PyAny>,
        args: Py<PyTuple>,
        context: Option<Py<PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.call_at_impl(self.runtime()?, py, when, callback, args, context)
    }

    #[pyo3(signature = (delay, callback, *args, context=None))]
    fn call_later<'py>(
        &self,
        py: Python<'py>,
        delay: f64,
        callback: Py<PyAny>,
        args: Py<PyTuple>,
        context: Option<Py<PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let runtime = self.runtime()?;
        let when = runtime.since_epoch().as_secs_f64() + delay;
        self.call_at_impl(runtime, py, when, callback, args, context)
    }

    fn time(&self) -> PyResult<f64> {
        Ok(self.runtime()?.since_epoch().as_secs_f64())
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
        eprintln!("Stopping event loop");
        self.stopping.store(true, atomic::Ordering::SeqCst);
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

    // Completion based I/O methods returning Futures.

    fn sock_recv_into(slf: Py<Self>, sock: Py<PyAny>, buf: Py<PyAny>) -> PyResult<PyFuture> {
        let coro = async {
            let op = Python::attach(|py| {
                let pybuf: PyBuffer<u8> = PyBuffer::get(buf.bind(py))?;
                if pybuf.readonly() {
                    return Err(PyErr::new::<PyValueError, _>(
                        "buffer argument must be writable",
                    ));
                }
                if !pybuf.is_c_contiguous() {
                    return Err(PyErr::new::<PyValueError, _>(
                        "buffer argument must be C-contiguous",
                    ));
                }
                let ptr = pybuf.buf_ptr() as *mut u8;
                let len = pybuf.len_bytes();
                let buf = unsafe { std::slice::from_raw_parts_mut(ptr, len) };

                let fd = sock.bind(py).call_method0("fileno")?.extract::<i32>()?;
                let fd = unsafe { OwnedFd::from_raw_fd(fd) };
                Ok(Recv::new(fd, buf))
            })?;
            let nbytes = runtime::execute(op).await.0?;

            // make sure sock and buf are captured and not dropped too early
            drop(sock);
            drop(buf);

            Python::attach(|py| nbytes.into_py_any(py))
        };
        Ok(PyFuture::from_future(coro, slf))
    }
}

impl CompioLoop {
    #[inline]
    pub fn runtime(&self) -> PyResult<owned::Ref<'_, Runtime>> {
        match self.runtime.get() {
            Ok(Some(rv)) => Ok(rv),
            Ok(None) => Err(PyErr::new::<PyRuntimeError, _>("CompioLoop is closed")),
            Err(_) => Err(PyErr::new::<PyRuntimeError, _>(
                "Non-thread-safe operation invoked on an event loop other than the current one",
            )),
        }
    }

    #[inline]
    fn call_at_impl<'py>(
        &self,
        runtime: owned::Ref<Runtime>,
        py: Python<'py>,
        when: f64,
        callback: Py<PyAny>,
        args: Py<PyTuple>,
        context: Option<Py<PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let handle = TimerHandle::new(py, callback, args, context, when)?;
        let rv = handle.as_py_any(py, runtime.timer_cancelled_count())?;
        runtime.push_scheduled(handle);
        Ok(rv)
    }
}

struct StoreFalseGuard(Arc<AtomicBool>);

impl Drop for StoreFalseGuard {
    #[inline]
    fn drop(&mut self) {
        self.0.store(false, atomic::Ordering::SeqCst);
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<CompioLoop>()?;
    Ok(())
}
