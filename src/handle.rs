// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2025 Fantix King

use std::{
    cmp, iter,
    ops::Deref,
    sync::{
        Arc,
        atomic::{self, AtomicBool, AtomicUsize},
    },
};
use async_task::Task;
use pyo3::{
    exceptions::{PyKeyboardInterrupt, PySystemExit},
    prelude::*,
    pyclass::CompareOp,
    sync::PyOnceLock,
    types::{PyDict, PyTuple},
};

pub struct Shared {
    callback: Py<PyAny>,
    args: Py<PyTuple>,
    context: Py<PyAny>,
    cancelled: AtomicBool,
}

impl Shared {
    #[inline]
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

    #[inline]
    pub fn run(&self) {
        Python::attach(|py| {
            // Build argument list: [callback, arg1, arg2, ...]
            let args = iter::once(self.callback.bind(py).clone())
                .chain(self.args.bind(py).iter())
                .collect::<Vec<_>>();

            // Equivalent to: self.context.run(callback, *args)
            let rv = self
                .context
                .bind(py)
                .getattr("run")
                .and_then(|run| run.call1(PyTuple::new(py, args)?));

            // Handle exceptions
            match rv {
                Ok(_) => Ok(()),

                // Reraise SystemExit and KeyboardInterrupt
                Err(e) if e.is_instance_of::<PySystemExit>(py) => Err(e),
                Err(e) if e.is_instance_of::<PyKeyboardInterrupt>(py) => Err(e),

                // Call the loop's exception handler for other exceptions
                Err(e) => {
                    let context = PyDict::new(py);
                    context.set_item("message", "Exception in callback")?;
                    context.set_item("exception", e)?;
                    context.set_item("handle", self.as_py_any(py)?)?;
                    call_exception_handler.bind(py).call1((context,)).map(drop)
                }
            }
        })
    }

    #[inline]
    fn cancel(&self) -> bool {
        self.cancelled
            .compare_exchange(
                false,
                true,
                atomic::Ordering::AcqRel,
                atomic::Ordering::Acquire,
            )
            .is_ok()
    }

    #[inline]
    fn cancelled(&self) -> bool {
        self.cancelled.load(atomic::Ordering::Acquire)
    }
}

pub struct Handle {
    shared: Arc<Shared>,

    pyhandle: PyOnceLock<Py<PyAny>>,
}

impl Handle {
    pub fn new(
        py: Python,
        callback: Py<PyAny>,
        args: Py<PyTuple>,
        context: Option<Py<PyAny>>,
    ) -> PyResult<Self> {
        // If no context is provided, copy the current context
        let context = match context {
            Some(ctx) => ctx,
            None => crate::import::copy_context(py)?.unbind(),
        };
        let shared = Shared::new(callback, args, context);
        let pyhandle = PyOnceLock::new();
        Ok(Self { shared, pyhandle })
    }

    pub fn run(&self, call_exception_handler: &Py<PyAny>) -> PyResult<()> {
        Python::attach(|py| {
            // Build argument list: [callback, arg1, arg2, ...]
            let shared = self.shared.deref();
            let args = iter::once(shared.callback.bind(py).clone())
                .chain(shared.args.bind(py).iter())
                .collect::<Vec<_>>();

            // Equivalent to: self.context.run(callback, *args)
            let rv = shared
                .context
                .bind(py)
                .getattr("run")
                .and_then(|run| run.call1(PyTuple::new(py, args)?));

            // Handle exceptions
            match rv {
                Ok(_) => Ok(()),

                // Reraise SystemExit and KeyboardInterrupt
                Err(e) if e.is_instance_of::<PySystemExit>(py) => Err(e),
                Err(e) if e.is_instance_of::<PyKeyboardInterrupt>(py) => Err(e),

                // Call the loop's exception handler for other exceptions
                Err(e) => {
                    let context = PyDict::new(py);
                    context.set_item("message", "Exception in callback")?;
                    context.set_item("exception", e)?;
                    context.set_item("handle", self.as_py_any(py)?)?;
                    call_exception_handler.bind(py).call1((context,)).map(drop)
                }
            }
        })
    }

    #[inline]
    pub fn cancelled(&self) -> bool {
        self.shared.cancelled()
    }

    pub fn as_py_any<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        self.pyhandle
            .get_or_try_init(py, || {
                Py::new(py, PyHandle(self.shared.clone())).map(|obj| obj.into_any())
            })
            .map(|obj| obj.bind(py).clone())
    }
}

pub struct TimerHandle {
    handle: Handle,
    when: f64,
}

impl TimerHandle {
    pub fn new(
        py: Python,
        callback: Py<PyAny>,
        args: Py<PyTuple>,
        context: Option<Py<PyAny>>,
        when: f64,
    ) -> PyResult<Self> {
        let handle = Handle::new(py, callback, args, context)?;
        Ok(Self { handle, when })
    }

    #[inline]
    pub fn cancelled(&self) -> bool {
        self.handle.shared.cancelled()
    }

    #[inline]
    pub fn when(&self) -> f64 {
        self.when
    }

    pub fn into_base(self) -> Handle {
        self.handle
    }

    pub fn as_py_any<'py>(
        &self,
        py: Python<'py>,
        timer_cancelled_count: Arc<AtomicUsize>,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.handle
            .pyhandle
            .get_or_try_init(py, || {
                let base = PyHandle(self.handle.shared.clone());
                let handle = PyTimerHandle {
                    shared: self.handle.shared.clone(),
                    when: self.when,
                    timer_cancelled_count,
                };
                let initializer = PyClassInitializer::from(base).add_subclass(handle);
                Py::new(py, initializer).map(|obj| obj.into_any())
            })
            .map(|obj| obj.bind(py).clone())
    }
}

impl PartialEq for TimerHandle {
    fn eq(&self, other: &Self) -> bool {
        self.when == other.when
    }
}

impl Eq for TimerHandle {}

impl PartialOrd for TimerHandle {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TimerHandle {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        // Reverse order to turn BinaryHeap into a min-heap (smallest `when` first)
        other
            .when
            .partial_cmp(&self.when)
            .unwrap_or(cmp::Ordering::Equal)
    }
}

#[pyclass(name = "Handle", subclass, weakref)]
struct PyHandle {
    callback: Py<PyAny>,
    args: Py<PyTuple>,
    context: Py<PyAny>,
    task: Task<()>,
    cancelled: AtomicBool,
}

#[pymethods]
impl PyHandle {
    fn cancel(&self) {
        self.0.cancel();
    }

    fn cancelled(&self) -> bool {
        self.0.cancelled()
    }

    fn get_context<'py>(&self, py: Python<'py>) -> Bound<'py, PyAny> {
        self.0.context.bind(py).clone()
    }
}

#[pyclass(name = "TimerHandle", extends=PyHandle)]
struct PyTimerHandle {
    shared: Arc<Shared>,
    when: f64,
    timer_cancelled_count: Arc<AtomicUsize>,
}

#[pymethods]
impl PyTimerHandle {
    fn cancel(&self) {
        if self.shared.cancel() {
            self.timer_cancelled_count
                .fetch_add(1, atomic::Ordering::AcqRel);
        }
    }

    fn when(&self) -> f64 {
        self.when
    }

    fn __hash__(&self) -> u64 {
        self.when.to_bits()
    }

    fn __richcmp__(&self, other: &Self, op: CompareOp, py: Python) -> PyResult<bool> {
        Ok(match op {
            CompareOp::Eq => self.eq(other, py)?,
            CompareOp::Ne => !self.eq(other, py)?,
            CompareOp::Lt => self.when < other.when,
            CompareOp::Le => self.when < other.when || self.eq(other, py)?,
            CompareOp::Gt => self.when > other.when,
            CompareOp::Ge => self.when > other.when || self.eq(other, py)?,
        })
    }
}

impl PyTimerHandle {
    fn eq(&self, other: &Self, py: Python) -> PyResult<bool> {
        if self.when == other.when {
            let this = self.shared.deref();
            let that = other.shared.deref();
            Ok(this.callback.bind(py).eq(that.callback.bind(py))?
                && this.args.bind(py).eq(that.args.bind(py))?
                && this.cancelled() == that.cancelled())
        } else {
            Ok(false)
        }
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyHandle>()?;
    m.add_class::<PyTimerHandle>()?;
    Ok(())
}
