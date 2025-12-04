// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2025 Fantix King

use std::{
    cmp, iter,
    sync::{
        Arc,
        atomic::{self, AtomicBool, AtomicUsize},
    },
};

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
            let args = iter::once(self.callback.bind(py).clone())
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
    pub fn cancelled(&self) -> bool {
        self.cancelled.load(atomic::Ordering::Acquire)
    }

    pub fn into_py(self: Arc<Self>, py: Python) -> PyResult<Bound<PyAny>> {
        PyHandle(self).into_bound_py_any(py)
    }
}

pub struct TimerHandle {
    handle: Arc<Handle>,
    when: f64,
    timer_cancelled_count: Arc<AtomicUsize>,
}

impl TimerHandle {
    pub fn new(
        py: Python,
        callback: Py<PyAny>,
        args: Py<PyTuple>,
        context: Option<Py<PyAny>>,
        when: f64,
        timer_cancelled_count: Arc<AtomicUsize>,
    ) -> PyResult<Arc<Self>> {
        Ok(Arc::new(Self {
            handle: Handle::new(py, callback, args, context)?,
            when,
            timer_cancelled_count,
        }))
    }

    #[inline]
    pub fn cancelled(&self) -> bool {
        self.handle.cancelled()
    }

    #[inline]
    pub fn when(&self) -> f64 {
        self.when
    }

    pub fn into_base(self: Arc<Self>) -> Arc<Handle> {
        self.handle.clone()
    }

    pub fn into_py(self: Arc<Self>, py: Python) -> PyResult<Bound<PyAny>> {
        let base = PyHandle(self.handle.clone());
        let initializer = PyClassInitializer::from(base).add_subclass(PyTimerHandle(self));
        Py::new(py, initializer)?.into_bound_py_any(py)
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

#[pyclass(name = "Handle", subclass)]
struct PyHandle(Arc<Handle>);

#[pymethods]
impl PyHandle {
    fn cancel(&self) {
        self.0.cancel();
    }

    fn cancelled(&self) -> bool {
        self.0.cancelled()
    }
}

#[pyclass(name = "TimerHandle", extends=PyHandle)]
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct PyTimerHandle(Arc<TimerHandle>);

#[pymethods]
impl PyTimerHandle {
    fn cancel(&self) {
        if self.0.handle.cancel() {
            self.0
                .timer_cancelled_count
                .fetch_add(1, atomic::Ordering::AcqRel);
        }
    }

    fn when(&self) -> f64 {
        self.0.when()
    }

    fn __hash__(&self) -> u64 {
        self.0.when().to_bits()
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyHandle>()?;
    m.add_class::<PyTimerHandle>()?;
    Ok(())
}
