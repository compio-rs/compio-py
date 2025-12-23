use std::{
    pin::Pin,
    task::{Context, Poll},
};

use pyo3::{exceptions::PyRuntimeError, exceptions::PyStopIteration, prelude::*, types::PyType};

use crate::{event_loop::CompioLoop, send_wrapper::SendWrapper};

type PyAnyResult = PyResult<Py<PyAny>>;

trait CloneRefPy {
    fn clone_ref(&self, py: Python) -> Self;
}

impl CloneRefPy for PyAnyResult {
    fn clone_ref(&self, py: Python) -> Self {
        match self {
            Ok(obj) => Ok(obj.clone_ref(py)),
            Err(err) => Err(err.clone_ref(py)),
        }
    }
}

#[pyclass(name = "Future", subclass)]
pub struct PyFuture {
    fut: Option<SendWrapper<Pin<Box<dyn Future<Output = PyAnyResult>>>>>,
    #[allow(unused)]
    pyloop: Py<CompioLoop>,
    result: Option<PyAnyResult>,
}

#[pymethods]
impl PyFuture {
    #[new]
    #[pyo3(signature = (*, r#loop))]
    pub fn new(r#loop: Py<CompioLoop>) -> Self {
        Self {
            fut: None,
            pyloop: r#loop,
            result: None,
        }
    }

    pub fn set_result(&mut self, result: Py<PyAny>) {
        self.result = Some(Ok(result));
    }

    pub fn set_exception(&mut self, py: Python, exc: Bound<PyAny>) -> PyResult<()> {
        if let Ok(ty) = exc.clone().cast_into::<PyType>() {
            self.result = Some(Err(PyErr::from_type(ty, ())));
        } else if exc.is_instance_of::<PyStopIteration>() {
            let e = PyRuntimeError::new_err("Cannot set StopIteration as exception of Future");
            let v = e.value(py);
            v.setattr("__cause__", exc.clone())?;
            v.setattr("__context__", exc.clone())?;
            self.result = Some(Err(e));
        } else {
            self.result = Some(Err(PyErr::from_value(exc)));
        }
        Ok(())
    }

    fn __await__<'py>(slf: Py<Self>, py: Python<'py>) -> PyResult<Bound<'py, FutureAwaiter>> {
        Bound::new(py, FutureAwaiter(slf))
    }
}

impl PyFuture {
    pub fn from_future<T>(fut: T, pyloop: Py<CompioLoop>) -> Self
    where
        T: Future<Output = PyAnyResult> + 'static,
    {
        Self {
            fut: Some(SendWrapper::new(Box::pin(fut))),
            pyloop,
            result: None,
        }
    }
}

#[pyclass]
struct FutureAwaiter(Py<PyFuture>);

#[pymethods]
impl FutureAwaiter {
    fn __next__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyFuture>> {
        let fut = self.0.bind(py);
        match &fut.borrow().result {
            Some(Ok(result)) => Err(PyErr::new::<PyStopIteration, _>(result.clone_ref(py))),
            Some(Err(e)) => Err(e.clone_ref(py)),
            None => Ok(fut.clone()),
        }
    }
}

struct PyFutureFuture(Py<PyFuture>);

impl Future for PyFutureFuture {
    type Output = PyAnyResult;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Python::attach(|py| {
            let mut slf = self.0.borrow_mut(py);
            if let Some(rv) = &slf.result {
                Poll::Ready(rv.clone_ref(py))
            } else if let Some(fut) = &mut slf.fut {
                match fut
                    .get_mut()
                    .ok_or_else(|| {
                        PyRuntimeError::new_err("Future polled from a different thread")
                    })?
                    .as_mut()
                    .poll(cx)
                {
                    Poll::Ready(result) => {
                        Python::attach(|py| {
                            slf.result = Some(result.clone_ref(py));
                        });
                        Poll::Ready(result)
                    }
                    Poll::Pending => Poll::Pending,
                }
            } else {
                Poll::Pending
            }
        })
    }
}

#[inline]
pub async fn wait_future(fut: Py<PyFuture>) -> PyAnyResult {
    PyFutureFuture(fut).await
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyFuture>()?;
    Ok(())
}
