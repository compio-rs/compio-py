use std::{
    pin::Pin,
    task::{Context, Poll},
};

use pyo3::{exceptions::PyRuntimeError, exceptions::PyStopIteration, prelude::*, types::PyType};

use crate::{event_loop::CompioLoop, send_wrapper::SendWrapper};

type PyAnyResult = Result<Py<PyAny>, Py<PyAny>>;

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

    pub fn set_exception(&mut self, exc: Bound<PyAny>) -> PyResult<()> {
        if exc.is_instance_of::<PyType>() {
            self.result = Some(Err(exc.call0()?.unbind()))
        } else if exc.is_instance_of::<PyStopIteration>() {
            return Err(PyErr::new::<PyRuntimeError, _>(
                "Cannot set StopIteration as exception of Future",
            ));
        } else {
            self.result = Some(Err(exc.unbind()));
        }
        Ok(())
    }

    fn __await__<'py>(slf: Py<Self>, py: Python<'py>) -> PyResult<Bound<'py, FutureAwaiter>> {
        Bound::new(py, FutureAwaiter(slf))
    }
    fn __iter__<'py>(slf: Py<Self>, py: Python<'py>) -> PyResult<Bound<'py, FutureAwaiter>> {
        Self::__await__(slf, py)
    }
}

impl PyFuture {
    pub fn from_future<T>(fut: T, pyloop: Py<CompioLoop>) -> Self
    where
        T: Future<Output = PyResult<Py<PyAny>>> + 'static,
    {
        let fut = async {
            match fut.await {
                Ok(result) => Ok(result),
                Err(err) => Err(Python::attach(|py| err.into_value(py).into_any())),
            }
        };
        Self {
            fut: Some(SendWrapper::new(Box::pin(fut))),
            pyloop,
            result: None,
        }
    }

    // pub fn poll(&mut self, cx: &mut Context) -> Poll<PyAnyResult> {
    //     if let Some(rv) = &self.result {
    //         Poll::Ready(Python::attach(|py| rv.clone_ref(py)))
    //     } else if let Some(fut) = self.fut.as_mut() {
    //         match fut
    //             .get_mut()
    //             .ok_or_else(|| {
    //                 PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
    //                     "Future polled from a different thread",
    //                 )
    //             })?
    //             .as_mut()
    //             .poll(cx)
    //         {
    //             Poll::Ready(result) => {
    //                 Python::attach(|py| {
    //                     self.result = Some(result.clone_ref(py));
    //                 });
    //                 Poll::Ready(result)
    //             }
    //             Poll::Pending => Poll::Pending,
    //         }
    //     } else {
    //         Poll::Pending
    //     }
    // }

    pub fn pyloop(&self) -> &Py<CompioLoop> {
        &self.pyloop
    }

    // pub fn take_fut(slf: Py<Self>) -> PyResult<impl Future<Output = PyAnyResult> + use<>> {
    //     Python::attach(|py| {
    //         let mut this = slf.borrow_mut(py);
    //         if let Some(rv) = &this.result {
    //             let rv = rv.clone_ref(py);
    //             Ok(Either::Left(async { rv }))
    //         } else if let Some(fut) = this
    //             .fut
    //             .get_mut()
    //             .ok_or_else(|| {
    //                 PyErr::new::<PyRuntimeError, _>("Future polled from a different thread")
    //             })?
    //             .take()
    //         {
    //             let slf = slf.clone_ref(py);
    //             Ok(Either::Right(Either::Left(async move {
    //                 let result = fut.await;
    //                 Python::attach(|py| {
    //                     slf.borrow_mut(py).result = Some(result.clone_ref(py));
    //                 });
    //                 result
    //             })))
    //         } else {
    //             let e = PyErr::new::<PyNotImplemented, _>("driven by add_done_callback");
    //             Ok(Either::Right(Either::Right(async { Err(e) })))
    //         }
    //     })
    // }
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
                            .into_value(py)
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

#[pyclass]
struct FutureAwaiter(Py<PyFuture>);

#[pymethods]
impl FutureAwaiter {
    fn __next__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyFuture>> {
        let fut = self.0.bind(py);
        match &fut.borrow().result {
            Some(Ok(result)) => Err(PyErr::new::<PyStopIteration, _>(result.clone_ref(py))),
            Some(Err(e)) => Err(PyErr::from_value(e.bind(py).clone()))?,
            None => Ok(fut.clone()),
        }
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
