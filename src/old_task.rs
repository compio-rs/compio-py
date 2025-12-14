use crate::{event_loop::CompioLoop, future::PyFuture, import};
use pyo3::exceptions::{PyKeyboardInterrupt, PyStopIteration, PySystemExit};
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyCFunction, PyTuple};
use std::task::{Context, Poll, Waker};

#[pyclass(name = "Task", extends=PyFuture, weakref)]
pub struct PyTask {
    #[allow(unused)]
    coro: Py<PyAny>,
    coro_send: Py<PyAny>,
    coro_throw: Py<PyAny>,
    #[allow(unused)]
    coro_close: Py<PyAny>,
    wakeup: Py<PyCFunction>,
}

#[pymethods]
impl PyTask {
    #[new]
    #[pyo3(signature = (coro, *, r#loop))]
    fn new(py: Python, coro: Py<PyAny>, r#loop: Py<CompioLoop>) -> PyResult<Bound<Self>> {
        let base = PyFuture::new(r#loop);
        let bound_coro = coro.bind(py);
        if !import::iscoroutine(py, bound_coro)? {
            return Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(format!(
                "a coroutine was expected, got {}",
                bound_coro.repr()?.to_string()
            )));
        }
        let wakeup = wrap_pyfunction!(task_wakeup)(py)?.unbind();
        let slf = Self {
            coro_send: bound_coro.getattr("send")?.unbind(),
            coro_throw: bound_coro.getattr("throw")?.unbind(),
            coro_close: bound_coro.getattr("close")?.unbind(),
            coro,
            wakeup,
        };
        let initializer = PyClassInitializer::from(base).add_subclass(slf);
        Bound::new(py, initializer)
    }
}

impl PyTask {
    fn step(&mut self, slf: &Bound<Self>, py: Python, exc: Option<Py<PyAny>>) -> PyResult<()> {
        // Send or throw into the coroutine
        let result = if let Some(exc) = exc {
            // coro.throw(exc)
            self.coro_throw.bind(py).call1((exc,))
        } else {
            // coro.send(None)
            static TUP_NONE: PyOnceLock<Py<PyTuple>> = PyOnceLock::new();
            TUP_NONE
                .get_or_try_init(py, || PyTuple::new(py, vec![py.None()]).map(|b| b.unbind()))
                .and_then(|args| self.coro_send.bind(py).call(args, None))
        };
        match result {
            Ok(result) => match result.cast_into_exact() {
                Ok(fut) => self.step_compio_future(fut),
                Err(e) => self.step_python_obj(slf, py, e.into_inner()),
            },
            Err(e) => self.handle_coro_exception(slf, py, e),
        }
    }

    #[inline]
    fn step_compio_future(&mut self, fut: Bound<PyFuture>) -> PyResult<()> {
        // TODO: construct a proper Context with the event loop's waker
        let waker = Waker::noop();
        let mut cx = Context::from_waker(&waker);
        match fut.borrow_mut().poll(&mut cx) {
            Poll::Ready(Ok(_)) => Ok(cx.waker().wake_by_ref()),
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Ok(()),
        }
    }

    #[inline]
    fn step_python_obj(
        &mut self,
        slf: &Bound<Self>,
        py: Python,
        result: Bound<PyAny>,
    ) -> PyResult<()> {
        if result.is_instance_of::<PyFuture>() || result.is_instance(import::future_type(py)?)? {
            result.call_method1("add_done_callback", (&self.wakeup, slf))?;
        }
        Ok(())
    }

    #[inline]
    fn handle_coro_exception(&mut self, slf: &Bound<Self>, py: Python, err: PyErr) -> PyResult<()> {
        if err.is_instance_of::<PyStopIteration>(py) {
            let value = err.value(py).getattr("value")?.unbind();
            slf.as_super().borrow_mut().set_result(value);
            Ok(())
        } else if err.is_instance_of::<PyKeyboardInterrupt>(py)
            || err.is_instance_of::<PySystemExit>(py)
        {
            let value = err.value(py).as_any().clone();
            slf.as_super().borrow_mut().set_exception(value);
            Err(err)
        } else {
            Ok(())
        }
    }
}

#[allow(unused)]
pub fn step(task: &Bound<PyTask>) -> PyResult<()> {
    Python::attach(|py| task.borrow_mut().step(task, py, None))
}

#[pyfunction]
fn task_wakeup(_task: &PyTask) {}
