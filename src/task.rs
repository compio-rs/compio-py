use async_task::Task;
use pyo3::{
    exceptions::{PyKeyboardInterrupt, PyStopIteration, PySystemExit},
    prelude::*,
    sync::PyOnceLock,
    types::PyTuple,
};

use crate::{
    event_loop::CompioLoop,
    future::{PyFuture, wait_future},
    import,
    owned::OwnedRefCell,
};

struct Coroutine {
    #[allow(unused)]
    coro: Py<PyAny>,
    coro_send: Py<PyAny>,
    coro_throw: Py<PyAny>,
    #[allow(unused)]
    coro_close: Py<PyAny>,
}

impl Coroutine {
    fn new(py: Python, coro: Py<PyAny>) -> PyResult<Self> {
        let bound_coro = coro.bind(py);
        if !import::iscoroutine(py, bound_coro)? {
            return Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(format!(
                "a coroutine was expected, got {}",
                bound_coro.repr()?.to_string()
            )));
        }
        Ok(Self {
            coro_send: bound_coro.getattr("send")?.unbind(),
            coro_throw: bound_coro.getattr("throw")?.unbind(),
            coro_close: bound_coro.getattr("close")?.unbind(),
            coro,
        })
    }

    async fn run(self, pytask: Py<PyTask>) -> PyResult<Py<PyAny>> {
        let mut exc = None;
        loop {
            eprintln!("Task step");
            match self.step(&pytask, exc.take()).await? {
                Ok(result) => {
                    eprintln!("Task finished");
                    break Ok(result);
                }
                Err(None) => {
                    eprintln!("Task continue");
                }
                Err(Some(e)) => {
                    eprintln!("Task exception");
                    exc = Some(e)
                }
            }
        }
    }

    async fn step(&self, pytask: &Py<PyTask>, exc: Option<Py<PyAny>>) -> PyResult<StepResult> {
        let partial: Result<_, Py<PyFuture>> = Python::attach(|py| {
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
            eprintln!("Coroutine step result: {:?}", result);
            match result {
                Ok(fut) => match fut.cast_into_exact() {
                    Ok(fut) => Err(fut.unbind()),
                    Err(e) => Ok(self.step_python_obj(pytask, py, e.into_inner())),
                },
                Err(e) => Ok(self.handle_coro_exception(pytask, py, e)),
            }
        });
        match partial {
            Ok(rv) => rv,
            Err(fut) => wait_future(fut)
                .await
                .map(|_result| {
                    // Python::attach(|py| pytask.bind(py).as_super().borrow_mut().set_result(result));
                    Err(None)
                })
                .or_else(|e| Ok(Err(Some(e)))),
        }
    }

    #[inline]
    fn step_python_obj(
        &self,
        _pytask: &Py<PyTask>,
        py: Python,
        result: Bound<PyAny>,
    ) -> PyResult<StepResult> {
        if result.is_instance_of::<PyFuture>() || result.is_instance(import::future_type(py)?)? {
            // result.call_method1("add_done_callback", (&self.wakeup, slf))?;
        }
        Ok(Err(None))
    }

    #[inline]
    fn handle_coro_exception(
        &self,
        pytask: &Py<PyTask>,
        py: Python,
        err: PyErr,
    ) -> PyResult<StepResult> {
        if err.is_instance_of::<PyStopIteration>(py) {
            let value = err.value(py).getattr("value")?.unbind();
            pytask
                .bind(py)
                .as_super()
                .borrow_mut()
                .set_result(value.clone_ref(py));
            Ok(Ok(value))
        } else if err.is_instance_of::<PyKeyboardInterrupt>(py)
            || err.is_instance_of::<PySystemExit>(py)
        {
            let value = err.value(py).as_any().clone();
            pytask
                .bind(py)
                .as_super()
                .borrow_mut()
                .set_exception(value)?;
            Err(err)
        } else {
            Ok(Err(Some(err.into_value(py).into_any())))
        }
    }
}

type StepResult = Result<Py<PyAny>, Option<Py<PyAny>>>;

#[pyclass(name = "Task", extends=PyFuture, weakref)]
pub struct PyTask {
    task: OwnedRefCell<Task<PyResult<Py<PyAny>>>>,
    #[allow(unused)]
    pycoro: Py<PyAny>,
}

#[pymethods]
impl PyTask {
    #[new]
    #[pyo3(signature = (coro, *, r#loop))]
    fn new(py: Python, coro: Py<PyAny>, r#loop: Py<CompioLoop>) -> PyResult<Bound<Self>> {
        let spawn = r#loop.borrow(py).runtime()?.spawner();
        let base = PyFuture::new(r#loop);
        let pycoro = coro.clone_ref(py);
        let coro = Coroutine::new(py, coro)?;
        let slf = Self {
            task: OwnedRefCell::default(),
            pycoro,
        };
        let initializer = PyClassInitializer::from(base).add_subclass(slf);
        let rv = Bound::new(py, initializer)?;
        let task = spawn(coro.run(rv.clone().unbind()));
        rv.borrow_mut().task.init(task).expect("same thread");
        Ok(rv)
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyTask>()?;
    Ok(())
}
