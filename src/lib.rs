use pyo3::prelude::*;

/// A Python module implemented in Rust. The name of this module must match
/// the `lib.name` setting in the `Cargo.toml`, else Python will not be able to
/// import the module.
#[pymodule]
mod _core {
    use compio::driver::Proactor;
    use pyo3::prelude::*;
    use pyo3::types::PyWeakrefReference;

    #[pyclass(unsendable)]
    pub struct Runtime {
        pyloop: Py<PyWeakrefReference>,
        driver: Proactor,
    }

    #[pymethods]
    impl Runtime {
        fn driver_type(&self) -> PyResult<String> {
            Ok(format!("{:?}", self.driver.driver_type()))
        }
    }

    #[pyfunction]
    fn make_runtime(pyloop: &Bound<PyAny>) -> PyResult<Runtime> {
        let pyloop = PyWeakrefReference::new(pyloop)?.unbind();
        let driver = Proactor::new()?;
        Ok(Runtime { pyloop, driver })
    }
}
