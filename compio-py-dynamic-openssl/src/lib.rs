// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2026 Fantix King

use std::{
    ffi::OsStr,
    io::{Read, Write},
    net::IpAddr,
};

use compio_log::debug;
pub use pyo3;
use pyo3::{
    ffi::{PyObject, c_str},
    prelude::*,
    types::PyDict,
};

use self::{
    loader::get,
    ssl::{HandshakeError, Ssl, SslStream},
    sys as ffi,
};

pub mod bio;
pub mod error;
pub mod loader;
pub mod ssl;
pub mod sys;

pub struct SSLContext {
    ptr: *mut ffi::SSL_CTX,
    pyobj: Py<PyAny>,
}

impl TryFrom<Bound<'_, PyAny>> for SSLContext {
    type Error = PyErr;

    fn try_from(obj: Bound<PyAny>) -> PyResult<Self> {
        #[repr(C)]
        struct PySSLContext {
            ob_base: PyObject,
            ctx: *mut ffi::SSL_CTX,
        }

        unsafe {
            let ptr = obj.as_ptr() as *const PySSLContext;
            let ptr = (*ptr).ctx;
            if ptr.is_null() {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "SSLContext has null SSL_CTX",
                ));
            }
            Ok(Self {
                ptr,
                pyobj: obj.unbind(),
            })
        }
    }
}

impl SSLContext {
    pub fn connect<S>(&self, domain: &str, stream: S) -> Result<SslStream<S>, HandshakeError<S>>
    where
        S: Read + Write,
    {
        let mut ssl = Ssl::new(self.ptr)?;
        let ip = domain.parse::<IpAddr>().ok();
        if ip.is_none() {
            ssl.set_hostname(domain)?;
        }
        let res = Python::attach(|py| {
            self.pyobj
                .bind(py)
                .getattr("check_hostname")?
                .extract::<bool>()
        });
        match res {
            Ok(true) => {
                let param = ssl.param_mut();
                match ip {
                    Some(ip) => param.set_ip(ip)?,
                    None => param.set_host(domain)?,
                }
            }
            Ok(false) => {}
            Err(e) => panic!("{e}"),
        }

        ssl.connect(stream)
    }

    pub fn accept<S>(&self, stream: S) -> Result<SslStream<S>, HandshakeError<S>>
    where
        S: Read + Write,
    {
        let ssl = Ssl::new(self.ptr)?;
        ssl.accept(stream)
    }
}

impl Clone for SSLContext {
    fn clone(&self) -> Self {
        Python::attach(|py| Self {
            ptr: self.ptr,
            pyobj: self.pyobj.clone_ref(py),
        })
    }
}

pub fn load_py(py: Python) -> PyResult<bool> {
    if loader::is_loaded() {
        return Ok(true);
    }

    let find_lib = c_str!(
        r#"
import inspect, ssl
try:
    lib = inspect.getfile(ssl.SSLSession)
except TypeError:
    import os, sysconfig
    lib = os.path.join(sysconfig.get_config_var("LIBDIR"), sysconfig.get_config_var("LDLIBRARY"))
"#
    );
    let locals = PyDict::new(py);
    py.run(find_lib, None, Some(&locals))?;
    let lib = locals
        .get_item("lib")?
        .expect("defined lib")
        .extract::<String>()?;
    match py.detach(|| loader::load(OsStr::new(&lib))) {
        Ok(()) => Ok(true),
        Err(loader::Error::AlreadyLoaded) => Ok(true),
        Err(loader::Error::LibraryNotFound) => {
            debug!("Failed to load OpenSSL: library not found");
            Ok(false)
        }
        Err(loader::Error::IoError(_e)) => {
            debug!("Failed to load OpenSSL: {_e}");
            Ok(false)
        }
        Err(loader::Error::VersionTooOld) => {
            debug!("Failed to load OpenSSL: version is too old");
            Ok(false)
        }
        Err(loader::Error::Loader(_e)) => {
            debug!("Failed to load OpenSSL: {_e}");
            Ok(false)
        }
        #[cfg(windows)]
        Err(loader::Error::PE(_e)) => {
            debug!("Failed to load OpenSSL: {_e}");
            Ok(false)
        }
    }
}
