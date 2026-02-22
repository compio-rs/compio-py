// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2026 Fantix King

use std::{
    io,
    net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4},
};

use compio::{
    buf::{BufResult, IntoInner, IoBuf, IoBufMut, buf_try},
    driver::{
        AsRawFd, ToSharedFd, impl_raw_fd,
        op::{BufResultExt, CloseSocket, Connect, Recv, Send, ShutdownSocket},
    },
};
use pyo3::{
    IntoPyObjectExt,
    buffer::PyBuffer,
    exceptions::{PyOSError, PyTypeError, PyValueError},
    prelude::*,
    types::{PyByteArray, PyBytes, PyList, PyTuple},
};
use socket2::{Domain, Protocol, SockAddr, Socket as Socket2, Type};

use crate::{
    event_loop::CompioLoop,
    import,
    runtime::{self, Attacher},
};

#[pyclass(unsendable, name = "Socket")]
pub struct PySocket {
    pyloop: Py<CompioLoop>,
    domain: Domain,
    ty: Type,
    protocol: Option<Protocol>,
    inner: Option<Socket>,
    bound: bool,
}

impl PySocket {
    pub async fn new(
        pyloop: Py<CompioLoop>,
        domain: Domain,
        ty: Type,
        protocol: Option<Protocol>,
    ) -> PyResult<Py<PyAny>> {
        let inner = Some(Socket::new(domain, ty, protocol).await?);
        Python::attach(|py| {
            Bound::new(
                py,
                Self {
                    pyloop,
                    domain,
                    ty,
                    protocol,
                    inner,
                    bound: false,
                },
            )?
            .into_py_any(py)
        })
    }

    #[inline]
    fn inner(&self) -> PyResult<&Socket> {
        self.inner
            .as_ref()
            .ok_or_else(|| PyOSError::new_err("socket is closed"))
    }
}

#[pymethods]
impl PySocket {
    fn __repr__(&self) -> PyResult<String> {
        if let Some(inner) = &self.inner {
            let fd = inner.as_raw_fd();
            let family = i32::from(self.domain);
            let ty = i32::from(self.ty);
            let proto = self.protocol.map(i32::from).unwrap_or_default();
            let laddr = match inner.socket.local_addr() {
                Ok(addr) => match addr.as_socket() {
                    Some(addr) => format!(", laddr={addr}"),
                    None => unimplemented!("unix socket"),
                },
                Err(_) => "".to_string(),
            };
            Ok(format!(
                "<compio.Socket fd={fd:?}, family={family}, type={ty}, protocol={proto}{laddr}>"
            ))
        } else {
            Ok("<compio.Socket (closed)>".to_string())
        }
    }

    #[pyo3(signature = (address, /))]
    fn connect<'py>(&mut self, py: Python<'py>, address: Py<PyAny>) -> PyResult<Bound<'py, PyAny>> {
        self.pyloop.bind(py).borrow().spawn_py(py, async move {
            let Some(inner) = &self.inner else {
                return Err(PyOSError::new_err("socket is closed"));
            };
            match self.domain {
                Domain::IPV4 => {
                    let (result, port) = Python::attach(|py| {
                        let (host, port): (Bound<PyAny>, u16) = address.extract(py)?;
                        idna_converter(&host, |name| {
                            // https://github.com/rust-lang/rust/issues/101035
                            match str::from_utf8(name)?.parse::<Ipv4Addr>() {
                                Ok(ip) => Ok((Ok(ip), port)),
                                Err(_) => Ok((Err(name.to_owned()), port)),
                            }
                        })
                    })?;
                    let ip = match result {
                        Ok(ip) => ip,
                        Err(name) => name_to_ip(name, self.domain).await?.parse()?,
                    };
                    if cfg!(windows) && !self.bound {
                        inner
                            .socket
                            .bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into())?;
                        self.bound = true;
                    }
                    let addr = SocketAddr::new(ip.into(), port).into();
                    inner.connect_async(&addr).await?;
                    self.bound = true;
                }
                _ => unimplemented!(),
            };
            Python::attach(|py| py.None().into_py_any(py))
        })
    }

    #[pyo3(signature = (bufsize, flags = 0, /))]
    fn recv<'py>(
        &self,
        py: Python<'py>,
        bufsize: usize,
        flags: i32,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.pyloop.bind(py).borrow().spawn_py(py, async move {
            let inner = self.inner()?;
            let buf = Vec::with_capacity(bufsize);
            let result = inner.recv(buf, flags).await;
            let bytes_read = result.0?;
            let mut buf = result.1;
            buf.truncate(bytes_read);
            Python::attach(|py| PyBytes::new(py, &buf).into_py_any(py))
        })
    }

    #[pyo3(signature = (data, flags = 0, /))]
    fn send<'py>(
        &self,
        py: Python<'py>,
        data: Py<PyAny>,
        flags: i32,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.pyloop.bind(py).borrow().spawn_py(py, async move {
            let inner = self.inner()?;
            let buf = Python::attach(|py| {
                let pybuf: PyBuffer<u8> = PyBuffer::get(data.bind(py))?;
                if pybuf.is_c_contiguous() {
                    let ptr = pybuf.buf_ptr() as *mut u8;
                    let len = pybuf.len_bytes();
                    Ok(Ok(unsafe { std::slice::from_raw_parts(ptr, len) }))
                } else {
                    pybuf.to_vec(py).map(|buf| Err(buf))
                }
            })?;
            let bytes_written = match buf {
                Ok(buf) => inner.send(buf, flags).await.0?,
                Err(buf) => inner.send(buf, flags).await.0?,
            };
            drop(data);
            Python::attach(|py| bytes_written.into_py_any(py))
        })
    }

    #[pyo3(signature = (how, /))]
    fn shutdown<'py>(&self, py: Python<'py>, how: i32) -> PyResult<Bound<'py, PyAny>> {
        self.pyloop.bind(py).borrow().spawn_py(py, async move {
            let inner = self.inner()?;
            let how = Python::attach(|py| {
                if how == import::socket::shut_wr(py)? {
                    Ok(Shutdown::Write)
                } else if how == import::socket::shut_rd(py)? {
                    Ok(Shutdown::Read)
                } else if how == import::socket::shut_rdwr(py)? {
                    Ok(Shutdown::Both)
                } else {
                    return Err(PyValueError::new_err(format!(
                        "invalid shutdown how: {how}"
                    )));
                }
            })?;
            inner.shutdown(how).await?;
            Python::attach(|py| py.None().into_py_any(py))
        })
    }

    fn close<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        self.pyloop.bind(py).borrow().spawn_py(py, async move {
            if let Some(inner) = self.inner.take() {
                inner.close().await?;
            };
            Python::attach(|py| py.None().into_py_any(py))
        })
    }
}

async fn name_to_ip(name: Vec<u8>, family: impl Into<i32>) -> PyResult<String> {
    let family = family.into();
    runtime::asyncify(move || {
        Python::attach(|py| {
            let args = (name, py.None(), family);
            let result_list: Bound<PyList> =
                import::socket::getaddrinfo(py, args, None)?.cast_into()?;
            let result: Bound<PyTuple> = result_list.get_item(0)?.cast_into()?;
            let addr: Bound<PyTuple> = result.get_item(result.len() - 1)?.cast_into()?;
            addr.get_item(0)?.extract()
        })
    })
    .await
}

fn idna_converter<T, F>(obj: &Bound<PyAny>, f: F) -> PyResult<T>
where
    F: FnOnce(&[u8]) -> PyResult<T>,
{
    if let Ok(bytes) = obj.cast::<PyBytes>() {
        f(bytes.as_bytes())
    } else if let Ok(bytes) = obj.cast::<PyByteArray>() {
        f(unsafe { bytes.as_bytes() })
    } else if let Ok(str) = obj.extract::<&str>() {
        if str.is_ascii() {
            f(str.as_bytes())
        } else {
            f(obj
                .call_method1("encode", ("idna",))?
                .cast::<PyBytes>()?
                .as_bytes())
        }
    } else {
        Err(PyTypeError::new_err(format!(
            "str, bytes or bytearray expected, not {}",
            obj.get_type()
        )))
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PySocket>()?;
    Ok(())
}

// Socket is copied and modified from compio-net:
// https://github.com/compio-rs/compio/blob/8cf1b4db78c93f37d462b85bd1f445caa7fca4d5/compio-net/src/socket.rs
// Copyright (c) 2023 Berrysoft

#[derive(Clone)]
struct Socket {
    socket: Attacher<Socket2>,
}

impl Socket {
    fn from_socket2(socket: Socket2) -> io::Result<Self> {
        let socket = Attacher::new(socket)?;
        Ok(Self { socket })
    }

    async fn new(domain: Domain, ty: Type, protocol: Option<Protocol>) -> io::Result<Self> {
        Self::from_socket2({
            #[cfg(windows)]
            {
                runtime::asyncify(move || Socket2::new(domain, ty, protocol)).await?
            }
            #[cfg(unix)]
            {
                use compio::driver::op::CreateSocket;

                let op = CreateSocket::new(
                    domain.into(),
                    ty.into(),
                    protocol.map(|p| p.into()).unwrap_or_default(),
                );
                let (_, op) = buf_try!(@try runtime::execute(op).await);
                op.into_inner()
            }
        })
    }

    async fn connect_async(&self, addr: &SockAddr) -> io::Result<()> {
        let op = Connect::new(self.to_shared_fd(), addr.clone());
        let (_, _op) = buf_try!(@try runtime::execute(op).await);
        #[cfg(windows)]
        _op.update_context()?;
        Ok(())
    }

    async fn recv<B: IoBufMut>(&self, buffer: B, flags: i32) -> BufResult<usize, B> {
        let fd = self.to_shared_fd();
        let op = Recv::new(fd, buffer, flags);
        let res = runtime::execute(op).await.into_inner();
        unsafe { res.map_advanced() }
    }

    async fn send<T: IoBuf>(&self, buffer: T, flags: i32) -> BufResult<usize, T> {
        let fd = self.to_shared_fd();
        let op = Send::new(fd, buffer, flags);
        runtime::execute(op).await.into_inner()
    }

    async fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        let fd = self.to_shared_fd();
        let op = ShutdownSocket::new(fd, how);
        runtime::execute(op).await.0?;
        Ok(())
    }

    async fn close(self) -> io::Result<()> {
        let fd = self.socket.into_inner().take().await;
        if let Some(fd) = fd {
            let op = CloseSocket::new(fd.into());
            runtime::execute(op).await.0?;
        }
        Ok(())
    }
}

impl_raw_fd!(Socket, Socket2, socket, socket);
