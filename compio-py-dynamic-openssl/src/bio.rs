// This module is mostly copied and modified from:
// https://github.com/rust-openssl/rust-openssl/blob/openssl-v0.10.75/openssl/src/ssl/bio.rs
//
// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2017 Google Inc.
//           2013 Jack Lloyd
//           2013-2014 Steven Fackler
//
// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2026 Fantix King

use std::{
    any::Any,
    ffi::{c_char, c_int, c_long, c_void},
    io::{self, Read, Write},
    panic::{AssertUnwindSafe, catch_unwind},
    ptr, slice,
};

use crate::{
    error::ErrorStack,
    sys::{self as ffi, BIO},
};

pub struct StreamState<S> {
    pub stream: S,
    pub error: Option<io::Error>,
    pub panic: Option<Box<dyn Any + Send>>,
    pub dtls_mtu_size: c_long,
}

pub fn new<S: Read + Write>(stream: S) -> Result<(*mut BIO, BioMethod), ErrorStack> {
    let ffi = crate::get();
    let method = BioMethod::new::<S>()?;

    let state = Box::new(StreamState {
        stream,
        error: None,
        panic: None,
        dtls_mtu_size: 0,
    });

    unsafe {
        let bio = cvt_p((ffi.BIO_new)(method.0))?;
        (ffi.BIO_set_data)(bio, Box::into_raw(state) as _);
        (ffi.BIO_set_init)(bio, 1);

        Ok((bio, method))
    }
}

pub unsafe fn take_error<S>(bio: *mut BIO) -> Option<io::Error> {
    let state = unsafe { state::<S>(bio) };
    state.error.take()
}

pub unsafe fn take_panic<S>(bio: *mut BIO) -> Option<Box<dyn Any + Send>> {
    let state = unsafe { state::<S>(bio) };
    state.panic.take()
}

pub unsafe fn get_ref<'a, S: 'a>(bio: *mut BIO) -> &'a S {
    let ffi = crate::get();
    let state = unsafe { &*((ffi.BIO_get_data)(bio) as *const StreamState<S>) };
    &state.stream
}

pub unsafe fn get_mut<'a, S: 'a>(bio: *mut BIO) -> &'a mut S {
    &mut unsafe { state(bio) }.stream
}

unsafe fn state<'a, S: 'a>(bio: *mut BIO) -> &'a mut StreamState<S> {
    let ffi = crate::get();
    unsafe { &mut *((ffi.BIO_get_data)(bio) as *mut _) }
}

unsafe extern "C" fn bwrite<S: Write>(bio: *mut BIO, buf: *const c_char, len: c_int) -> c_int {
    let ffi = crate::get();
    unsafe { ffi.BIO_clear_retry_flags(bio) };

    let state = unsafe { state::<S>(bio) };
    let buf = unsafe { from_raw_parts(buf as *const _, len as usize) };

    match catch_unwind(AssertUnwindSafe(|| state.stream.write(buf))) {
        Ok(Ok(len)) => len as c_int,
        Ok(Err(err)) => {
            if retriable_error(&err) {
                unsafe { ffi.BIO_set_retry_write(bio) };
            }
            state.error = Some(err);
            -1
        }
        Err(err) => {
            state.panic = Some(err);
            -1
        }
    }
}

unsafe extern "C" fn bread<S: Read>(bio: *mut BIO, buf: *mut c_char, len: c_int) -> c_int {
    let ffi = crate::get();
    unsafe { ffi.BIO_clear_retry_flags(bio) };

    let state = unsafe { state::<S>(bio) };
    let buf = unsafe { from_raw_parts_mut(buf as *mut _, len as usize) };

    match catch_unwind(AssertUnwindSafe(|| state.stream.read(buf))) {
        Ok(Ok(len)) => len as c_int,
        Ok(Err(err)) => {
            if retriable_error(&err) {
                unsafe { ffi.BIO_set_retry_read(bio) };
            }
            state.error = Some(err);
            -1
        }
        Err(err) => {
            state.panic = Some(err);
            -1
        }
    }
}

fn retriable_error(err: &io::Error) -> bool {
    match err.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::NotConnected => true,
        _ => false,
    }
}

unsafe extern "C" fn bputs<S: Write>(bio: *mut BIO, s: *const c_char) -> c_int {
    unsafe {
        let mut len = 0;
        while *s.add(len) != 0 {
            len += 1;
        }
        bwrite::<S>(bio, s, len as c_int)
    }
}

unsafe extern "C" fn ctrl<S: Write>(
    bio: *mut BIO,
    cmd: c_int,
    _num: c_long,
    _ptr: *mut c_void,
) -> c_long {
    let state = unsafe { state::<S>(bio) };

    if cmd == ffi::BIO_CTRL_FLUSH {
        match catch_unwind(AssertUnwindSafe(|| state.stream.flush())) {
            Ok(Ok(())) => 1,
            Ok(Err(err)) => {
                state.error = Some(err);
                0
            }
            Err(err) => {
                state.panic = Some(err);
                0
            }
        }
    } else if cmd == ffi::BIO_CTRL_DGRAM_QUERY_MTU {
        state.dtls_mtu_size
    } else {
        0
    }
}

unsafe extern "C" fn create(bio: *mut BIO) -> c_int {
    let ffi = crate::get();
    unsafe {
        (ffi.BIO_set_init)(bio, 0);
        (ffi.BIO_set_data)(bio, ptr::null_mut());
        (ffi.BIO_set_flags)(bio, 0);
    }
    1
}

unsafe extern "C" fn destroy<S>(bio: *mut BIO) -> c_int {
    if bio.is_null() {
        return 0;
    }

    let ffi = crate::get();
    unsafe {
        let data = (ffi.BIO_get_data)(bio);
        assert!(!data.is_null());
        let _ = Box::<StreamState<S>>::from_raw(data as *mut _);
        (ffi.BIO_set_data)(bio, ptr::null_mut());
        (ffi.BIO_set_init)(bio, 0);
    }
    1
}

pub struct BioMethod(*mut ffi::BIO_METHOD);

impl BioMethod {
    fn new<S: Read + Write>() -> Result<Self, ErrorStack> {
        let ffi = crate::get();
        unsafe {
            let method = cvt_p((ffi.BIO_meth_new)(
                ffi::BIO_TYPE_NONE,
                b"compio\n".as_ptr() as _,
            ))?;
            cvt((ffi.BIO_meth_set_write)(method, Some(bwrite::<S>)))?;
            cvt((ffi.BIO_meth_set_read)(method, Some(bread::<S>)))?;
            cvt((ffi.BIO_meth_set_puts)(method, Some(bputs::<S>)))?;
            cvt((ffi.BIO_meth_set_ctrl)(method, Some(ctrl::<S>)))?;
            cvt((ffi.BIO_meth_set_create)(method, Some(create)))?;
            cvt((ffi.BIO_meth_set_destroy)(method, Some(destroy::<S>)))?;
            Ok(Self(method))
        }
    }
}

impl Drop for BioMethod {
    fn drop(&mut self) {
        let ffi = crate::get();
        unsafe {
            (ffi.BIO_meth_free)(self.0);
        }
    }
}

pub(crate) unsafe fn from_raw_parts<'a, T>(data: *const T, len: usize) -> &'a [T] {
    if len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(data, len) }
    }
}

unsafe fn from_raw_parts_mut<'a, T>(data: *mut T, len: usize) -> &'a mut [T] {
    if len == 0 {
        &mut []
    } else {
        unsafe { slice::from_raw_parts_mut(data, len) }
    }
}

#[inline]
pub(crate) fn cvt_p<T>(r: *mut T) -> Result<*mut T, ErrorStack> {
    if r.is_null() {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

#[inline]
pub(crate) fn cvt(r: c_int) -> Result<c_int, ErrorStack> {
    if r <= 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}
