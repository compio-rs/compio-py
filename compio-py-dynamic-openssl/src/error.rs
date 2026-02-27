// This module is mostly copied and modified from:
// https://github.com/rust-openssl/rust-openssl/blob/openssl-v0.10.75/openssl/src/error.rs
//
// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2017 Google Inc.
//           2013 Jack Lloyd
//           2013-2014 Steven Fackler
//
// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2026 Fantix King

use std::{
    borrow::Cow,
    error,
    ffi::{CStr, CString, c_char, c_int, c_ulong},
    fmt, io, ptr,
};

use crate::sys as ffi;

type ErrType = c_ulong;

#[derive(Debug, Clone)]
pub struct ErrorStack(Vec<Error>);

impl ErrorStack {
    pub fn get() -> Self {
        let mut vec = vec![];
        while let Some(err) = Error::get() {
            vec.push(err);
        }
        ErrorStack(vec)
    }

    pub fn errors(&self) -> &[Error] {
        &self.0
    }
}

impl fmt::Display for ErrorStack {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return fmt.write_str("OpenSSL error");
        }

        let mut first = true;
        for err in &self.0 {
            if !first {
                fmt.write_str(", ")?;
            }
            write!(fmt, "{}", err)?;
            first = false;
        }
        Ok(())
    }
}

impl error::Error for ErrorStack {}

impl From<ErrorStack> for io::Error {
    fn from(e: ErrorStack) -> io::Error {
        io::Error::new(io::ErrorKind::Other, e)
    }
}

impl From<ErrorStack> for fmt::Error {
    fn from(_: ErrorStack) -> fmt::Error {
        fmt::Error
    }
}

#[derive(Clone)]
pub struct Error {
    code: ErrType,
    file: ShimStr,
    line: c_int,
    func: Option<ShimStr>,
    data: Option<Cow<'static, str>>,
}

unsafe impl Sync for Error {}
unsafe impl Send for Error {}

impl Error {
    pub fn get() -> Option<Self> {
        let ffi = crate::get();
        unsafe {
            let mut file = ptr::null();
            let mut line = 0;
            let mut func = ptr::null();
            let mut data = ptr::null();
            let mut flags = 0;
            match ffi.ERR_get_error_all(&mut file, &mut line, &mut func, &mut data, &mut flags) {
                0 => None,
                code => {
                    let data = if flags & ffi::ERR_TXT_STRING != 0 {
                        let bytes = CStr::from_ptr(data as *const _).to_bytes();
                        let data = str::from_utf8(bytes).unwrap();
                        let data = if flags & ffi::ERR_TXT_MALLOCED != 0 {
                            Cow::Owned(data.to_string())
                        } else {
                            Cow::Borrowed(data)
                        };
                        Some(data)
                    } else {
                        None
                    };

                    let file = ShimStr::new(file);

                    let func = if func.is_null() {
                        None
                    } else {
                        Some(ShimStr::new(func))
                    };

                    Some(Error {
                        code,
                        file,
                        line,
                        func,
                        data,
                    })
                }
            }
        }
    }

    pub fn code(&self) -> ErrType {
        self.code
    }

    pub fn library(&self) -> Option<&'static str> {
        let ffi = crate::get();
        unsafe {
            let cstr = (ffi.ERR_lib_error_string)(self.code);
            if cstr.is_null() {
                return None;
            }
            let bytes = CStr::from_ptr(cstr as *const _).to_bytes();
            Some(str::from_utf8(bytes).unwrap())
        }
    }

    pub fn library_code(&self) -> c_int {
        let ffi = crate::get();
        ffi.ERR_GET_LIB(self.code)
    }

    pub fn function(&self) -> Option<&str> {
        self.func.as_ref().map(|s| s.as_str())
    }

    pub fn reason(&self) -> Option<&'static str> {
        let ffi = crate::get();
        unsafe {
            let cstr = (ffi.ERR_reason_error_string)(self.code);
            if cstr.is_null() {
                return None;
            }
            let bytes = CStr::from_ptr(cstr as *const _).to_bytes();
            Some(str::from_utf8(bytes).unwrap())
        }
    }

    pub fn reason_code(&self) -> c_int {
        let ffi = crate::get();
        ffi.ERR_GET_REASON(self.code)
    }

    pub fn file(&self) -> &str {
        self.file.as_str()
    }

    pub fn line(&self) -> u32 {
        self.line as u32
    }

    pub fn data(&self) -> Option<&str> {
        self.data.as_ref().map(|s| &**s)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = fmt.debug_struct("Error");
        builder.field("code", &self.code());
        if let Some(library) = self.library() {
            builder.field("library", &library);
        }
        if let Some(function) = self.function() {
            builder.field("function", &function);
        }
        if let Some(reason) = self.reason() {
            builder.field("reason", &reason);
        }
        builder.field("file", &self.file());
        builder.field("line", &self.line());
        if let Some(data) = self.data() {
            builder.field("data", &data);
        }
        builder.finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "error:{:08X}", self.code())?;
        match self.library() {
            Some(l) => write!(fmt, ":{}", l)?,
            None => write!(fmt, ":lib({})", self.library_code())?,
        }
        match self.function() {
            Some(f) => write!(fmt, ":{}", f)?,
            None => write!(fmt, ":func({})", crate::get().ERR_GET_FUNC(self.code()))?,
        }
        match self.reason() {
            Some(r) => write!(fmt, ":{}", r)?,
            None => write!(fmt, ":reason({})", self.reason_code())?,
        }
        write!(
            fmt,
            ":{}:{}:{}",
            self.file(),
            self.line(),
            self.data().unwrap_or("")
        )
    }
}

impl error::Error for Error {}

#[derive(Clone)]
enum ShimStr {
    Owned(CString),
    Borrowed(*const c_char),
}

impl ShimStr {
    unsafe fn new(s: *const c_char) -> Self {
        if crate::get().version_num < 0x30000000 {
            ShimStr::Borrowed(s)
        } else {
            ShimStr::Owned(unsafe { CStr::from_ptr(s) }.to_owned())
        }
    }

    fn as_str(&self) -> &str {
        match self {
            ShimStr::Owned(s) => s.to_str().unwrap(),
            ShimStr::Borrowed(s) => unsafe { CStr::from_ptr(*s).to_str().unwrap() },
        }
    }
}
