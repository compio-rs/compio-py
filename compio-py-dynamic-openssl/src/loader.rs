// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2026 Fantix King

use std::{
    ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_void},
    sync::OnceLock,
};

use libloading::{AsFilename, Library};

use crate::sys::*;

static OPENSSL: OnceLock<OpenSSL> = OnceLock::new();

pub enum Error {
    Loader(libloading::Error),
    AlreadyLoaded,
    VersionTooOld,
}

impl From<libloading::Error> for Error {
    fn from(value: libloading::Error) -> Self {
        Self::Loader(value)
    }
}

#[allow(bad_style)]
pub struct OpenSSL {
    lib: Library,
    pub version_num: c_ulong,

    pub BIO_meth_new: unsafe extern "C" fn(type_: c_int, name: *const c_char) -> *mut BIO_METHOD,
    pub BIO_meth_free: unsafe extern "C" fn(biom: *mut BIO_METHOD),
    pub BIO_meth_set_write: unsafe extern "C" fn(
        biom: *mut BIO_METHOD,
        write: Option<unsafe extern "C" fn(*mut BIO, *const c_char, c_int) -> c_int>,
    ) -> c_int,
    pub BIO_meth_set_read: unsafe extern "C" fn(
        biom: *mut BIO_METHOD,
        read: Option<unsafe extern "C" fn(*mut BIO, *mut c_char, c_int) -> c_int>,
    ) -> c_int,
    pub BIO_meth_set_puts: unsafe extern "C" fn(
        biom: *mut BIO_METHOD,
        puts: Option<unsafe extern "C" fn(*mut BIO, *const c_char) -> c_int>,
    ) -> c_int,
    pub BIO_meth_set_ctrl: unsafe extern "C" fn(
        biom: *mut BIO_METHOD,
        ctrl: Option<unsafe extern "C" fn(*mut BIO, c_int, c_long, *mut c_void) -> c_long>,
    ) -> c_int,
    pub BIO_meth_set_create: unsafe extern "C" fn(
        biom: *mut BIO_METHOD,
        create: Option<unsafe extern "C" fn(*mut BIO) -> c_int>,
    ) -> c_int,
    pub BIO_meth_set_destroy: unsafe extern "C" fn(
        biom: *mut BIO_METHOD,
        destroy: Option<unsafe extern "C" fn(*mut BIO) -> c_int>,
    ) -> c_int,

    pub BIO_new: unsafe extern "C" fn(type_: *const BIO_METHOD) -> *mut BIO,
    pub BIO_get_data: unsafe extern "C" fn(b: *mut BIO) -> *mut c_void,
    pub BIO_set_data: unsafe extern "C" fn(b: *mut BIO, data: *mut c_void),
    pub BIO_set_init: unsafe extern "C" fn(b: *mut BIO, init: c_int),
    pub BIO_set_flags: unsafe extern "C" fn(b: *mut BIO, flags: c_int),
    pub BIO_clear_flags: unsafe extern "C" fn(b: *mut BIO, flags: c_int),

    pub SSL_new: unsafe extern "C" fn(ctx: *mut SSL_CTX) -> *mut SSL,
    pub SSL_free: unsafe extern "C" fn(ssl: *mut SSL),
    pub SSL_connect: unsafe extern "C" fn(ssl: *mut SSL) -> i32,
    pub SSL_accept: unsafe extern "C" fn(ssl: *mut SSL) -> c_int,
    pub SSL_ctrl:
        unsafe extern "C" fn(ssl: *mut SSL, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long,
    pub SSL_do_handshake: unsafe extern "C" fn(ssl: *mut SSL) -> c_int,
    pub SSL_set_bio: unsafe extern "C" fn(ssl: *mut SSL, rbio: *mut BIO, wbio: *mut BIO),
    pub SSL_get_rbio: unsafe extern "C" fn(ssl: *mut SSL) -> *mut BIO,
    pub SSL_get_error: unsafe extern "C" fn(ssl: *mut SSL, ret: c_int) -> c_int,
    pub SSL_read_ex: unsafe extern "C" fn(
        ssl: *mut SSL,
        buf: *mut c_void,
        num: usize,
        readbytes: *mut usize,
    ) -> c_int,
    pub SSL_write_ex: unsafe extern "C" fn(
        ssl: *mut SSL,
        buf: *const c_void,
        num: usize,
        written: *mut usize,
    ) -> c_int,
    pub SSL_get0_alpn_selected:
        unsafe extern "C" fn(s: *const SSL, data: *mut *const c_uchar, len: *mut c_uint),
    pub SSL_get0_param: unsafe extern "C" fn(ssl: *mut SSL) -> *mut X509_VERIFY_PARAM,
    pub SSL_shutdown: unsafe extern "C" fn(*mut SSL) -> c_int,

    pub X509_VERIFY_PARAM_set1_host: unsafe extern "C" fn(
        param: *mut X509_VERIFY_PARAM,
        name: *const c_char,
        namelen: isize,
    ) -> c_int,
    pub X509_VERIFY_PARAM_set1_ip: unsafe extern "C" fn(
        param: *mut X509_VERIFY_PARAM,
        ip: *const c_uchar,
        iplen: isize,
    ) -> c_int,

    pub ERR_get_error_all: Option<
        unsafe extern "C" fn(
            file: *mut *const c_char,
            line: *mut c_int,
            func: *mut *const c_char,
            data: *mut *const c_char,
            flags: *mut c_int,
        ) -> c_ulong,
    >,
    pub ERR_get_error_line_data: Option<
        unsafe extern "C" fn(
            file: *mut *const c_char,
            line: *mut c_int,
            data: *mut *const c_char,
            flags: *mut c_int,
        ) -> c_ulong,
    >,
    pub ERR_func_error_string: Option<unsafe extern "C" fn(err: c_ulong) -> *const c_char>,
    pub ERR_lib_error_string: unsafe extern "C" fn(err: c_ulong) -> *const c_char,
    pub ERR_reason_error_string: unsafe extern "C" fn(err: c_ulong) -> *const c_char,
}

impl OpenSSL {
    fn load(filename: impl AsFilename) -> Result<Self, Error> {
        let lib = {
            #[cfg(windows)]
            {
                libloading::os::windows::Library::open_already_loaded(filename)?
            }
            #[cfg(unix)]
            {
                cfg_if::cfg_if! {
                    if #[cfg(any(
                        target_os = "linux",
                        target_os = "android",
                        target_os = "emscripten",
                        target_os = "solaris",
                        target_os = "illumos",
                        target_os = "fuchsia",
                        target_os = "hurd",
                    ))] {
                        const RTLD_NOLOAD: c_int = 0x4;
                    } else if #[cfg(any(
                        target_os = "macos",
                        target_os = "ios",
                        target_os = "tvos",
                        target_os = "visionos",
                        target_os = "watchos",
                        target_os = "cygwin",
                    ))] {
                        const RTLD_NOLOAD: c_int = 0x10;
                    } else if #[cfg(any(
                        target_os = "freebsd",
                        target_os = "dragonfly",
                        target_os = "netbsd",
                    ))] {
                        const RTLD_NOLOAD: c_int = 0x2000;
                    } else {
                        compile_error!(
                            "Target has no known `RTLD_NOLOAD` value. Please submit an issue or PR adding it."
                        );
                    }
                }
                unsafe { libloading::os::unix::Library::open(Some(filename), RTLD_NOLOAD)? }
            }
        };

        let mut rv = Self {
            BIO_meth_new: *unsafe { lib.get(b"BIO_meth_new")? },
            BIO_meth_free: *unsafe { lib.get(b"BIO_meth_free")? },
            BIO_meth_set_write: *unsafe { lib.get(b"BIO_meth_set_write")? },
            BIO_meth_set_read: *unsafe { lib.get(b"BIO_meth_set_read")? },
            BIO_meth_set_puts: *unsafe { lib.get(b"BIO_meth_set_puts")? },
            BIO_meth_set_ctrl: *unsafe { lib.get(b"BIO_meth_set_ctrl")? },
            BIO_meth_set_create: *unsafe { lib.get(b"BIO_meth_set_create")? },
            BIO_meth_set_destroy: *unsafe { lib.get(b"BIO_meth_set_destroy")? },

            BIO_new: *unsafe { lib.get(b"BIO_new")? },
            BIO_get_data: *unsafe { lib.get(b"BIO_get_data")? },
            BIO_set_data: *unsafe { lib.get(b"BIO_set_data")? },
            BIO_set_init: *unsafe { lib.get(b"BIO_set_init")? },
            BIO_set_flags: *unsafe { lib.get(b"BIO_set_flags")? },
            BIO_clear_flags: *unsafe { lib.get(b"BIO_clear_flags")? },

            SSL_new: *unsafe { lib.get(b"SSL_new")? },
            SSL_free: *unsafe { lib.get(b"SSL_free")? },
            SSL_connect: *unsafe { lib.get(b"SSL_connect")? },
            SSL_accept: *unsafe { lib.get(b"SSL_accept")? },
            SSL_ctrl: *unsafe { lib.get(b"SSL_ctrl")? },
            SSL_do_handshake: *unsafe { lib.get(b"SSL_do_handshake")? },
            SSL_set_bio: *unsafe { lib.get(b"SSL_set_bio")? },
            SSL_get_rbio: *unsafe { lib.get(b"SSL_get_rbio")? },
            SSL_get_error: *unsafe { lib.get(b"SSL_get_error")? },
            SSL_read_ex: *unsafe { lib.get(b"SSL_read_ex")? },
            SSL_write_ex: *unsafe { lib.get(b"SSL_write_ex")? },
            SSL_get0_alpn_selected: *unsafe { lib.get(b"SSL_get0_alpn_selected")? },
            SSL_get0_param: *unsafe { lib.get(b"SSL_get0_param")? },
            SSL_shutdown: *unsafe { lib.get(b"SSL_shutdown")? },

            X509_VERIFY_PARAM_set1_host: *unsafe { lib.get(b"X509_VERIFY_PARAM_set1_host")? },
            X509_VERIFY_PARAM_set1_ip: *unsafe { lib.get(b"X509_VERIFY_PARAM_set1_ip")? },

            ERR_get_error_all: None,
            ERR_get_error_line_data: None,
            ERR_func_error_string: None,
            ERR_lib_error_string: *unsafe { lib.get(b"ERR_lib_error_string")? },
            ERR_reason_error_string: *unsafe { lib.get(b"ERR_reason_error_string")? },

            version_num: unsafe {
                lib.get::<unsafe extern "C" fn() -> c_ulong>(b"OpenSSL_version_num")?()
            },

            lib: lib.into(),
        };
        if rv.version_num < 0x10100010 {
            return Err(Error::VersionTooOld);
        }
        if rv.version_num < 0x30000000 {
            rv.ERR_get_error_line_data = Some(*unsafe { rv.lib.get(b"ERR_get_error_line_data")? });
            rv.ERR_func_error_string = Some(*unsafe { rv.lib.get(b"ERR_func_error_string")? });
        } else {
            rv.ERR_get_error_all = Some(*unsafe { rv.lib.get(b"ERR_get_error_all")? });
        }
        Ok(rv)
    }
}

pub fn is_loaded() -> bool {
    OPENSSL.get().is_some()
}

pub fn load(filename: impl AsFilename) -> Result<(), Error> {
    if is_loaded() {
        return Err(Error::AlreadyLoaded);
    }
    OPENSSL
        .set(OpenSSL::load(filename)?)
        .map_err(|_| Error::AlreadyLoaded)
}

pub fn get() -> &'static OpenSSL {
    OPENSSL.get().expect("OpenSSL library not loaded")
}
