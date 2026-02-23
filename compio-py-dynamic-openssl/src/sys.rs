// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2026 Fantix King

use std::ffi::{c_char, c_int, c_long, c_ulong, c_void};

use crate::loader::OpenSSL;

pub const ERR_TXT_MALLOCED: c_int = 0x01;
pub const ERR_TXT_STRING: c_int = 0x02;
pub const ERR_LIB_SYS: c_int = 2;

pub const BIO_TYPE_NONE: c_int = 0;

pub const BIO_CTRL_FLUSH: c_int = 11;
pub const BIO_CTRL_DGRAM_QUERY_MTU: c_int = 40;

pub const BIO_FLAGS_READ: c_int = 0x01;
pub const BIO_FLAGS_WRITE: c_int = 0x02;
pub const BIO_FLAGS_IO_SPECIAL: c_int = 0x04;
pub const BIO_FLAGS_RWS: c_int = BIO_FLAGS_READ | BIO_FLAGS_WRITE | BIO_FLAGS_IO_SPECIAL;
pub const BIO_FLAGS_SHOULD_RETRY: c_int = 0x08;

pub const SSL_ERROR_SSL: c_int = 1;
pub const SSL_ERROR_SYSCALL: c_int = 5;
pub const SSL_ERROR_WANT_READ: c_int = 2;
pub const SSL_ERROR_WANT_WRITE: c_int = 3;
pub const SSL_ERROR_ZERO_RETURN: c_int = 6;
pub const SSL_ERROR_WANT_CLIENT_HELLO_CB: c_int = 11;

pub const SSL_CTRL_SET_TLSEXT_HOSTNAME: c_int = 55;

#[allow(bad_style)]
pub const TLSEXT_NAMETYPE_host_name: c_int = 0;

#[allow(bad_style)]
pub enum BIO_METHOD {}

pub enum BIO {}

#[allow(bad_style)]
pub enum SSL_CTX {}

pub enum SSL {}

#[allow(bad_style)]
pub enum X509_VERIFY_PARAM {}

#[allow(bad_style)]
impl OpenSSL {
    pub unsafe fn BIO_set_retry_read(&self, b: *mut BIO) {
        unsafe { (self.BIO_set_flags)(b, BIO_FLAGS_READ | BIO_FLAGS_SHOULD_RETRY) }
    }

    pub unsafe fn BIO_set_retry_write(&self, b: *mut BIO) {
        unsafe { (self.BIO_set_flags)(b, BIO_FLAGS_WRITE | BIO_FLAGS_SHOULD_RETRY) }
    }

    pub unsafe fn BIO_clear_retry_flags(&self, b: *mut BIO) {
        unsafe { (self.BIO_clear_flags)(b, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY) }
    }

    pub unsafe fn SSL_set_tlsext_host_name(&self, s: *mut SSL, name: *mut c_char) -> c_long {
        unsafe {
            (self.SSL_ctrl)(
                s,
                SSL_CTRL_SET_TLSEXT_HOSTNAME,
                TLSEXT_NAMETYPE_host_name as c_long,
                name as *mut c_void,
            )
        }
    }

    pub unsafe fn ERR_get_error_all(
        &self,
        file: *mut *const c_char,
        line: *mut c_int,
        func: *mut *const c_char,
        data: *mut *const c_char,
        flags: *mut c_int,
    ) -> c_ulong {
        if self.version_num < 0x30000000 {
            unsafe {
                let code = self
                    .ERR_get_error_line_data
                    .expect("OpenSSL 1.x should have ERR_get_error_line_data")(
                    file, line, data, flags,
                );
                *func = self
                    .ERR_func_error_string
                    .expect("OpenSSL 1.x should have ERR_func_error_string")(
                    code
                );
                code
            }
        } else {
            unsafe {
                self.ERR_get_error_all
                    .expect("OpenSSL 3.0 should have ERR_get_error_all")(
                    file, line, func, data, flags,
                )
            }
        }
    }

    pub const fn ERR_SYSTEM_ERROR(&self, errcode: c_ulong) -> bool {
        assert!(self.version_num >= 0x30000000);
        const ERR_SYSTEM_FLAG: c_ulong = c_int::MAX as c_ulong + 1;
        errcode & ERR_SYSTEM_FLAG != 0
    }

    pub const fn ERR_GET_LIB(&self, errcode: c_ulong) -> c_int {
        if self.version_num < 0x30000000 {
            ((errcode >> 24) & 0x0FF) as c_int
        } else {
            const ERR_LIB_OFFSET: c_ulong = 23;
            const ERR_LIB_MASK: c_ulong = 0xff;
            ((ERR_LIB_SYS as c_ulong * (self.ERR_SYSTEM_ERROR(errcode) as c_ulong))
                | (((errcode >> ERR_LIB_OFFSET) & ERR_LIB_MASK)
                    * (!self.ERR_SYSTEM_ERROR(errcode) as c_ulong))) as c_int
        }
    }

    pub const fn ERR_GET_FUNC(&self, errcode: c_ulong) -> c_int {
        if self.version_num < 0x30000000 {
            ((errcode >> 12) & 0xFFF) as c_int
        } else {
            0
        }
    }

    pub const fn ERR_GET_REASON(&self, errcode: c_ulong) -> c_int {
        if self.version_num < 0x30000000 {
            (errcode & 0xFFF) as c_int
        } else {
            const ERR_REASON_MASK: c_ulong = 0x7FFFFF;
            ((ERR_LIB_SYS as c_ulong * (self.ERR_SYSTEM_ERROR(errcode) as c_ulong))
                | ((errcode & ERR_REASON_MASK) * (!self.ERR_SYSTEM_ERROR(errcode) as c_ulong)))
                as c_int
        }
    }
}
