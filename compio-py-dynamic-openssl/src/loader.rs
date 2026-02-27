// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2026 Fantix King

use std::{
    ffi::{OsStr, c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_void},
    io,
    sync::OnceLock,
};

use libloading::{Library, Symbol};

use crate::sys::*;

static OPENSSL: OnceLock<OpenSSL> = OnceLock::new();

pub enum Error {
    IoError(io::Error),
    Loader(libloading::Error),
    #[cfg(windows)]
    PE(pelite::Error),
    LibraryNotFound,
    AlreadyLoaded,
    VersionTooOld,
}

impl From<libloading::Error> for Error {
    fn from(value: libloading::Error) -> Self {
        Self::Loader(value)
    }
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::IoError(value)
    }
}

#[cfg(windows)]
impl From<pelite::Error> for Error {
    fn from(value: pelite::Error) -> Self {
        Self::PE(value)
    }
}

#[allow(bad_style)]
pub struct OpenSSL {
    lib: OsslLibraries,
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

struct OsslLibraries(Vec<Library>);

impl OsslLibraries {
    #[cfg(windows)]
    fn from(filename: &OsStr) -> Result<Self, Error> {
        use std::{ffi::OsString, fs, os::windows::ffi::OsStringExt, path::Path};

        use pelite::pe::{Pe, PeFile};
        use windows_sys::Win32::{
            Foundation::MAX_PATH,
            System::ProcessStatus::{EnumProcessModules, GetModuleFileNameExW},
        };

        // Unlike UNIX platforms, Windows requires to load from the exact library
        // file containing the symbol, instead of e.g. _ssl.so. So we'll need to
        // look into _ssl.pyd import tables, find the DLL file names, and match it
        // with the currently-loaded DLLs for full paths of libcrypto and libssl.

        let mut linked_dlls = Vec::new();
        let file_data = fs::read(filename)?;
        let pe = PeFile::from_bytes(&file_data)?;
        if let Ok(imports) = pe.imports() {
            for desc in imports {
                if let Ok(dll_name) = desc.dll_name()
                    && let Ok(dll_name) = dll_name.to_str()
                {
                    let lower_name = dll_name.to_lowercase();
                    if lower_name.contains("ssl") || lower_name.contains("crypto") {
                        linked_dlls.push(OsString::from(lower_name));
                    }
                }
            }
        }

        let mut libs = Vec::new();
        let process = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() };
        let mut h_mods = vec![0isize; 1024];
        let mut cb_needed = 0u32;
        if unsafe {
            EnumProcessModules(
                process,
                h_mods.as_mut_ptr() as *mut _,
                (h_mods.len() * size_of::<isize>()) as u32,
                &mut cb_needed,
            )
        } != 0
        {
            let count = (cb_needed as usize) / size_of::<isize>();
            for i in 0..count {
                let mut sz_mod_name = vec![0u16; MAX_PATH as usize];
                if unsafe {
                    GetModuleFileNameExW(
                        process,
                        h_mods[i] as *mut _,
                        sz_mod_name.as_mut_ptr(),
                        MAX_PATH,
                    )
                } > 0
                {
                    let len = sz_mod_name
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(sz_mod_name.len());
                    let path = OsString::from_wide(&sz_mod_name[..len]);
                    if let Some(name) = Path::new(&path).file_name()
                        && linked_dlls.iter().any(|n| n == name)
                    {
                        let lib = libloading::os::windows::Library::open_already_loaded(path)?;
                        libs.push(lib.into());
                    }
                }
            }
        }
        Ok(Self(libs))
    }

    #[cfg(unix)]
    fn from(filename: &OsStr) -> Result<Self, Error> {
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
        unsafe {
            let lib = libloading::os::unix::Library::open(
                Some(filename),
                RTLD_NOLOAD | libloading::os::unix::RTLD_LAZY,
            )?;
            Ok(Self(vec![lib.into()]))
        }
    }

    pub unsafe fn get<T>(&self, symbol: &[u8]) -> Result<Symbol<'_, T>, Error> {
        let mut res = Err(Error::LibraryNotFound);
        for lib in self.0.iter() {
            match unsafe { lib.get::<T>(symbol) } {
                Ok(sym) => return Ok(sym),
                Err(e) => res = Err(e.into()),
            }
        }
        res
    }
}

impl OpenSSL {
    fn load(filename: &OsStr) -> Result<Self, Error> {
        let lib = OsslLibraries::from(filename)?;

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

            lib,
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

pub fn load(filename: &OsStr) -> Result<(), Error> {
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
