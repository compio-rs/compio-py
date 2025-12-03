// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2025 Fantix King

use std::{
    cell::RefCell, collections::VecDeque, io, sync::Arc, sync::atomic::AtomicBool, time::Duration,
};

use compio::driver::{DriverType, Proactor};
use pyo3::{prelude::*, types::PyWeakrefReference};

use crate::handle::Handle;

pub struct Runtime {
    #[allow(unused)]
    pyloop: Py<PyWeakrefReference>,
    stopping: Arc<AtomicBool>,
    driver: RefCell<Proactor>,
    ready: RefCell<VecDeque<Arc<Handle>>>,
}

impl Runtime {
    pub fn new(pyloop: Py<PyWeakrefReference>, stopping: Arc<AtomicBool>) -> io::Result<Runtime> {
        Ok(Runtime {
            pyloop,
            stopping,
            driver: RefCell::new(Proactor::new()?),
            ready: RefCell::new(VecDeque::new()),
        })
    }

    pub fn driver_type(&self) -> DriverType {
        self.driver.borrow().driver_type()
    }

    #[inline]
    pub fn push_ready(&self, handle: Arc<Handle>) {
        self.ready.borrow_mut().push_back(handle);
    }

    #[inline(always)]
    fn run_once(&self) -> PyResult<()> {
        let timeout = if self.ready.borrow().is_empty() {
            None
        } else {
            Some(Duration::default())
        };
        self.driver
            .borrow_mut()
            .poll(timeout)
            .or_else(|e| match e.kind() {
                io::ErrorKind::TimedOut => Ok(()),
                _ => Err(e),
            })?;

        let ntodo = self.ready.borrow().len();
        for _ in 0..ntodo {
            let handle = self.ready.borrow_mut().pop_front().expect("not empty");
            if !handle.cancelled() {
                handle.run()?;
            }
        }
        Ok(())
    }

    pub fn run(&self) -> PyResult<()> {
        loop {
            self.run_once()?;
            if self.stopping.load(std::sync::atomic::Ordering::SeqCst) {
                break Ok(());
            }
        }
    }
}
