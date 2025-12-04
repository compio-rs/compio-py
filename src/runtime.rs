// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2025 Fantix King

use std::{
    cell::RefCell,
    collections::{BinaryHeap, VecDeque},
    io,
    sync::{
        Arc,
        atomic::{self, AtomicBool, AtomicUsize},
    },
    time::{Duration, Instant},
};

use compio::driver::{DriverType, Proactor};
use pyo3::{prelude::*, types::PyWeakrefReference};

use crate::handle::{Handle, TimerHandle};

/// Minimum number of _scheduled timer handles before cleanup of
/// cancelled handles is performed.
const MIN_SCHEDULED_TIMER_HANDLES: usize = 100;

/// Minimum fraction of _scheduled timer handles that are cancelled
/// before cleanup of cancelled handles is performed.
const MIN_CANCELLED_TIMER_HANDLES_FRACTION: f64 = 0.5;

/// Maximum timeout passed to select to avoid OS limitations
const MAXIMUM_SELECT_TIMEOUT: Duration = Duration::from_hours(24);

pub struct Runtime {
    #[allow(unused)]
    pyloop: Py<PyWeakrefReference>,
    epoch: Instant,
    stopping: Arc<AtomicBool>,
    driver: RefCell<Proactor>,
    ready: RefCell<VecDeque<Arc<Handle>>>,
    scheduled: RefCell<BinaryHeap<Arc<TimerHandle>>>,
    timer_cancelled_count: Arc<AtomicUsize>,
}

impl Runtime {
    pub fn new(pyloop: Py<PyWeakrefReference>, stopping: Arc<AtomicBool>) -> io::Result<Runtime> {
        Ok(Runtime {
            pyloop,
            epoch: Instant::now(),
            stopping,
            driver: RefCell::new(Proactor::new()?),
            ready: RefCell::new(VecDeque::new()),
            scheduled: RefCell::new(BinaryHeap::new()),
            timer_cancelled_count: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub fn driver_type(&self) -> DriverType {
        self.driver.borrow().driver_type()
    }

    #[inline]
    pub fn push_ready(&self, handle: Arc<Handle>) {
        self.ready.borrow_mut().push_back(handle);
    }

    #[inline]
    pub fn push_scheduled(&self, handle: Arc<TimerHandle>) {
        self.scheduled.borrow_mut().push(handle);
    }

    pub fn since_epoch(&self) -> Duration {
        Instant::now().duration_since(self.epoch)
    }

    pub fn timer_cancelled_count(&self) -> Arc<AtomicUsize> {
        self.timer_cancelled_count.clone()
    }

    #[inline(always)]
    fn run_once(&self) -> PyResult<()> {
        let sched_count = self.scheduled.borrow().len();
        if sched_count > MIN_SCHEDULED_TIMER_HANDLES
            && self.timer_cancelled_count.load(atomic::Ordering::Acquire) as f64
                / sched_count as f64
                > MIN_CANCELLED_TIMER_HANDLES_FRACTION
        {
            // Remove delayed calls that were cancelled if their number
            // is too high
            let mut new_scheduled = Vec::new();
            for handle in self.scheduled.take() {
                if !handle.cancelled() {
                    new_scheduled.push(handle);
                }
            }
            self.scheduled.replace(BinaryHeap::from(new_scheduled));
            self.timer_cancelled_count
                .store(0, atomic::Ordering::Release);
        } else {
            // Remove delayed calls that were cancelled from head of queue.
            let mut scheduled = self.scheduled.borrow_mut();
            while let Some(next_scheduled) = scheduled.peek() {
                if next_scheduled.cancelled() {
                    self.timer_cancelled_count
                        .fetch_sub(1, atomic::Ordering::AcqRel);
                    scheduled.pop();
                } else {
                    break;
                }
            }
        }

        let timeout =
            if !self.ready.borrow().is_empty() || self.stopping.load(atomic::Ordering::Acquire) {
                Some(Duration::default())
            } else if let Some(next_scheduled) = self.scheduled.borrow().peek() {
                Some(
                    Duration::from_secs_f64(next_scheduled.when())
                        .saturating_sub(self.since_epoch())
                        .min(MAXIMUM_SELECT_TIMEOUT),
                )
            } else {
                None
            };
        self.driver
            .borrow_mut()
            .poll(timeout)
            .or_else(|e| match e.kind() {
                io::ErrorKind::TimedOut => Ok(()),
                _ => Err(e),
            })?;

        // Handle 'later' callbacks that are ready.
        {
            let end_time = (self.since_epoch() + Duration::from_micros(1)).as_secs_f64();
            let mut scheduled = self.scheduled.borrow_mut();
            let mut ready = self.ready.borrow_mut();
            while let Some(next_scheduled) = scheduled.peek() {
                if next_scheduled.when() < end_time {
                    let next_scheduled = scheduled.pop().expect("not empty");
                    ready.push_back(next_scheduled.into_base());
                } else {
                    break;
                }
            }
        }

        // This is the only place where callbacks are actually *called*.
        // All other places just add them to ready.
        // Note: We run all currently scheduled callbacks, but not any
        // callbacks scheduled by callbacks run this time around --
        // they will be run the next time (after another I/O poll).
        // Use an idiom that is thread-safe without using locks.
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
            if self.stopping.load(atomic::Ordering::SeqCst) {
                break Ok(());
            }
        }
    }
}
