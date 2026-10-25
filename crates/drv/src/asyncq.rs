//! `driver_async`: jobs on the async thread pool and their `ready_async` completion.
//!
//! Port of erts/emulator/beam/erl_async.c (driver_async :541, driver_async_port_key
//! :518, async_main, call_async_ready :318) and io.c:5368 (async_ready), OTP-29.1.1.
//! A job runs `async_invoke` on the worker picked by its key, then `ready_async` runs
//! as auxiliary work of the scheduler that issued the job, with the port locked. If the port is gone by then, or the driver
//! has no `ready_async`, `async_free` releases the job data.

use std::ffi::{c_long, c_uint, c_void};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::thread::JoinHandle;

use crate::task::{call1, call2};
use crate::threads;
use crate::{DrvFn1, PortRef, REDS_INPUT};

/// Default `+A` of OTP 29: one async thread.
const DEFAULT_ASYNC_THREADS: usize = 1;

static CONFIGURED: AtomicUsize = AtomicUsize::new(DEFAULT_ASYNC_THREADS);
static NEXT_ID: AtomicI64 = AtomicI64::new(0);
static POOL: OnceLock<Pool> = OnceLock::new();

/// Set the number of async threads (`erts_async_max_threads`, `+A`); zero runs jobs on
/// the calling thread. It only takes effect before the first [`driver_async`] call.
pub fn set_async_threads(threads: usize) {
    CONFIGURED.store(threads, Ordering::Relaxed);
}

/// A queued `driver_async` request (`ErtsAsync`).
pub(crate) struct Job {
    port: PortRef,
    invoke: DrvFn1,
    data: usize,
    free: Option<DrvFn1>,
    /// The port data lock the job holds a reference on (`ErtsAsync.pdl`), zero when none.
    pdl: usize,
    /// Zero-based scheduler that issued the job (`a->sched_id - 1`).
    sched_id: usize,
}

struct Pool {
    queues: Vec<Mutex<Sender<AsyncMessage>>>,
    threads: Mutex<Vec<JoinHandle<()>>>,
    stopped: Mutex<bool>,
}

enum AsyncMessage {
    Job(Job),
    Exit,
}

fn pool() -> &'static Pool {
    POOL.get_or_init(|| {
        let mut queues = Vec::new();
        let mut threads = Vec::new();
        for index in 0..CONFIGURED.load(Ordering::Relaxed) {
            let (tx, rx) = channel::<AsyncMessage>();
            let handle = thread::Builder::new()
                .name(format!("arinsal-drv-async-{}", index + 1))
                .spawn(move || {
                    while let Ok(message) = rx.recv() {
                        let AsyncMessage::Job(job) = message else {
                            break;
                        };
                        call1(job.invoke, job.data as *mut c_void);
                        // Port of erl_async.c:227 (async_reply): the issuing
                        // scheduler runs ready_async as aux work.
                        let port = job.port.clone();
                        port.host
                            .schedule_async_ready(job.sched_id, Box::new(move || job.ready()));
                    }
                })
                .expect("start driver async thread");
            queues.push(Mutex::new(tx));
            threads.push(handle);
        }
        Pool {
            queues,
            threads: Mutex::new(threads),
            stopped: Mutex::new(false),
        }
    })
}

impl Pool {
    fn enqueue(&self, queue: usize, job: Job) -> Result<(), Job> {
        let stopped = self.stopped.lock().unwrap();
        if *stopped {
            return Err(job);
        }
        match self.queues[queue]
            .lock()
            .unwrap()
            .send(AsyncMessage::Job(job))
        {
            Ok(()) => Ok(()),
            Err(error) => match error.0 {
                AsyncMessage::Job(job) => Err(job),
                AsyncMessage::Exit => unreachable!("an exit message is never enqueued here"),
            },
        }
    }

    /// Drain queued async invocations, send one exit marker per worker, and join every worker.
    /// Port of erts/emulator/beam/erl_async.c:446-460 (`erts_exit_flush_async`), OTP-29.1.1.
    fn flush_exit(&self) {
        let mut stopped = self.stopped.lock().unwrap();
        if *stopped {
            return;
        }
        *stopped = true;
        for queue in &self.queues {
            let _ = queue.lock().unwrap().send(AsyncMessage::Exit);
        }
        drop(stopped);
        for thread in self.threads.lock().unwrap().drain(..) {
            let _ = thread.join();
        }
    }
}

/// Flush queued async work during a runtime exit without starting an unused pool.
pub(crate) fn flush_exit() {
    if let Some(pool) = POOL.get() {
        pool.flush_exit();
    }
}

impl Job {
    /// Port of io.c:5368 (async_ready): `true` when the job data still needs `async_free`.
    fn deliver(&self) -> bool {
        let port = &self.port;
        let _guard = port.guard();
        if !port.live() {
            return true;
        }
        port.start_task();
        match port.driver.callbacks.ready_async {
            Some(callback) => {
                call2(callback, port.data(), self.data as *mut c_void);
                port.add_reds(REDS_INPUT);
                false
            }
            None => true,
        }
    }

    fn free(&self) {
        if let Some(free) = self.free {
            call1(free, self.data as *mut c_void);
        }
    }

    /// Port of erl_async.c:318 (call_async_ready).
    pub(crate) fn ready(self) {
        if self.deliver() {
            self.free();
        }
        if self.pdl != 0 {
            threads::pdl_dec(self.pdl as *mut threads::PortDataLock);
        }
        self.port.host.ddll_dereference(&self.port);
    }
}

/// Port of erl_async.c:541 (driver_async). Returns the job id, or 0 when the job ran
/// synchronously because there are no async threads.
pub(crate) fn driver_async(
    port: PortRef,
    key: Option<&mut c_uint>,
    invoke: DrvFn1,
    data: *mut c_void,
    free: Option<DrvFn1>,
) -> c_long {
    let threads = CONFIGURED.load(Ordering::Relaxed);
    let mut job = Job {
        port: port.clone(),
        invoke,
        data: data as usize,
        free,
        pdl: 0,
        // Port of erl_async.c:552-554, OTP-29.1.1: scheduler 1 when not on a scheduler.
        sched_id: arinsal_sched::current_normal_scheduler().unwrap_or(0),
    };
    if threads == 0 {
        call1(invoke, data);
        if job.deliver() {
            job.free();
        }
        return 0;
    }
    let id = loop {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        if id != 0 {
            break id.wrapping_abs();
        }
    };
    let pool = pool();
    let threads = pool.queues.len();
    // The key picks the queue; `*key` is replaced by the queue index.
    let queue = match key {
        None => id as usize % threads,
        Some(key) => {
            let queue = *key as usize % threads;
            *key = queue as c_uint;
            queue
        }
    };
    // Port of erl_async.c:596: the job keeps the port data lock alive until it is ready.
    let pdl = port.pdl.load(Ordering::Acquire);
    if pdl != 0 {
        threads::pdl_inc(pdl as *mut threads::PortDataLock);
        job.pdl = pdl;
    }
    port.host.ddll_reference(&port);
    if let Err(job) = pool.enqueue(queue, job) {
        call1(job.invoke, job.data as *mut c_void);
        job.ready();
        return 0;
    }
    id as c_long
}
