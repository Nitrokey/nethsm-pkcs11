use rayon::{ThreadPool, ThreadPoolBuilder};

use std::{
    any::Any,
    io, mem,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed},
        Mutex, RwLock,
    },
    thread::{available_parallelism, JoinHandle},
};

use crate::config::device::{start_background_timer, stop_background_timer};

// If the calling application allows threads to be used
pub static THREADS_ALLOWED: AtomicBool = AtomicBool::new(true);

static DEAD_THREADS: AtomicUsize = AtomicUsize::new(0);
static RAYON_HANDLES: Mutex<Vec<JoinHandle<()>>> = Mutex::new(Vec::new());
static RAYON_THREADPOOL: RwLock<Option<ThreadPool>> = RwLock::new(None);

fn log_thread_pool_error(err: &Box<dyn Any + Send + 'static>) {
    if let Some(err) = err.downcast_ref::<&'static str>() {
        log::error!("Thread pool thread panicked: {err}");
    } else if let Some(err) = err.downcast_ref::<String>() {
        log::error!("Thread pool thread panicked: {err}");
    } else {
        log::error!("Thread pool thread panicked: {err:?}");
    }
}

fn cleanup_dead_threads(num_cpus: usize) {
    let dead_threads = DEAD_THREADS.fetch_add(1, Relaxed);
    // Prevent potential infinitely growing handle count
    if dead_threads > 2 * num_cpus {
        // Should be somewhat fast as the number of threads should be proportional to the number of CPU
        // Only use try_lock to avoid any deadlock
        if let Ok(mut handles) = RAYON_HANDLES.try_lock() {
            let tmp = mem::replace(&mut *handles, Vec::with_capacity(2 * num_cpus));
            let mut removed_threads = 0;
            *handles = tmp
                .into_iter()
                .filter_map(|h| {
                    if h.is_finished() {
                        removed_threads += 1;
                        h.join().inspect_err(log_thread_pool_error).ok();
                        None
                    } else {
                        Some(h)
                    }
                })
                .collect();
            DEAD_THREADS.fetch_sub(removed_threads, Relaxed);
        }
    }
}

fn spawn_handler(num_cpus: usize, thread: rayon::ThreadBuilder) -> io::Result<()> {
    let mut builder = std::thread::Builder::new();
    if let Some(name) = thread.name() {
        builder = builder.name(name.to_string());
    }
    if let Some(size) = thread.stack_size() {
        builder = builder.stack_size(size);
    }
    let handle = builder.spawn(move || {
        thread.run();
        cleanup_dead_threads(num_cpus);
    })?;
    RAYON_HANDLES
        .lock()
        .expect("Rayon handles not poisoned")
        .push(handle);
    Ok(())
}

fn initialize_threadpool() {
    assert!(THREADS_ALLOWED.load(Relaxed));

    let num_cpus = available_parallelism().map(|m| m.get()).unwrap_or(1);
    let threadpool = ThreadPoolBuilder::new()
        .spawn_handler(|thread| spawn_handler(num_cpus, thread))
        .build()
        .expect("Failed to start rayon pool");
    let mut handle = RAYON_THREADPOOL
        .try_write()
        .expect("During initialization, pool should be free");
    assert!(
        handle.is_none(),
        "During initialization, threadpool should be empty"
    );
    *handle = Some(threadpool);
}

pub struct RayonOperation<OP, OP2> {
    pub rayon: OP,
    pub std: OP2,
}

impl<R, OP, OP2> RayonOperation<OP, OP2>
where
    OP: FnOnce() -> R + Send,
    OP2: FnOnce() -> R + Send,
    R: Send,
{
    pub fn run(self) -> R {
        if THREADS_ALLOWED.load(Relaxed) {
            RAYON_THREADPOOL
                .read()
                .expect("THREADPOOL to be initialized")
                .as_ref()
                .expect("Thread pool should not be closed")
                .install(self.rayon)
        } else {
            (self.std)()
        }
    }
}

fn close_threadpool() {
    assert!(THREADS_ALLOWED.load(Relaxed));
    *RAYON_THREADPOOL.write().unwrap() = None;
    for handle in mem::take(&mut *RAYON_HANDLES.lock().unwrap()) {
        handle.join().inspect_err(log_thread_pool_error).ok();
    }
}

pub fn enable_threads() {
    THREADS_ALLOWED.store(true, Relaxed);
    initialize_threadpool();
    start_background_timer();
}

pub fn disable_threads() {
    THREADS_ALLOWED.store(false, Relaxed);
}

pub fn stop_and_join_threads() {
    if THREADS_ALLOWED.load(Relaxed) {
        close_threadpool();
        stop_background_timer();
    }
}
