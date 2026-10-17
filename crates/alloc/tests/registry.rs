//! The thread to instance registry and the configured instance counts, in a process of its own.

use arinsal_alloc::typed::{AllocBlock, ErtsAlcType, configure, instance_count};
use arinsal_alloc::{RegisterError, ThreadKind, register_thread};
use std::sync::Mutex;
use std::sync::OnceLock;
use std::thread;

static SERIAL: Mutex<()> = Mutex::new(());

fn configured() -> std::sync::MutexGuard<'static, ()> {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| configure(3, 2).expect("first configuration"));
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn instance_of_new_block() -> usize {
    AllocBlock::new(ErtsAlcType::HEAP, 4).unwrap().instance()
}

fn on_thread(kind: Option<ThreadKind>) -> (Option<Result<usize, RegisterError>>, usize) {
    thread::spawn(move || {
        let registered = kind.map(register_thread);
        (registered, instance_of_new_block())
    })
    .join()
    .unwrap()
}

#[test]
fn instance_counts_follow_the_configuration() {
    let _serial = configured();
    assert_eq!(instance_count("eheap_alloc"), Some(1 + 3 + 2));
    assert_eq!(instance_count("temp_alloc"), Some(1 + 3 + 2));
    assert_eq!(instance_count("binary_alloc"), Some(1 + 3 + 2));
    assert_eq!(instance_count("literal_alloc"), Some(1));
    assert_eq!(instance_count("no_such_alloc"), None);
    assert!(configure(8, 0).is_err());
}

#[test]
fn scheduler_n_gets_instance_n_and_other_threads_get_zero() {
    let _serial = configured();
    assert_eq!(instance_of_new_block(), 0);
    assert_eq!(on_thread(None).1, 0);
    for no in 1..=3 {
        assert_eq!(
            on_thread(Some(ThreadKind::Scheduler(no))),
            (Some(Ok(no)), no)
        );
    }
    assert_eq!(
        on_thread(Some(ThreadKind::Scheduler(6))),
        (Some(Ok(6)), 0),
        "a scheduler number beyond the instance count uses instance 0"
    );
}

#[test]
fn dirty_schedulers_map_onto_the_dirty_instances() {
    let _serial = configured();
    let expected = [
        (ThreadKind::DirtyCpu(1), 4),
        (ThreadKind::DirtyCpu(2), 5),
        (ThreadKind::DirtyCpu(3), 4),
        (ThreadKind::DirtyCpu(4), 5),
        (ThreadKind::DirtyIo(1), 4),
        (ThreadKind::DirtyIo(2), 5),
        (ThreadKind::DirtyIo(3), 4),
    ];
    for (kind, instance) in expected {
        assert_eq!(
            on_thread(Some(kind)),
            (Some(Ok(instance)), instance),
            "{kind:?}"
        );
    }
}
