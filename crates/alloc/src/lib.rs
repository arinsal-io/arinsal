#![deny(unsafe_code)]

pub mod alloc_util;
pub mod allocator;
pub mod instances;
pub mod mmap;
pub mod mseg;
#[allow(unsafe_code)]
pub mod raw;
pub mod typed;
pub mod types;

pub use instances::{
    RegisterError, ThreadKind, notify_owner, register_thread, set_owner_notifier, thread_alloc_ix,
};
