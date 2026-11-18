//! Raw-memory access of the vm crate: the one place where code reached from JIT-generated
//! native code touches addresses it was handed as integers or pointers.

pub(crate) mod beam_common_ffi;
pub(crate) mod gc_ffi;
pub(crate) mod jit_ffi;
