//! Typed SSA regions and a separate Cranelift optimizing tier.

pub mod ir;

mod backend;

pub use backend::{CompileError, Engine, MaterializeFn, NativeFn};
