//! Port of the architecture-neutral part of erts/emulator/beam/jit/ (beam_jit_args.hpp,
//! beam_jit_types.hpp, beam_jit_common.hpp, beam_jit_register_cache.hpp, beam_jit_bs.cpp),
//! shared by every target emitter.

pub mod args;
pub mod bs;
pub mod process_offsets;
pub mod register_cache;
pub mod types;
