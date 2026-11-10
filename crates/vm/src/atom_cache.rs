//! Atoms erts does not predefine.
//!
//! Predefined atoms are `arinsal_term::atoms` constants (erts `am_*`); every other name is put
//! into the atom table where it is needed, as erts does with `erts_atom_put`.

use arinsal_term::{Term, global_atoms};

/// The atom named `name`, created when it does not exist yet.
///
/// For names that erts does not predefine: those take an `arinsal_term::atoms` constant
/// (`am_*`). erts builds the others at run time with `ERTS_MAKE_AM`/`erts_atom_put`.
// Port of erts/emulator/beam/atom.c (erts_atom_put), OTP-29.1.1.
pub(crate) fn put(name: &str) -> Term {
    Term::atom(global_atoms().intern(name).expect("atom table full"))
}
