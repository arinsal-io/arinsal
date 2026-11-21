//! Operating-system and stable runtime information BIFs.

use std::ffi::OsString;

use arinsal_term::{Term, TermBuilder, global_atoms};

use crate::pure::Heap;
use crate::{BifError, Ctx};

pub(super) fn lookup<V: crate::BifTableVisitor>(
    module: &str,
    name: &str,
    arity: u8,
    v: &mut V,
) -> Option<V::Output> {
    let f = match (module, name, arity) {
        ("erts_internal", "no_aux_work_threads", 0) => v.entry::<bodies::no_aux_work_threads>(),
        ("os", "getenv", 1) => v.entry::<bodies::getenv>(),
        ("os", "getpid", 0) => v.entry::<bodies::getpid>(),
        _ => return None,
    };
    if module == "os" || arinsal_spec::bif_lookup(module, name, arity).is_some() {
        Some(f)
    } else {
        None
    }
}

fn atom(name: &str) -> Term {
    Term::atom(global_atoms().intern(name).expect("short runtime atom"))
}
fn integer(ctx: &mut Ctx<'_>, value: u64) -> Result<Term, BifError> {
    if let Ok(value) = i64::try_from(value)
        && let Some(term) = Term::small(value)
    {
        return Ok(term);
    }
    TermBuilder::new(&mut Heap(&mut ctx.heap))
        .int_from_bigint(&num_bigint::BigInt::from(value))
        .map_err(|_| BifError::SystemLimit)
}
fn string(ctx: &mut Ctx<'_>, value: &str) -> Result<Term, BifError> {
    let mut tail = Term::NIL;
    for ch in value.chars().rev() {
        let code = i64::from(ch as u32);
        tail = TermBuilder::new(&mut Heap(&mut ctx.heap))
            .cons(Term::small(code).ok_or(BifError::SystemLimit)?, tail)
            .map_err(|_| BifError::SystemLimit)?;
    }
    Ok(tail)
}

fn no_aux_work_threads_result(ctx: &mut Ctx<'_>, _: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/erl_process.c:9234 and :6219-6223, OTP-29.1.1.
    // The runtime uses one standard auxiliary worker and no dirty allocator instances.
    let schedulers = arinsal_alloc::cpuinfo::default_schedulers().0 as u64;
    integer(ctx, schedulers.saturating_add(1))
}

fn os_string(ctx: &mut Ctx<'_>, value: OsString) -> Result<Term, BifError> {
    string(ctx, &value.to_string_lossy())
}
fn getenv_result(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let chars = crate::pure::list(args[0])?;
    let mut name = String::new();
    for ch in chars {
        let code = ch
            .as_small()
            .filter(|n| (0..=0x10ffff).contains(n))
            .ok_or(BifError::BADARG)?;
        name.push(char::from_u32(code as u32).ok_or(BifError::BADARG)?);
    }
    match std::env::var_os(name) {
        Some(value) => os_string(ctx, value),
        None => Ok(atom("false")),
    }
}
fn getpid_result(ctx: &mut Ctx<'_>, _: &[Term]) -> Result<Term, BifError> {
    // SAFETY: getpid has no preconditions and does not retain pointers.
    string(ctx, &unsafe { libc::getpid() }.to_string())
}
macro_rules! word_adapters {
    ($($word:ident => $body:ident),+ $(,)?) => {
        $(#[inline(always)]
        fn $word(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
            match $body(ctx, args) { Ok(value) => value, Err(error) => ctx.fail(error) }
        })+
    };
}
word_adapters!(no_aux_work_threads => no_aux_work_threads_result, getenv => getenv_result,
    getpid => getpid_result);
crate::word_bif_bodies_in!(bodies; no_aux_work_threads, getenv, getpid);

/// Build the `os_type` and `os_version` global literals.
// Port of erts/emulator/beam/erl_bif_info.c (os_info_init), OTP-29.1.1. Guarded by a `Once`
// because a VM can boot more than once in one process.
pub fn os_info_init() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let intern = |name: &str| global_atoms().intern(name).expect("os_type atom");
        let (flavor, version) = uname_fields();
        // Atoms first: creating one takes the global literal lock the build holds.
        let elements = [Term::atom(intern("unix")), Term::atom(intern(&flavor))];
        let mut build = arinsal_term::global_literal_allocate(3);
        let tuple = arinsal_term::TermBuilder::new(&mut build)
            .tuple(&elements)
            .expect("os_type literal");
        arinsal_term::set_global_os_type(build.register(tuple));

        let mut build = arinsal_term::global_literal_allocate(4);
        let tuple = arinsal_term::TermBuilder::new(&mut build)
            .tuple(&version.map(|n| Term::small(n).expect("small")))
            .expect("os_version literal");
        arinsal_term::set_global_os_version(build.register(tuple));
    });
}

/// `erlang:system_info(os_type)`: `ERTS_GLOBAL_LIT_OS_TYPE`.
pub fn os_type() -> Term {
    arinsal_term::global_os_type()
}

/// `erlang:system_info(os_version)`: `ERTS_GLOBAL_LIT_OS_VERSION`.
pub fn os_version() -> Term {
    arinsal_term::global_os_version()
}

/// `(os_flavor, os_version)` from `uname(2)`.
// Port of erts/emulator/sys/unix/sys.c (os_flavor, os_version), OTP-29.1.1.
fn uname_fields() -> (String, [i64; 3]) {
    let uts = rustix::system::uname();
    let flavor = uts.sysname().to_string_lossy().to_ascii_lowercase();
    // get_number: a component counts only when it starts with a digit; atoi stops at the
    // first non-digit, and the rest of the release string is then skipped.
    let release = uts.release().to_string_lossy().into_owned();
    let mut rest = release.as_str();
    let mut vals = [0i64; 3];
    for v in &mut vals {
        if !rest.starts_with(|c: char| c.is_ascii_digit()) {
            break;
        }
        let (part, tail) = rest.split_once('.').unwrap_or((rest, ""));
        let digits: String = part.chars().take_while(char::is_ascii_digit).collect();
        *v = digits.parse().unwrap_or(0);
        rest = tail;
    }
    (flavor, vals)
}
