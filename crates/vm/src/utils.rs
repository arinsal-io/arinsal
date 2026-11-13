//! Logger messaging of the emulator.
//!
//! Port of erts/emulator/beam/utils.c (`do_allocate_logger_message`, `do_send_logger_message`,
//! `do_send_to_logger`, `do_send_term_to_logger`, `erts_send_*_to_logger*`) and of
//! erl_trace.c (`erts_queue_error_logger_message`), OTP-29.1.1.

use crate::process::{Message, Runtime};
use arinsal_sched::Pid;
use arinsal_term::{ProcessHeap, Term, TermBuilder, TermError, atoms};

/// Port of utils.c `do_send_logger_message` with `do_allocate_logger_message`:
/// `{log, Tag, Format, Args, #{error_logger => #{emulator => true, tag => ElTag}, gl => GL,
/// pid => Pid, time => Us}}`, queued as the system message `erts_queue_error_logger_message`
/// sends to the `erlang:system_logger/0` destination. `from` is `erts_get_current_pid()`
/// (`None` outside a process, e.g. a port), `gleader` is NIL when absent. `format` is built
/// on the message heap; `args` is a term on a live heap that is copied into the message.
fn do_send_logger_message(
    runtime: &'static Runtime,
    from: Option<Pid>,
    gleader: Term,
    tag: Term,
    format: &str,
    args: impl FnOnce(&mut TermBuilder<ProcessHeap>) -> Result<Term, TermError>,
) {
    // `ts = ERTS_MONOTONIC_TO_USEC(erts_os_system_time())`.
    let ts: i64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_micros())
        .try_into()
        .unwrap_or(i64::MAX);
    let mut heap = ProcessHeap::with_words(format.len() * 2 + 512);
    let event = (|| {
        let mut builder = TermBuilder::new(&mut heap);
        let format = builder.string_to_list(format)?;
        let args = args(&mut builder)?;
        let time = Term::small(ts).ok_or(TermError::SystemLimit)?;
        // The backwards compatible `error_logger` tag mapping.
        let el_tag = if tag == crate::atom_cache::put("info") {
            crate::atom_cache::put("info_msg")
        } else if tag == Term::atom(atoms::WARNING) {
            Term::atom(atoms::WARNING_MSG)
        } else {
            Term::atom(atoms::ERROR)
        };
        let md = builder.flatmap_from_pairs(&[
            (Term::atom(atoms::EMULATOR), Term::atom(atoms::TRUE)),
            (Term::atom(atoms::TAG), el_tag),
        ])?;
        let mut pairs = vec![(Term::atom(atoms::ERROR_LOGGER), md)];
        if gleader != Term::NIL {
            pairs.push((crate::atom_cache::put("gl"), gleader));
        }
        if let Some(pid) = from.and_then(Pid::to_term) {
            pairs.push((Term::atom(atoms::PID), pid));
        }
        pairs.push((Term::atom(atoms::TIME), time));
        let md = builder.flatmap_from_pairs(&pairs)?;
        builder.tuple(&[Term::atom(atoms::LOG), tag, format, args, md])
    })();
    let Ok(event) = event else {
        return;
    };
    let Ok(message) = Message::copy_from(event) else {
        return;
    };
    crate::erl_trace::queue_error_logger_message(runtime, from, message);
}

/// Port of utils.c `do_send_to_logger`: format `"~s~n"`, args `[Text]`.
fn do_send_to_logger(
    runtime: &'static Runtime,
    from: Option<Pid>,
    gleader: Term,
    tag: Term,
    text: &str,
) {
    do_send_logger_message(runtime, from, gleader, tag, "~s~n", |builder| {
        let text = builder.string_to_list(text)?;
        builder.list_from_iter([text])
    });
}

/// Port of utils.c `erts_send_warning_to_logger_str`
/// (`do_send_to_logger` with `erts_error_logger_warnings`, `warning` by default).
pub(crate) fn send_warning_to_logger_str(
    runtime: &'static Runtime,
    from: Pid,
    gleader: Term,
    text: &str,
) {
    do_send_to_logger(
        runtime,
        Some(from),
        gleader,
        Term::atom(atoms::WARNING),
        text,
    );
}

/// Port of utils.c `erts_send_error_to_logger_str` with the caller's group leader.
pub(crate) fn send_error_to_logger_str(
    runtime: &'static Runtime,
    from: Pid,
    gleader: Term,
    text: &str,
) {
    do_send_to_logger(runtime, Some(from), gleader, Term::atom(atoms::ERROR), text);
}

/// Port of utils.c `erts_send_error_to_logger_nogl`: no group leader; `from` is
/// `erts_get_current_pid()`, `None` when a port or the scheduler runs it.
pub(crate) fn send_error_to_logger_nogl(runtime: &'static Runtime, from: Option<Pid>, text: &str) {
    do_send_to_logger(runtime, from, Term::NIL, Term::atom(atoms::ERROR), text);
}

/// Port of utils.c `erts_send_error_term_to_logger` (`do_send_term_to_logger`): `format` is
/// the dsprintf buffer, `args` a list on the caller's live heap.
pub(crate) fn send_error_term_to_logger(
    runtime: &'static Runtime,
    from: Pid,
    gleader: Term,
    format: &str,
    args: Term,
) {
    do_send_logger_message(
        runtime,
        Some(from),
        gleader,
        Term::atom(atoms::ERROR),
        format,
        |_| Ok(args),
    );
}
