//! Scheduler-path prim_tty checks against OTP 29.1.1.
//!
//! Exported calls (`isatty/1`, `sizeof_wchar/0`, `wcswidth/1`, `window_size/1`,
//! `unicode/1`, termcap wrappers) run on both sides. `tty_create`, `tty_init`,
//! `tty_select`, `write_nif`, and `read_nif` are not exported; erts reaches them
//! from inside `prim_tty`. Those are invoked here on the scheduler and compared
//! to the bytes, error terms, and `{select, _, _, ready_input}` shape erts
//! produces through the exported wrappers.

use std::fs;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use arinsal_difftest::RefErl;
use arinsal_etf::{OwnedTerm, decode};
use arinsal_vm::Vm;

static STDIO: Mutex<()> = Mutex::new(());

fn stdio() -> std::sync::MutexGuard<'static, ()> {
    STDIO.lock().unwrap_or_else(|poison| poison.into_inner())
}
static NEXT: AtomicU64 = AtomicU64::new(1);

const SOURCE: &str = r#"
-module(tty_diff).
-export([pipes/0, window/0, init_modes/0, create/0, write_ok/1, write_big/1,
         select_read/0, chars/0, locale/0, termcap/0, bad/0, closed/0,
         encoding/0, plain_bifs/0]).
plain_bifs() ->
    F = fun(M, Fun, Args) -> apply(M, Fun, Args) end,
    [a, b] = F(erlang, '++', [[a], [b]]),
    "abc" = F(erlang, atom_to_list, [abc]),
    abc = F(erlang, list_to_atom, ["abc"]),
    [a, b] = [a] ++ [b],
    ok.
pipes() ->
    ok = prim_tty:load(),
    {prim_tty:isatty(stdin), prim_tty:isatty(stdout), prim_tty:isatty(stderr)}.
window() ->
    {ok, T} = prim_tty:tty_create(stdout),
    prim_tty:tty_window_size(T).
init_modes() ->
    {ok, T} = prim_tty:tty_create(stdout),
    {prim_tty:tty_init(T, #{input => raw}),
     prim_tty:tty_init(T, #{input => cooked}),
     prim_tty:tty_init(T, #{input => false}),
     try prim_tty:tty_init(T, #{}) catch error:R1 -> {error, R1} end,
     try prim_tty:tty_init(not_a_tty, #{input => cooked}) catch error:R2 -> {error, R2} end}.
create() ->
    {ok, T} = prim_tty:tty_create(stdout),
    T.
write_ok(T) ->
    prim_tty:write_nif(T, [<<"a">>, 10, <<"b\n">>]).
write_big(T) ->
    prim_tty:write_nif(T, [binary:copy(<<16#5a>>, 131072)]).
select_read() ->
    {ok, T} = prim_tty:tty_create(stdout),
    Ref = make_ref(),
    ok = prim_tty:tty_select(T, Ref),
    Shape = receive
        {select, Tty, R, ready_input} -> {select, Tty =:= T, R =:= Ref, ready_input}
    after 3000 -> timeout
    end,
    {Shape, prim_tty:read_nif(T, Ref, 64)}.
chars() ->
    _ = prim_tty:setlocale(stdin),
    {prim_tty:sizeof_wchar(),
     [prim_tty:wcswidth(<<C:32/native-signed>>) || C <- [65, 10, 16#1F600, 0]],
     [prim_tty:wcwidth(C) || C <- [65, 10, 16#1F600]],
     [prim_tty:isprint(C) || C <- [0, 10, 32, 65, 127, 255]]}.
locale() ->
    prim_tty:setlocale(stdin).
encoding() ->
    prim_tty:tty_encoding(stdin).
termcap() ->
    ok = prim_tty:setupterm_nif(),
    Nums = [prim_tty:tigetnum(C) || C <- ["co", "li", "zz"]],
    Flags = [prim_tty:tigetflag(C) || C <- ["am", "xn", "zz"]],
    Strs = [prim_tty:tigetstr(C) || C <- ["clear", "cup"]],
    Puts = prim_tty:tputs("\e[H", []),
    Info = prim_tty:tinfo(),
    {Nums, Flags, Strs, Puts, Info}.
bad() ->
    {try prim_tty:isatty(other) catch error:R1 -> {error, R1} end,
     try prim_tty:tty_create(stdin) catch error:R2 -> {error, R2} end,
     try prim_tty:tty_select(x, x) catch error:R3 -> {error, R3} end,
     try prim_tty:write_nif(x, <<"a">>) catch error:R4 -> {error, R4} end,
     try prim_tty:read_nif(x, x, 1) catch error:R5 -> {error, R5} end,
     try prim_tty:tty_window_size(x) catch error:R6 -> {error, R6} end,
     try prim_tty:tty_is_open(x, stdin) catch error:R7 -> {error, R7} end,
     try prim_tty:wcwidth(not_int) catch error:R8 -> {error, R8} end,
     try prim_tty:isprint(not_int) catch error:R9 -> {error, R9} end}.
closed() ->
    {ok, T} = prim_tty:tty_create(stdout),
    prim_tty:read_nif(T, make_ref(), 8).
"#;

fn beam() -> &'static [u8] {
    static BEAM: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    BEAM.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!(
            "arinsal-tty-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap();
        let source = dir.join("tty_diff.erl");
        fs::write(&source, SOURCE).unwrap();
        let output = Command::new("erlc")
            .arg("-o")
            .arg(&dir)
            .arg(&source)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "erlc: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        fs::read(dir.join("tty_diff.beam")).unwrap()
    })
}

fn scheduled(function: &str) -> OwnedTerm {
    scheduled_args(function, &[])
}

fn scheduled_args(function: &str, args: &[arinsal_term::Term]) -> OwnedTerm {
    let mut vm = Vm::new([]);
    vm.load_bytes(beam()).unwrap();
    vm.eval_scheduled("tty_diff", function, args, 1, None)
        .unwrap_or_else(|error| panic!("{function}: {error}"))
        .term
}

fn call_with(function: &str, arg: &OwnedTerm) -> OwnedTerm {
    let mut heap = arinsal_term::VecHeap::new();
    let term = arinsal_term::from_owned(arg, &mut heap).expect("tty term");
    scheduled_args(function, &[term])
}

struct SavedFd {
    fd: RawFd,
    saved: RawFd,
}

impl Drop for SavedFd {
    fn drop(&mut self) {
        // SAFETY: both descriptors were created by dup/dup2 in redirect and stay open until here.
        unsafe {
            libc::dup2(self.saved, self.fd);
            libc::close(self.saved);
        }
    }
}

fn redirect(fd: RawFd, onto: RawFd) -> SavedFd {
    // SAFETY: fd is a standard stream kept open by the test process.
    let saved = unsafe { libc::dup(fd) };
    assert!(saved >= 0);
    // SAFETY: onto is a live pipe end and fd is the saved standard stream.
    assert_eq!(unsafe { libc::dup2(onto, fd) }, fd);
    SavedFd { fd, saved }
}

fn pipe() -> (OwnedFd, OwnedFd) {
    let mut fds = [-1; 2];
    // SAFETY: pipe writes two new descriptors into fds on success.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    // SAFETY: both values are fresh descriptors from the successful pipe call.
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

fn set_nonblock(fd: RawFd) {
    // SAFETY: fd is a pipe end still owned by the caller.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    assert!(flags >= 0);
    assert_eq!(
        // SAFETY: the same descriptor stays open and the flag word is from F_GETFL.
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) },
        0
    );
}

fn temp_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "arinsal-tty-out-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

fn erl_term(stdin: &[u8], body: &str) -> OwnedTerm {
    let path = temp_path();
    let eval = format!(
        "R = ({body}), ok = file:write_file(\"{}\", term_to_binary(R)), halt().",
        path.display()
    );
    let mut child = Command::new("erl")
        .args(["-noshell", "-noinput", "-eval", &eval])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    let output = child.wait_with_output().unwrap();
    let bytes = fs::read(&path).unwrap_or_default();
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file("erl_crash.dump");
    assert!(
        output.status.success(),
        "erl failed: {}\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    decode(&bytes).unwrap()
}

fn erl_stdout(stdin: &[u8], body: &str) -> Vec<u8> {
    let mut child = Command::new("erl")
        .args(["-noshell", "-noinput", "-eval", body])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    let output = child.wait_with_output().unwrap();
    let _ = fs::remove_file("erl_crash.dump");
    assert!(
        output.status.success(),
        "erl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn discard_ready(fd: RawFd) {
    let mut buf = [0u8; 256];
    loop {
        // SAFETY: buf is writable and fd is the nonblocking pipe read end.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            break;
        }
    }
}

fn read_available(fd: RawFd, exact: usize) -> Vec<u8> {
    let start = Instant::now();
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    while out.len() < exact {
        if start.elapsed() > Duration::from_secs(8) {
            panic!("read {} of {exact} bytes", out.len());
        }
        let want = exact - out.len();
        // SAFETY: buf is writable and fd is the pipe read end kept open by the caller.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len().min(want)) };
        if n > 0 {
            out.extend_from_slice(&buf[..n as usize]);
        } else if n == 0 {
            break;
        } else {
            let err = std::io::Error::last_os_error();
            if matches!(
                err.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) {
                std::thread::sleep(Duration::from_millis(1));
                continue;
            }
            panic!("{err}");
        }
    }
    out
}

/// `++`, `atom_to_list/1` and `list_to_atom/1` are plain BIFs in erts; they must not
/// register the caller with the tty poller.
#[test]
fn plain_bifs_do_not_touch_the_tty_poller() {
    let _lock = stdio();
    let before = arinsal_vm::tty_registered_callers();
    let result = scheduled("plain_bifs");
    assert_eq!(result, atom("ok"));
    assert_eq!(arinsal_vm::tty_registered_callers(), before);
}

#[test]
fn isatty_on_pipes_matches_erl() {
    let _lock = stdio();
    let path = temp_path();
    let eval = format!(
        "R = begin ok = prim_tty:load(), {{prim_tty:isatty(stdin), prim_tty:isatty(stdout), prim_tty:isatty(stderr)}} end, ok = file:write_file(\"{}\", term_to_binary(R)), halt().",
        path.display()
    );
    let output = Command::new("erl")
        .args(["-noshell", "-noinput", "-eval", &eval])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    let _ = fs::remove_file("erl_crash.dump");
    assert!(
        output.status.success(),
        "isatty erl: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected = decode(&fs::read(&path).unwrap()).unwrap();
    let _ = fs::remove_file(&path);
    let (in_r, _in_w) = pipe();
    let (_out_r, out_w) = pipe();
    let (_err_r, err_w) = pipe();
    let actual = {
        let _a = redirect(0, in_r.as_raw_fd());
        let _b = redirect(1, out_w.as_raw_fd());
        let _c = redirect(2, err_w.as_raw_fd());
        scheduled("pipes")
    };
    assert_eq!(actual, expected);
}

#[test]
fn window_size_error_on_non_tty_matches_erl() {
    let _lock = stdio();
    let expected = erl_term(
        &[],
        "begin ok = prim_tty:load(), register(tty_parent, self()), S = prim_tty:init(#{input => disabled, output => raw}), prim_tty:window_size(S) end",
    );
    let (_read, write) = pipe();
    let actual = {
        let _saved = redirect(1, write.as_raw_fd());
        scheduled("window")
    };
    assert_eq!(actual, expected);
}

#[test]
fn tty_init_on_pipe_matches_erts_non_tty_rules() {
    let _lock = stdio();
    let enotsup = erl_term(
        &[],
        "begin ok = prim_tty:load(), register(tty_parent, self()), S = prim_tty:init(#{input => disabled, output => raw}), prim_tty:window_size(S) end",
    );
    let ok = erl_term(&[], "ok");
    let badarg = erl_term(
        &[],
        "begin ok = prim_tty:load(), try prim_tty:isatty(other) catch error:Reason -> {error, Reason} end end",
    );
    let (_read, write) = pipe();
    let actual = {
        let _saved = redirect(1, write.as_raw_fd());
        scheduled("init_modes")
    };
    assert_eq!(
        actual,
        OwnedTerm::Tuple(vec![
            enotsup.clone(),
            ok.clone(),
            ok,
            badarg.clone(),
            badarg,
        ])
    );
    assert_eq!(enotsup, tuple(&atom("error"), &atom("enotsup")));
}

#[test]
fn write_iodata_to_a_pipe_matches_erl_bytes() {
    let _lock = stdio();
    let expected_bytes = erl_stdout(
        &[],
        "ok = prim_tty:load(), register(tty_parent, self()), S = prim_tty:init(#{input => disabled, output => raw}), prim_tty:write(S, [<<\"a\">>, 10, <<\"b\\n\">>]), receive after 1000 -> ok end, halt().",
    );
    let ok = erl_term(&[], "ok");
    let (read, write) = pipe();
    set_nonblock(read.as_raw_fd());
    let tty = {
        let _saved = redirect(1, write.as_raw_fd());
        scheduled("create")
    };
    discard_ready(read.as_raw_fd());
    let actual = call_with("write_ok", &tty);
    let got = read_available(read.as_raw_fd(), expected_bytes.len());
    assert_eq!(actual, ok);
    assert_eq!(got, expected_bytes);
}

#[test]
fn write_finishes_after_partial_nonblocking_pipe() {
    let _lock = stdio();
    let (read, write) = pipe();
    set_nonblock(read.as_raw_fd());
    set_nonblock(write.as_raw_fd());
    let expected_len = 131_072;
    let tty = {
        let _saved = redirect(1, write.as_raw_fd());
        scheduled("create")
    };
    discard_ready(read.as_raw_fd());
    let read_fd = read.as_raw_fd();
    let reader = std::thread::spawn(move || read_available(read_fd, expected_len));
    let actual = call_with("write_big", &tty);
    let got = reader.join().unwrap();
    assert_eq!(actual, erl_term(&[], "ok"));
    assert_eq!(got.len(), expected_len);
    assert!(got.iter().all(|byte| *byte == 0x5a));
}

#[test]
fn select_and_read_from_a_pipe_deliver_message_and_data() {
    let _lock = stdio();
    let expected_read = erl_term(
        b"hello",
        "begin ok = prim_tty:load(), register(tty_parent, self()), S = prim_tty:init(#{input => cooked, output => raw}), ok = prim_tty:read(S), receive {_, {data, Bin}} -> {ok, Bin} after 2000 -> timeout end end",
    );
    let expected_shape = erl_term(&[], "{select, true, true, ready_input}");
    let (read, write) = pipe();
    assert_eq!(
        // SAFETY: the write end is open and the five bytes remain borrowed for the call.
        unsafe { libc::write(write.as_raw_fd(), b"hello".as_ptr().cast(), 5) },
        5
    );
    let actual = {
        let _saved = redirect(0, read.as_raw_fd());
        scheduled("select_read")
    };
    let OwnedTerm::Tuple(ref parts) = actual else {
        panic!("select result {actual}");
    };
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0], expected_shape);
    assert_eq!(parts[1], expected_read);
}

#[test]
fn read_on_closed_pipe_matches_closed_error() {
    let _lock = stdio();
    let expected = erl_term(&[], "{error, closed}");
    let (read, write) = pipe();
    drop(write);
    let actual = {
        let _saved = redirect(0, read.as_raw_fd());
        scheduled("closed")
    };
    assert_eq!(actual, expected);
}

#[test]
fn width_locale_and_badarg_match_erl() {
    let _lock = stdio();
    let chars = erl_term(
        &[],
        "begin ok = prim_tty:load(), {prim_tty:sizeof_wchar(), [prim_tty:wcswidth(<<C:32/native-signed>>) || C <- [65, 10, 16#1F600, 0]]} end",
    );
    let mut vm = Vm::new([]);
    vm.load_bytes(beam()).unwrap();
    let actual = vm
        .eval_scheduled("tty_diff", "chars", &[], 1, None)
        .unwrap()
        .term;
    let OwnedTerm::Tuple(parts) = &actual else {
        panic!("chars {actual}");
    };
    let OwnedTerm::Tuple(ref expected_parts) = chars else {
        panic!("erl chars");
    };
    assert_eq!(parts[0], expected_parts[0]);
    assert_eq!(parts[1], expected_parts[1]);
    let OwnedTerm::List { elems: widths, .. } = &parts[1] else {
        panic!("widths");
    };
    let OwnedTerm::List { elems: wc, .. } = &parts[2] else {
        panic!("wcwidth");
    };
    for (wide, one) in widths.iter().zip(wc) {
        let wide = match wide {
            OwnedTerm::Tuple(v) if v.len() == 2 && v[0] == OwnedTerm::Atom("ok".into()) => &v[1],
            other => other,
        };
        assert_eq!(one, wide);
    }
    let locale = erl_term(
        &[],
        "begin ok = prim_tty:load(), register(tty_locale, self()), S = prim_tty:init(#{input => disabled, output => raw}), prim_tty:unicode(S) end",
    );
    assert_eq!(scheduled("locale"), locale);
    assert_eq!(scheduled("encoding"), erl_term(&[], "utf8"));
    let badarg = erl_term(
        &[],
        "begin ok = prim_tty:load(), try prim_tty:isatty(other) catch error:Reason -> {error, Reason} end end",
    );
    let OwnedTerm::Tuple(ref bad) = scheduled("bad") else {
        panic!("bad");
    };
    assert!(bad.iter().all(|term| term == &badarg));
    let reference = RefErl::start().expect("erl");
    let open_bad = reference.call(
        "prim_tty",
        "tty_is_open",
        &[OwnedTerm::atom("x"), OwnedTerm::atom("stdin")],
    );
    drop(reference);
    let arinsal_difftest::CallResult::Exception { class, reason, .. } = open_bad else {
        panic!("erl tty_is_open should fail: {open_bad:?}");
    };
    assert_eq!(class, "error");
    assert_eq!(reason, OwnedTerm::Atom("badarg".into()));
}

#[test]
fn termcap_wrappers_match_erl() {
    let _lock = stdio();
    let term = "xterm-256color";
    let path = temp_path();
    let eval = format!(
        "R = begin ok = prim_tty:load(), Nums = [prim_tty:tigetnum(C) || C <- [\"co\",\"li\",\"zz\"]], Flags = [prim_tty:tigetflag(C) || C <- [\"am\",\"xn\",\"zz\"]], Strs = [prim_tty:tigetstr(C) || C <- [\"clear\",\"cup\"]], Puts = prim_tty:tputs(\"\\e[H\", []), Info = prim_tty:tinfo(), {{Nums, Flags, Strs, Puts, Info}} end, ok = file:write_file(\"{}\", term_to_binary(R)), halt().",
        path.display()
    );
    let output = Command::new("erl")
        .args(["-noshell", "-noinput", "-eval", &eval])
        .env("TERM", term)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    let _ = fs::remove_file("erl_crash.dump");
    assert!(
        output.status.success(),
        "termcap erl: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected = decode(&fs::read(&path).unwrap()).unwrap();
    let _ = fs::remove_file(&path);
    // SAFETY: this test holds STDIO and is the only one publishing TERM.
    unsafe { std::env::set_var("TERM", term) };
    let actual = scheduled("termcap");
    assert_eq!(normalize(&actual), normalize(&expected));
}

fn normalize(term: &OwnedTerm) -> OwnedTerm {
    match term {
        OwnedTerm::Map(pairs) => {
            let mut pairs: Vec<_> = pairs
                .iter()
                .map(|(key, value)| (normalize(key), normalize(value)))
                .collect();
            pairs.sort_by(|left, right| format!("{:?}", left.0).cmp(&format!("{:?}", right.0)));
            OwnedTerm::Map(pairs)
        }
        OwnedTerm::Tuple(values) => OwnedTerm::Tuple(values.iter().map(normalize).collect()),
        OwnedTerm::List { elems, tail } => OwnedTerm::List {
            elems: elems.iter().map(normalize).collect(),
            tail: Box::new(normalize(tail)),
        },
        other => other.clone(),
    }
}

fn atom(name: &str) -> OwnedTerm {
    OwnedTerm::Atom(name.into())
}

fn tuple(a: &OwnedTerm, b: &OwnedTerm) -> OwnedTerm {
    OwnedTerm::Tuple(vec![a.clone(), b.clone()])
}

type RawFd = std::os::fd::RawFd;
