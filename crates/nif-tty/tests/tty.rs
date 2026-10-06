use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use arinsal_bifs::{BifError, Ctx, FragmentingHeap};
use arinsal_etf::{OwnedTerm as O, decode};
use arinsal_term::{ProcessHeap, from_owned, to_owned};

static TERM_TEST_LOCK: Mutex<()> = Mutex::new(());
static NEXT_TMP: AtomicU64 = AtomicU64::new(1);

fn atom(s: &str) -> O {
    O::atom(s)
}
fn tuple(a: O, b: O) -> O {
    O::tuple(vec![a, b])
}
fn call(name: &str, args: &[O]) -> Result<O, BifError> {
    let mut heap = ProcessHeap::with_words(2048);
    let mut alloc = FragmentingHeap(&mut heap);
    let terms = args
        .iter()
        .map(|a| from_owned(a, &mut alloc).unwrap())
        .collect::<Vec<_>>();
    let mut ctx = Ctx::new(&mut alloc);
    let nif = arinsal_nif_tty::lookup("prim_tty", name, args.len() as u8).unwrap();
    nif(&mut ctx, &terms).map(|term| to_owned(term).unwrap())
}
fn pty() -> (OwnedFd, OwnedFd) {
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: openpty initializes both descriptor output slots on success.
    let status = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(status, 0);
    // SAFETY: successful openpty returned two new owned descriptors.
    unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) }
}
fn attrs(fd: i32) -> libc::termios {
    let mut value = std::mem::MaybeUninit::uninit();
    // SAFETY: tcgetattr initializes the out parameter on success.
    assert_eq!(unsafe { libc::tcgetattr(fd, value.as_mut_ptr()) }, 0);
    // SAFETY: tcgetattr succeeded.
    unsafe { value.assume_init() }
}
#[test]
fn registry_matches_otp_nifs() {
    let entries = [
        ("isatty", 1),
        ("tty_create", 1),
        ("tty_init", 2),
        ("setlocale", 1),
        ("tty_select", 2),
        ("tty_window_size", 1),
        ("tty_encoding", 1),
        ("tty_is_open", 2),
        ("write_nif", 2),
        ("read_nif", 3),
        ("isprint", 1),
        ("wcwidth", 1),
        ("wcswidth", 1),
        ("sizeof_wchar", 0),
        ("setupterm_nif", 0),
        ("tigetnum_nif", 1),
        ("tigetflag_nif", 1),
        ("tigetstr_nif", 1),
        ("tinfo_nif", 0),
        ("tputs_nif", 2),
    ];
    for (name, arity) in entries {
        assert!(
            arinsal_nif_tty::lookup("prim_tty", name, arity).is_some(),
            "{name}/{arity}"
        );
    }
    assert!(arinsal_nif_tty::lookup("prim_tty", "tty_create", 0).is_none());
    assert!(arinsal_nif_tty::lookup("other", "isatty", 1).is_none());
}

#[test]
fn pty_io_modes_geometry_and_selection() {
    let (master, slave) = pty();
    let original = attrs(slave.as_raw_fd());
    let tty = arinsal_nif_tty::create_with_fds(slave.as_raw_fd(), slave.as_raw_fd()).unwrap();
    let opts = |input| O::Map(vec![(atom("input"), atom(input))]);
    assert_eq!(
        call("tty_init", &[tty.clone(), opts("raw")]).unwrap(),
        atom("ok")
    );
    let raw = attrs(slave.as_raw_fd());
    assert_eq!(raw.c_lflag & (libc::ICANON | libc::ECHO), 0);
    assert_eq!(raw.c_iflag & libc::ICRNL, 0);
    assert_eq!(raw.c_oflag & libc::OPOST, 0);
    let winsize = libc::winsize {
        ws_row: 41,
        ws_col: 113,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: slave is open and winsize points to an initialized value.
    let status = unsafe { libc::ioctl(slave.as_raw_fd(), libc::TIOCSWINSZ, &winsize) };
    assert_eq!(status, 0);
    assert_eq!(
        call("tty_window_size", std::slice::from_ref(&tty)).unwrap(),
        tuple(atom("ok"), tuple(O::Int(113), O::Int(41)))
    );
    let read_ref = O::Ref {
        node: "nonode@nohost".into(),
        creation: 0,
        ids: vec![4, 5, 6],
    };
    assert_eq!(
        call("tty_select", &[tty.clone(), read_ref.clone()]).unwrap(),
        atom("ok")
    );
    let selection = arinsal_nif_tty::selection(&tty).unwrap().unwrap();
    assert_eq!(selection.tty, tty);
    assert_eq!(selection.reference, read_ref);
    let input = b"hello";
    // SAFETY: master is open and input points to five bytes.
    let written = unsafe { libc::write(master.as_raw_fd(), input.as_ptr().cast(), input.len()) };
    assert_eq!(written, input.len() as isize);
    assert!(arinsal_nif_tty::wait_readable(&tty, Duration::from_secs(1)).unwrap());
    assert_eq!(
        call("read_nif", &[tty.clone(), read_ref, O::Int(5)]).unwrap(),
        tuple(atom("ok"), O::Binary(input.to_vec()))
    );
    assert_eq!(
        call(
            "write_nif",
            &[
                tty.clone(),
                O::list(vec![O::Binary(b"one".to_vec()), O::Binary(b"two".to_vec())])
            ]
        )
        .unwrap(),
        atom("ok")
    );
    let mut out = [0_u8; 6];
    // SAFETY: master is open and out is writable for six bytes.
    let read = unsafe { libc::read(master.as_raw_fd(), out.as_mut_ptr().cast(), out.len()) };
    assert_eq!(read, 6);
    assert_eq!(&out, b"onetwo");
    assert_eq!(
        call("tty_init", &[tty.clone(), opts("cooked")]).unwrap(),
        atom("ok")
    );
    assert_eq!(
        attrs(slave.as_raw_fd()).c_lflag & (libc::ICANON | libc::ECHO),
        original.c_lflag & (libc::ICANON | libc::ECHO)
    );
    assert_eq!(
        call("tty_init", &[tty.clone(), opts("raw")]).unwrap(),
        atom("ok")
    );
    arinsal_nif_tty::release(&tty).unwrap();
    assert_eq!(
        attrs(slave.as_raw_fd()).c_lflag & (libc::ICANON | libc::ECHO),
        original.c_lflag & (libc::ICANON | libc::ECHO)
    );
}

#[test]
fn descriptor_kinds() {
    let (_master, slave) = pty();
    let path = std::env::temp_dir().join(format!("arinsal-tty-{}", std::process::id()));
    let file = fs::File::create(&path).unwrap();
    let mut pipe = [-1; 2];
    // SAFETY: pipe initializes both descriptors on success.
    assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
    // SAFETY: successful pipe returned new owned descriptors.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(pipe[0]), OwnedFd::from_raw_fd(pipe[1])) };
    assert!(arinsal_nif_tty::isatty_fd(slave.as_raw_fd()).unwrap());
    assert!(!arinsal_nif_tty::isatty_fd(file.as_raw_fd()).unwrap());
    assert!(!arinsal_nif_tty::isatty_fd(read.as_raw_fd()).unwrap());
    assert!(!arinsal_nif_tty::isatty_fd(write.as_raw_fd()).unwrap());
    fs::remove_file(path).unwrap();
}

#[test]
fn write_finishes_after_partial_nonblocking_writes() {
    let mut pipe = [-1; 2];
    // SAFETY: pipe initializes both descriptors on success.
    let status = unsafe { libc::pipe(pipe.as_mut_ptr()) };
    assert_eq!(status, 0);
    // SAFETY: the pipe call returned fresh descriptors owned by this test.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(pipe[0]), OwnedFd::from_raw_fd(pipe[1])) };
    // SAFETY: fcntl changes only the descriptor flags of an owned pipe fd.
    let flags = unsafe { libc::fcntl(write.as_raw_fd(), libc::F_GETFL) };
    assert!(flags >= 0);
    // SAFETY: the pipe fd remains open and flags are from F_GETFL.
    let status = unsafe { libc::fcntl(write.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
    assert_eq!(status, 0);
    let tty = arinsal_nif_tty::create_with_fds(read.as_raw_fd(), write.as_raw_fd()).unwrap();
    let bytes = vec![0x5a; 256 * 1024];
    let expected_len = bytes.len();
    let reader = std::thread::spawn(move || {
        let mut output = Vec::new();
        let mut chunk = [0_u8; 4096];
        while output.len() < expected_len {
            // SAFETY: read is owned by this thread and chunk is writable.
            let n = unsafe { libc::read(read.as_raw_fd(), chunk.as_mut_ptr().cast(), chunk.len()) };
            assert!(n > 0);
            output.extend_from_slice(&chunk[..n as usize]);
        }
        output
    });
    assert_eq!(
        call(
            "write_nif",
            &[tty.clone(), O::list(vec![O::Binary(bytes.clone())])]
        )
        .unwrap(),
        atom("ok")
    );
    assert_eq!(reader.join().unwrap(), bytes);
    arinsal_nif_tty::release(&tty).unwrap();
}

fn otp_file(term: Option<&str>, expr: &str) -> Option<O> {
    if Command::new("erl").arg("-version").output().is_err() {
        eprintln!("skipping OTP differential: erl is missing");
        return None;
    }
    let path = std::env::temp_dir().join(format!(
        "arinsal-tty-diff-{}-{}",
        std::process::id(),
        NEXT_TMP.fetch_add(1, Ordering::Relaxed)
    ));
    let eval = format!(
        "ok = file:write_file(\"{}\", term_to_binary({expr})), halt().",
        path.display()
    );
    let mut command = Command::new("erl");
    command.args(["-noshell", "-eval", &eval]);
    if let Some(term) = term {
        command.env("TERM", term);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "erl: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bytes = fs::read(&path).unwrap();
    fs::remove_file(path).unwrap();
    Some(decode(&bytes).unwrap())
}

#[test]
fn wide_character_large_sample_matches_erl() {
    let Some(expected) = otp_file(
        None,
        "[prim_tty:wcswidth(<<N:32/native-signed>>) || N <- lists:seq(1, 16#10ffff, 11)]",
    ) else {
        return;
    };
    let O::List { elems, tail } = &expected else {
        panic!("expected result list")
    };
    assert_eq!(**tail, O::Nil);
    assert_eq!(elems.len(), 101283);
    for (i, want) in elems.iter().enumerate() {
        let point = 1 + i as i64 * 11;
        let got = call(
            "wcswidth",
            &[O::Binary((point as i32).to_ne_bytes().to_vec())],
        )
        .unwrap();
        assert_eq!(&got, want, "U+{point:04X}");
        let wc = call("wcwidth", &[O::Int(point)]).unwrap();
        let mapped = match want {
            O::Tuple(v) if v.len() == 2 && v[0] == atom("ok") => v[1].clone(),
            other => other.clone(),
        };
        assert_eq!(wc, mapped, "wcwidth U+{point:04X}");
    }
}

#[test]
fn isprint_matches_erts_c_locale_rule() {
    let _ = call("setlocale", &[atom("ignored")]).unwrap();
    for n in 0..=255_i64 {
        // SAFETY: this uses the same libc call and signed-char cast as prim_tty_nif.c.
        let printable = unsafe { libc::isprint(n as i8 as i32) } != 0;
        assert_eq!(
            call("isprint", &[O::Int(n)]).unwrap(),
            atom(if printable { "true" } else { "false" }),
            "byte {n}"
        );
    }
}

#[test]
fn terminfo_matches_erl_for_xterm_and_dumb() {
    let _lock = TERM_TEST_LOCK.lock().unwrap();
    let expression = "[prim_tty:tigetnum(C) || C <- [\"co\",\"li\",\"it\",\"zz\"]] ++ [prim_tty:tigetflag(C) || C <- [\"am\",\"xn\",\"ms\",\"zz\"]] ++ [prim_tty:tigetstr(C) || C <- [\"clear\",\"cup\",\"sgr0\",\"el\",\"bold\"]]";
    for term in ["xterm-256color", "dumb"] {
        let Some(expected) = otp_file(Some(term), expression) else {
            return;
        };
        // SAFETY: the test is the only test changing TERM; the environment value is valid UTF-8.
        unsafe { std::env::set_var("TERM", term) };
        assert_eq!(call("setupterm_nif", &[]).unwrap(), atom("ok"));
        let mut got = Vec::new();
        for cap in ["co", "li", "it", "zz"] {
            got.push(
                call(
                    "tigetnum_nif",
                    &[O::list(
                        cap.bytes()
                            .map(|b| O::Int(i64::from(b)))
                            .chain([O::Int(0)])
                            .collect(),
                    )],
                )
                .unwrap(),
            );
        }
        for cap in ["am", "xn", "ms", "zz"] {
            got.push(
                call(
                    "tigetflag_nif",
                    &[O::list(
                        cap.bytes()
                            .map(|b| O::Int(i64::from(b)))
                            .chain([O::Int(0)])
                            .collect(),
                    )],
                )
                .unwrap(),
            );
        }
        for cap in ["clear", "cup", "sgr0", "el", "bold"] {
            got.push(
                call(
                    "tigetstr_nif",
                    &[O::list(
                        cap.bytes()
                            .map(|b| O::Int(i64::from(b)))
                            .chain([O::Int(0)])
                            .collect(),
                    )],
                )
                .unwrap(),
            );
        }
        assert_eq!(O::list(got), expected, "TERM={term}");
        let Some(expected_puts) = otp_file(
            Some(term),
            "[prim_tty:tputs(\"\\e[%i%p1%d;%p2%dH\", [3,7]), prim_tty:tputs(\"\\e[H\", [])]",
        ) else {
            return;
        };
        let puts = O::list(vec![
            call(
                "tputs_nif",
                &[
                    O::list(
                        b"\x1b[%i%p1%d;%p2%dH"
                            .iter()
                            .map(|b| O::Int(i64::from(*b)))
                            .chain([O::Int(0)])
                            .collect(),
                    ),
                    O::list(vec![O::Int(3), O::Int(7)]),
                ],
            )
            .unwrap(),
            call(
                "tputs_nif",
                &[
                    O::list(
                        b"\x1b[H"
                            .iter()
                            .map(|b| O::Int(i64::from(*b)))
                            .chain([O::Int(0)])
                            .collect(),
                    ),
                    O::Nil,
                ],
            )
            .unwrap(),
        ]);
        assert_eq!(puts, expected_puts, "tputs TERM={term}");
    }
}

#[test]
fn terminfo_metadata_is_available() {
    let _lock = TERM_TEST_LOCK.lock().unwrap();
    let Some(expected) = otp_file(
        Some("xterm-256color"),
        "maps:map(fun(_, V) -> length(V) end, prim_tty:tinfo())",
    ) else {
        return;
    };
    // SAFETY: the test is the only test changing TERM; the value contains no NUL.
    unsafe { std::env::set_var("TERM", "xterm-256color") };
    assert_eq!(call("setupterm_nif", &[]).unwrap(), atom("ok"));
    let got = call("tinfo_nif", &[]).unwrap();
    let O::Map(entries) = &got else {
        panic!("tinfo should return a map")
    };
    let counts = O::Map(
        entries
            .iter()
            .map(|(key, value)| {
                let O::List { elems, .. } = value else {
                    panic!("expected capability list")
                };
                (key.clone(), O::Int(elems.len() as i64))
            })
            .collect(),
    );
    assert_eq!(counts, expected);
}
