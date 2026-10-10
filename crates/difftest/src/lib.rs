//! Differential tests against an isolated OTP 29.1.1 reference node.

#![forbid(unsafe_code)]

mod codec;
pub mod gens;
pub mod reference;
pub mod suites;

use arinsal_etf::OwnedTerm;
use num_bigint::BigInt;
use num_traits::FromPrimitive;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::thread;

/// Failures in the reference transport or protocol.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("ETF: {0}")]
    Codec(#[from] codec::CodecError),
    #[error("reference protocol: {0}")]
    Protocol(String),
    #[error("reference Erlang returned {0:?}")]
    Reference(OwnedTerm),
}
/// Result of one VM call.
#[derive(Debug, Clone, PartialEq)]
pub enum CallResult {
    /// Successful term.
    Ok(OwnedTerm),
    /// Caught error, exit, or throw.
    Exception {
        class: String,
        reason: OwnedTerm,
        stack_top: Option<OwnedTerm>,
    },
    /// The call exceeded its deadline.
    Timeout,
    /// The VM transport failed; this is never a matching VM result.
    TransportError(String),
}
/// Options for a reference call.
#[derive(Debug, Clone, Default)]
pub struct CallOptions {
    pub timeout_ms: Option<u64>,
    pub capture_io: bool,
    pub strip_lines: bool,
    pub reductions: bool,
    pub heap: bool,
    pub encode_opts: Option<Vec<OwnedTerm>>,
}
/// A result with requested process measurements.
#[derive(Debug, Clone)]
pub struct CallOutcome {
    pub result: CallResult,
    pub io: Option<Vec<u8>>,
    pub reductions: Option<u64>,
    pub heap: Option<u64>,
}
/// VM adapter implemented by the reference now and the interpreter later.
pub trait Vm {
    fn call(&mut self, m: &str, f: &str, args: &[OwnedTerm]) -> CallResult;
    fn load(&mut self, module: &str, beam: &[u8]) -> Result<(), Error>;
}

type Pending = Arc<Mutex<HashMap<u64, mpsc::Sender<Result<OwnedTerm, String>>>>>;
struct Process {
    child: Child,
    stdin: ChildStdin,
    pending: Pending,
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Long lived Erlang reference process with concurrent request matching.
pub struct RefErl {
    process: Mutex<Process>,
    next_id: AtomicU64,
    otp_version: String,
}

impl RefErl {
    /// Compile and start the endpoint, checking the installed OTP release.
    pub fn start() -> Result<Self, Error> {
        let output = Command::new("erl").args(["-noshell", "-eval",
            "io:format(\"~s|~s\", [erlang:system_info(otp_release), string:trim(element(2, file:read_file(filename:join([code:root_dir(), \"releases\", erlang:system_info(otp_release), \"OTP_VERSION\"]))))]), halt()."])
            .output()?;
        if !output.status.success() {
            return Err(Error::Protocol(
                String::from_utf8_lossy(&output.stderr).into(),
            ));
        }
        let version = String::from_utf8_lossy(&output.stdout);
        let (release, exact) = version
            .split_once('|')
            .ok_or_else(|| Error::Protocol(format!("unexpected OTP version: {version}")))?;
        if release != "29" {
            return Err(Error::Protocol(format!("OTP 29 required, found {exact}")));
        }
        static COMPILE_LOCK: Mutex<()> = Mutex::new(());
        let _compile_guard = COMPILE_LOCK.lock().unwrap();
        let source = server_source();
        let ebin = source.parent().unwrap().join("ebin");
        std::fs::create_dir_all(&ebin)?;
        let beam = ebin.join("difftest_server.beam");
        let stale = beam
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .zip(source.metadata().and_then(|m| m.modified()).ok())
            .is_none_or(|(built, src)| built < src);
        if stale {
            let output = Command::new("erlc")
                .arg("-o")
                .arg(&ebin)
                .arg(&source)
                .output()?;
            if !output.status.success() {
                return Err(Error::Protocol(
                    String::from_utf8_lossy(&output.stderr).into(),
                ));
            }
        }
        Ok(Self {
            process: Mutex::new(spawn(&ebin)?),
            next_id: AtomicU64::new(1),
            otp_version: exact.to_owned(),
        })
    }
    /// Shared reference for tests. Calls themselves are pipelined internally.
    pub fn shared() -> Result<&'static Self, Error> {
        static SHARED: OnceLock<RefErl> = OnceLock::new();
        if let Some(value) = SHARED.get() {
            return Ok(value);
        }
        let reference = Self::start()?;
        let _ = SHARED.set(reference);
        Ok(SHARED.get().expect("initialized above"))
    }
    /// Exact installed OTP patch version.
    pub fn otp_version(&self) -> &str {
        &self.otp_version
    }
    fn send(
        &self,
        kind: &str,
        args: Vec<OwnedTerm>,
    ) -> Result<mpsc::Receiver<Result<OwnedTerm, String>>, Error> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut xs = vec![atom(kind), OwnedTerm::Int(id as i64)];
        xs.extend(args);
        let bytes = codec::encode(&OwnedTerm::Tuple(xs))?;
        let (tx, rx) = mpsc::channel();
        let mut process = self.process.lock().unwrap();
        if let Some(status) = process.child.try_wait()? {
            let _ = status;
            *process = spawn(&server_ebin())?;
        }
        process.pending.lock().unwrap().insert(id, tx);
        let result = process
            .stdin
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .and_then(|()| process.stdin.write_all(&bytes))
            .and_then(|()| process.stdin.flush());
        if result.is_err() {
            process.pending.lock().unwrap().remove(&id);
            *process = spawn(&server_ebin())?;
            return Err(Error::Protocol("reference process died; restarted".into()));
        }
        Ok(rx)
    }
    fn request(&self, kind: &str, args: Vec<OwnedTerm>) -> Result<OwnedTerm, Error> {
        for attempt in 0..2 {
            match self.send(kind, args.clone()) {
                Ok(rx) => match rx.recv() {
                    Ok(Ok(term)) => return Ok(term),
                    Ok(Err(message)) if attempt == 0 => {
                        let mut p = self.process.lock().unwrap();
                        *p = spawn(&server_ebin())?;
                        let _ = message;
                    }
                    Ok(Err(message)) => return Err(Error::Protocol(message)),
                    Err(_) => return Err(Error::Protocol("reference reader stopped".into())),
                },
                Err(_) if attempt == 0 => continue,
                Err(e) => return Err(e),
            }
        }
        Err(Error::Protocol("reference retry exhausted".into()))
    }
    /// Call a module function in a fresh reference process.
    pub fn call(&self, m: &str, f: &str, args: &[OwnedTerm]) -> CallResult {
        self.call_opts(m, f, args, &CallOptions::default()).result
    }
    /// Call with timeout, output capture, metrics, or ETF encoding options.
    pub fn call_opts(
        &self,
        m: &str,
        f: &str,
        args: &[OwnedTerm],
        opts: &CallOptions,
    ) -> CallOutcome {
        let mut options = Vec::new();
        if let Some(n) = opts.timeout_ms {
            options.push(pair("timeout", OwnedTerm::Int(n as i64)));
        }
        if opts.capture_io {
            options.push(pair("capture_io", atom("true")));
        }
        if opts.strip_lines {
            options.push(pair("strip_lines", atom("true")));
        }
        if opts.reductions {
            options.push(pair("reductions", atom("true")));
        }
        if opts.heap {
            options.push(pair("heap", atom("true")));
        }
        if let Some(xs) = &opts.encode_opts {
            options.push(pair("encode_opts", list(xs.clone())));
        }
        let name = if options.is_empty() {
            "call"
        } else {
            "call_opts"
        };
        let mut req = vec![atom(m), atom(f), list(args.to_vec())];
        if !options.is_empty() {
            req.push(list(options));
        }
        match self.request(name, req) {
            Ok(t) => parse_call(t),
            Err(e) => CallOutcome {
                result: CallResult::TransportError(e.to_string()),
                io: None,
                reductions: None,
                heap: None,
            },
        }
    }
    /// Compile Erlang forms from a source string and return a BEAM image.
    pub fn compile(&self, src: &str) -> Result<Vec<u8>, Error> {
        self.compile_named("difftest_inline", src, &[])
    }
    /// Compile forms under an explicit module name and compiler options.
    pub fn compile_named(
        &self,
        module: &str,
        src: &str,
        opts: &[OwnedTerm],
    ) -> Result<Vec<u8>, Error> {
        let reply = self.request(
            "compile",
            vec![atom(module), string_term(src), list(opts.to_vec())],
        )?;
        match &reply {
            OwnedTerm::Tuple(xs) if xs.len() == 2 && is_atom(&xs[0], "ok") => match &xs[1] {
                OwnedTerm::Binary(b) => Ok(b.clone()),
                _ => Err(Error::Protocol(format!("compile reply: {xs:?}"))),
            },
            _ => Err(Error::Reference(reply)),
        }
    }
    /// Load a BEAM image on the reference node.
    pub fn load(&self, module: &str, beam: &[u8]) -> Result<(), Error> {
        let reply = self.request("load", vec![atom(module), OwnedTerm::Binary(beam.to_vec())])?;
        match &reply {
            OwnedTerm::Tuple(xs) if xs.len() == 2 && is_atom(&xs[0], "module") => Ok(()),
            _ => Err(Error::Reference(reply)),
        }
    }
    /// Evaluate an Erlang expression and return its term.
    pub fn eval(&self, expr: &str) -> Result<OwnedTerm, Error> {
        let term = self.request("eval", vec![string_term(expr)])?;
        match parse_call(term).result {
            CallResult::Ok(value) => Ok(value),
            other => Err(Error::Protocol(format!("eval: {other:?}"))),
        }
    }
    /// Send all calls before waiting for responses; used for throughput measurement.
    pub fn call_batch(&self, calls: &[(&str, &str, Vec<OwnedTerm>)]) -> Vec<CallResult> {
        let pending: Vec<_> = calls
            .iter()
            .map(|(m, f, args)| self.send("call", vec![atom(m), atom(f), list(args.clone())]))
            .collect();
        pending
            .into_iter()
            .map(|item| match item {
                Ok(rx) => match rx.recv() {
                    Ok(Ok(t)) => parse_call(t).result,
                    Ok(Err(e)) => CallResult::TransportError(e),
                    Err(e) => CallResult::TransportError(e.to_string()),
                },
                Err(e) => CallResult::TransportError(e.to_string()),
            })
            .collect()
    }
}
impl Vm for RefErl {
    fn call(&mut self, m: &str, f: &str, args: &[OwnedTerm]) -> CallResult {
        RefErl::call(self, m, f, args)
    }
    fn load(&mut self, module: &str, beam: &[u8]) -> Result<(), Error> {
        RefErl::load(self, module, beam)
    }
}
fn server_source() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tools/difftest/difftest_server.erl")
}
fn server_ebin() -> std::path::PathBuf {
    server_source().parent().unwrap().join("ebin")
}
fn spawn(ebin: &std::path::Path) -> Result<Process, Error> {
    let mut child = Command::new("erl")
        .args(["-noshell", "-pa"])
        .arg(ebin)
        .args([
            "-kernel",
            "logger_level",
            "emergency",
            "-s",
            "difftest_server",
            "main",
        ])
        .env("DIFFTEST_PARENT_PID", std::process::id().to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
    let routing = pending.clone();
    thread::spawn(move || {
        loop {
            let mut header = [0; 4];
            if stdout.read_exact(&mut header).is_err() {
                break;
            }
            let len = u32::from_be_bytes(header) as usize;
            if len > 64 * 1024 * 1024 {
                break;
            }
            let mut bytes = vec![0; len];
            if stdout.read_exact(&mut bytes).is_err() {
                break;
            }
            match codec::decode(&bytes) {
                Ok(mut reply) if matches!(&reply, OwnedTerm::Tuple(xs) if xs.len() == 2) => {
                    let OwnedTerm::Tuple(xs) = &mut reply else {
                        unreachable!()
                    };
                    if matches!(xs.first(), Some(OwnedTerm::Atom(name)) if name == "protocol_error")
                    {
                        break;
                    }
                    if let OwnedTerm::Int(id) = xs.remove(0)
                        && let Some(tx) = routing.lock().unwrap().remove(&(id as u64))
                    {
                        let _ = tx.send(Ok(xs.remove(0)));
                    }
                }
                _ => break,
            }
        }
        for (_, tx) in routing.lock().unwrap().drain() {
            let _ = tx.send(Err("reference process exited".into()));
        }
    });
    Ok(Process {
        child,
        stdin,
        pending,
    })
}
fn atom(s: &str) -> OwnedTerm {
    OwnedTerm::Atom(s.to_owned())
}
fn list(xs: Vec<OwnedTerm>) -> OwnedTerm {
    if xs.is_empty() {
        OwnedTerm::Nil
    } else {
        OwnedTerm::List {
            elems: xs,
            tail: Box::new(OwnedTerm::Nil),
        }
    }
}
fn string_term(s: &str) -> OwnedTerm {
    list(s.chars().map(|x| OwnedTerm::Int(x as i64)).collect())
}
fn pair(k: &str, v: OwnedTerm) -> OwnedTerm {
    OwnedTerm::Tuple(vec![atom(k), v])
}
fn is_atom(t: &OwnedTerm, s: &str) -> bool {
    matches!(t, OwnedTerm::Atom(x) if x == s)
}
fn parse_call(t: OwnedTerm) -> CallOutcome {
    let mut outcome = CallOutcome {
        result: CallResult::TransportError(format!("invalid reply {t:?}")),
        io: None,
        reductions: None,
        heap: None,
    };
    if is_atom(&t, "timeout") {
        outcome.result = CallResult::Timeout;
        return outcome;
    }
    if let OwnedTerm::Tuple(xs) = &t {
        if xs.len() >= 2 && is_atom(&xs[0], "ok") {
            outcome.result = CallResult::Ok(xs[1].clone());
        }
        if xs.len() >= 4 && is_atom(&xs[0], "exception") {
            outcome.result = CallResult::Exception {
                class: match &xs[1] {
                    OwnedTerm::Atom(s) => s.clone(),
                    _ => format!("{:?}", xs[1]),
                },
                reason: xs[2].clone(),
                stack_top: if is_atom(&xs[3], "undefined") {
                    None
                } else {
                    Some(xs[3].clone())
                },
            };
        }
        if let Some(OwnedTerm::List { elems, .. }) =
            xs.last().filter(|_| xs.len() == 3 || xs.len() == 5)
        {
            for item in elems {
                if let OwnedTerm::Tuple(kv) = item
                    && kv.len() == 2
                {
                    match (&kv[0], &kv[1]) {
                        (OwnedTerm::Atom(k), OwnedTerm::Binary(b)) if k == "io" => {
                            outcome.io = Some(b.clone())
                        }
                        (OwnedTerm::Atom(k), OwnedTerm::Int(n)) if k == "reductions" => {
                            outcome.reductions = Some(*n as u64)
                        }
                        (OwnedTerm::Atom(k), OwnedTerm::Int(n)) if k == "heap" => {
                            outcome.heap = Some(*n as u64)
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    outcome
}

/// Compare rules for Erlang strict and numeric equality.
#[derive(Debug, Clone, Copy)]
pub enum CompareMode {
    Exact,
    Equal,
}
/// A difference with the smallest known path into the result.
#[derive(Debug, Clone)]
pub struct Mismatch {
    pub path: String,
    pub left: String,
    pub right: String,
}
impl std::fmt::Display for Mismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {} != {}", self.path, self.left, self.right)
    }
}
impl std::error::Error for Mismatch {}
/// Compare two results, including exception class and reason. Stack frames are optional.
pub fn compare(a: &CallResult, b: &CallResult, mode: CompareMode) -> Result<(), Mismatch> {
    compare_with_stack(a, b, mode, false)
}
/// Compare two results and optionally require matching normalized stack tops.
pub fn compare_with_stack(
    a: &CallResult,
    b: &CallResult,
    mode: CompareMode,
    stack: bool,
) -> Result<(), Mismatch> {
    match (a, b) {
        (CallResult::Ok(x), CallResult::Ok(y)) => cmp_term(x, y, mode, "result"),
        (
            CallResult::Exception {
                class: ac,
                reason: ar,
                stack_top: ast,
            },
            CallResult::Exception {
                class: bc,
                reason: br,
                stack_top: bst,
            },
        ) => {
            if ac != bc {
                return mismatch("exception class", ac, bc);
            }
            cmp_term(ar, br, CompareMode::Exact, "exception reason")?;
            if stack {
                match (ast, bst) {
                    (Some(x), Some(y)) => cmp_term(x, y, CompareMode::Exact, "stack top"),
                    (None, None) => Ok(()),
                    _ => mismatch("stack top", ast, bst),
                }
            } else {
                Ok(())
            }
        }
        (CallResult::Timeout, CallResult::Timeout) => Ok(()),
        _ => Err(Mismatch {
            path: "result".into(),
            left: pretty_result(a),
            right: pretty_result(b),
        }),
    }
}
/// Render a term in compact Erlang-like notation for mismatch reports.
pub fn pretty(term: &OwnedTerm) -> String {
    match term {
        OwnedTerm::Int(n) => n.to_string(),
        OwnedTerm::BigInt(n) => n.to_string(),
        OwnedTerm::Float(f) => format!("{f:?}"),
        OwnedTerm::Atom(a)
            if a.starts_with(|c: char| c.is_ascii_lowercase())
                && a.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '@') =>
        {
            a.clone()
        }
        OwnedTerm::Atom(a) => format!("'{}'", a.replace('\'', "\\'")),
        OwnedTerm::Nil => "[]".into(),
        OwnedTerm::List { elems, tail } => {
            let mut text = elems.iter().map(pretty).collect::<Vec<_>>().join(",");
            if !matches!(**tail, OwnedTerm::Nil) {
                text.push('|');
                text.push_str(&pretty(tail));
            }
            format!("[{text}]")
        }
        OwnedTerm::Tuple(xs) => format!(
            "{{{}}}",
            xs.iter().map(pretty).collect::<Vec<_>>().join(",")
        ),
        OwnedTerm::Map(xs) => format!(
            "#{{{}}}",
            xs.iter()
                .map(|(k, v)| format!("{} => {}", pretty(k), pretty(v)))
                .collect::<Vec<_>>()
                .join(",")
        ),
        OwnedTerm::Binary(xs) => format!(
            "<<{}>>",
            xs.iter().map(u8::to_string).collect::<Vec<_>>().join(",")
        ),
        OwnedTerm::BitString { bytes, bits } => format!(
            "<<{}:{}>>",
            bytes
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(","),
            bits
        ),
        OwnedTerm::Pid {
            node, id, serial, ..
        } => format!("<{}.{id}.{serial}>", node),
        OwnedTerm::Port { node, id, .. } => format!("#Port<{}.{id}>", node),
        OwnedTerm::Ref { node, ids, .. } => format!(
            "#Ref<{}.{}>",
            node,
            ids.iter().map(u32::to_string).collect::<Vec<_>>().join(".")
        ),
        OwnedTerm::Export {
            module,
            function,
            arity,
        } => format!("fun {module}:{function}/{arity}"),
        other => format!("{other:?}"),
    }
}
fn pretty_result(result: &CallResult) -> String {
    match result {
        CallResult::Ok(term) => format!("ok {}", pretty(term)),
        CallResult::Exception { class, reason, .. } => format!("{class}:{}", pretty(reason)),
        CallResult::Timeout => "timeout".into(),
        CallResult::TransportError(error) => format!("transport error: {error}"),
    }
}
fn term_mismatch(path: &str, a: &OwnedTerm, b: &OwnedTerm) -> Result<(), Mismatch> {
    Err(Mismatch {
        path: path.into(),
        left: pretty(a),
        right: pretty(b),
    })
}
fn mismatch(path: &str, a: impl std::fmt::Debug, b: impl std::fmt::Debug) -> Result<(), Mismatch> {
    Err(Mismatch {
        path: path.into(),
        left: format!("{a:?}"),
        right: format!("{b:?}"),
    })
}
fn cmp_term(a: &OwnedTerm, b: &OwnedTerm, mode: CompareMode, path: &str) -> Result<(), Mismatch> {
    match (a, b) {
        (OwnedTerm::Int(x), OwnedTerm::Int(y)) if x == y => Ok(()),
        (OwnedTerm::BigInt(x), OwnedTerm::BigInt(y)) if x == y => Ok(()),
        (OwnedTerm::Int(x), OwnedTerm::BigInt(y)) | (OwnedTerm::BigInt(y), OwnedTerm::Int(x))
            if &BigInt::from(*x) == y =>
        {
            Ok(())
        }
        (OwnedTerm::Float(x), OwnedTerm::Float(y))
            if x.to_bits() == y.to_bits() || (matches!(mode, CompareMode::Equal) && x == y) =>
        {
            Ok(())
        }
        (OwnedTerm::Int(x), OwnedTerm::Float(y)) | (OwnedTerm::Float(y), OwnedTerm::Int(x))
            if matches!(mode, CompareMode::Equal)
                && float_integer(*y).as_ref() == Some(&BigInt::from(*x)) =>
        {
            Ok(())
        }
        (OwnedTerm::BigInt(x), OwnedTerm::Float(y))
        | (OwnedTerm::Float(y), OwnedTerm::BigInt(x))
            if matches!(mode, CompareMode::Equal) && float_integer(*y).as_ref() == Some(x) =>
        {
            Ok(())
        }
        (OwnedTerm::Atom(x), OwnedTerm::Atom(y)) if x == y => Ok(()),
        (OwnedTerm::Nil, OwnedTerm::Nil) => Ok(()),
        (OwnedTerm::Binary(x), OwnedTerm::Binary(y)) if x == y => Ok(()),
        (
            OwnedTerm::BitString {
                bytes: xb,
                bits: xn,
            },
            OwnedTerm::BitString {
                bytes: yb,
                bits: yn,
            },
        ) if xb == yb && xn == yn => Ok(()),
        (OwnedTerm::Tuple(xs), OwnedTerm::Tuple(ys)) => cmp_seq(xs, ys, mode, path, "element"),
        (
            OwnedTerm::List {
                elems: xs,
                tail: xt,
            },
            OwnedTerm::List {
                elems: ys,
                tail: yt,
            },
        ) => {
            cmp_seq(xs, ys, mode, path, "element")?;
            cmp_term(xt, yt, mode, &format!("{path} → tail"))
        }
        (OwnedTerm::Map(xs), OwnedTerm::Map(ys)) if xs.len() == ys.len() => {
            for (k, v) in xs {
                let Some((_, other)) = ys
                    .iter()
                    .find(|(key, _)| cmp_term(k, key, CompareMode::Exact, "key").is_ok())
                else {
                    return Err(Mismatch {
                        path: format!("{path} → key {}", pretty(k)),
                        left: pretty(v),
                        right: "missing".into(),
                    });
                };
                cmp_term(v, other, mode, &format!("{path} → key {}", pretty(k)))?;
            }
            Ok(())
        }
        (OwnedTerm::Float(_), OwnedTerm::Float(_)) => term_mismatch(path, a, b),
        _ if a == b => Ok(()),
        _ => term_mismatch(path, a, b),
    }
}
fn float_integer(value: f64) -> Option<BigInt> {
    if !value.is_finite() || value.fract() != 0.0 {
        return None;
    }
    BigInt::from_f64(value)
}
fn cmp_seq(
    xs: &[OwnedTerm],
    ys: &[OwnedTerm],
    mode: CompareMode,
    path: &str,
    name: &str,
) -> Result<(), Mismatch> {
    if xs.len() != ys.len() {
        return mismatch(&format!("{path} → arity/length"), xs.len(), ys.len());
    }
    for (i, (x, y)) in xs.iter().zip(ys).enumerate() {
        cmp_term(x, y, mode, &format!("{path} → {name} {}", i + 1))?;
    }
    Ok(())
}

/// Run a fixed case against two VMs and assert equivalent results.
#[macro_export]
macro_rules! difftest {
    ($name:ident, $m:expr, $f:expr, [$($arg:expr),* $(,)?]) => {
        #[test]
        fn $name() {
            let left = $crate::RefErl::start().expect("reference VM");
            let right = $crate::RefErl::start().expect("second reference VM");
            let args = vec![$($arg),*];
            let a = left.call($m, $f, &args);
            let b = right.call($m, $f, &args);
            $crate::compare(&a, &b, $crate::CompareMode::Exact).expect("differential mismatch");
        }
    };
    ($left:expr, $right:expr, $m:expr, $f:expr, [$($arg:expr),* $(,)?]) => {{
        let args = vec![$($arg),*];
        let a = $crate::Vm::call($left, $m, $f, &args);
        let b = $crate::Vm::call($right, $m, $f, &args);
        $crate::compare(&a, &b, $crate::CompareMode::Exact)
    }};
}

#[cfg(test)]
mod internal_tests {
    use super::*;
    #[test]
    fn restarts_after_reference_process_exits() {
        let erl = RefErl::start().unwrap();
        {
            let mut p = erl.process.lock().unwrap();
            p.child.kill().unwrap();
            p.child.wait().unwrap();
        }
        assert_eq!(
            erl.call("erlang", "abs", &[OwnedTerm::Int(-5)]),
            CallResult::Ok(OwnedTerm::Int(5))
        );
    }
}
