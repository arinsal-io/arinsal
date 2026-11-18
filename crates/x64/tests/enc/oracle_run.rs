//! Builds and runs the asmjit oracle (`tests/asmjit_oracle/oracle.cpp`).
//!
//! The oracle links the asmjit sources that erts 29.1.1 vendors (`erts/emulator/asmjit`, built
//! with the flags of `erts/emulator/Makefile.in` `ASMJIT_FLAGS`). Objects and the harness binary
//! are cached under `CARGO_TARGET_TMPDIR/asmjit_oracle`; every file is written under a private
//! name and renamed, so concurrent test processes need no lock. The asmjit source root is
//! `$ASMJIT_SRC` or `<repo>/ref/otp-29/erts/emulator` (the directory containing `asmjit/`).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Bytes (hex-decoded) or the asmjit error name for one oracle case.
pub type OracleResult = Result<Vec<u8>, String>;

const FLAGS: &[&str] = &[
    "-std=c++17",
    "-O1",
    "-DASMJIT_EMBED=1",
    "-DASMJIT_NO_BUILDER=1",
    "-DASMJIT_NO_COMPILER=1",
    "-DASMJIT_NO_UJIT=1",
    "-DASMJIT_NO_DEPRECATED=1",
    "-DASMJIT_STATIC=1",
    "-DASMJIT_NO_FOREIGN=1",
];

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn cxx() -> String {
    std::env::var("CXX").unwrap_or_else(|_| "c++".into())
}

fn asmjit_root() -> Option<PathBuf> {
    let root = match std::env::var_os("ASMJIT_SRC") {
        Some(p) => PathBuf::from(p),
        None => manifest_dir().join("../../ref/otp-29/erts/emulator"),
    };
    root.join("asmjit/x86/x86assembler.cpp")
        .exists()
        .then_some(root)
}

fn compile(args: &[&str], out: &Path) -> Result<(), String> {
    let tmp = out.with_extension(format!("tmp{}", std::process::id()));
    let res = Command::new(cxx())
        .args(args)
        .arg("-o")
        .arg(&tmp)
        .output()
        .map_err(|e| format!("cannot run {}: {e}", cxx()))?;
    if !res.status.success() {
        let _ = std::fs::remove_file(&tmp);
        return Err(String::from_utf8_lossy(&res.stderr).into_owned());
    }
    std::fs::rename(&tmp, out).map_err(|e| e.to_string())
}

fn build(root: &Path) -> Result<PathBuf, String> {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("asmjit_oracle");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let harness = manifest_dir().join("tests/asmjit_oracle/oracle.cpp");
    let bin = dir.join("oracle");
    let mtime = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    if let (Some(b), Some(h)) = (mtime(&bin), mtime(&harness))
        && b >= h
    {
        return Ok(bin);
    }
    let inc = format!("-I{}", root.display());
    let mut sources = Vec::new();
    for sub in ["core", "support", "x86"] {
        let d = root.join("asmjit").join(sub);
        for entry in std::fs::read_dir(&d).map_err(|e| e.to_string())? {
            let p = entry.map_err(|e| e.to_string())?.path();
            if p.extension().is_some_and(|e| e == "cpp") {
                sources.push((sub, p));
            }
        }
    }
    let errors = std::sync::Mutex::new(Vec::new());
    let next = std::sync::atomic::AtomicUsize::new(0);
    let objs: Vec<PathBuf> = sources
        .iter()
        .map(|(sub, p)| {
            dir.join(format!(
                "{sub}_{}.o",
                p.file_stem().unwrap().to_string_lossy()
            ))
        })
        .collect();
    std::thread::scope(|s| {
        for _ in 0..std::thread::available_parallelism().map_or(4, |n| n.get()) {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some((_, src)) = sources.get(i) else {
                        break;
                    };
                    if objs[i].exists() {
                        continue;
                    }
                    let mut args: Vec<&str> = FLAGS.to_vec();
                    args.extend(["-c", &inc, src.to_str().unwrap()]);
                    if let Err(e) = compile(&args, &objs[i]) {
                        errors.lock().unwrap().push(e);
                    }
                }
            });
        }
    });
    if let Some(e) = errors.into_inner().unwrap().first() {
        return Err(e.clone());
    }
    let mut args: Vec<&str> = FLAGS.to_vec();
    args.push(&inc);
    args.push(harness.to_str().unwrap());
    let obj_strs: Vec<String> = objs.iter().map(|o| o.display().to_string()).collect();
    args.extend(obj_strs.iter().map(String::as_str));
    compile(&args, &bin)?;
    Ok(bin)
}

/// Builds the oracle once per process. `None` (with the reason on stderr) when asmjit sources or a
/// C++ compiler are missing, so the caller skips instead of failing on machines without them.
pub fn oracle() -> Option<PathBuf> {
    let Some(root) = asmjit_root() else {
        eprintln!(
            "asmjit oracle skipped: asmjit sources not found (set ASMJIT_SRC to the directory \
             containing asmjit/, default ref/otp-29/erts/emulator)"
        );
        return None;
    };
    if Command::new(cxx()).arg("--version").output().is_err() {
        eprintln!("asmjit oracle skipped: no C++ compiler ({})", cxx());
        return None;
    }
    match build(&root) {
        Ok(bin) => Some(bin),
        Err(e) => panic!("building the asmjit oracle failed:\n{e}"),
    }
}

/// Encodes every case line with asmjit; one result per line.
pub fn run(bin: &Path, lines: &[&str]) -> Vec<OracleResult> {
    let mut child = Command::new(bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn oracle");
    let mut stdin = child.stdin.take().expect("oracle stdin");
    let input: String = lines.iter().map(|l| format!("{l}\n")).collect();
    // Feed from a thread: the oracle's stdout pipe fills while we are still writing.
    let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()));
    let out = child.wait_with_output().expect("oracle output");
    writer
        .join()
        .expect("oracle writer")
        .expect("write oracle input");
    let text = String::from_utf8(out.stdout).expect("oracle utf8");
    let results: Vec<OracleResult> = text
        .lines()
        .map(|l| match l.split_once(' ') {
            Some(("OK", hex)) => Ok((0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
                .collect()),
            Some(("ERR", name)) => Err(name.to_string()),
            _ if l == "OK" => Ok(Vec::new()),
            _ => panic!("bad oracle line {l:?}"),
        })
        .collect();
    assert_eq!(results.len(), lines.len(), "oracle answered every case");
    results
}
