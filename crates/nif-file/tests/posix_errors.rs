use arinsal_bifs::{BifError, Ctx, ProcessHeapHandle};
use arinsal_difftest::{CallResult, Error as RefError, RefErl};
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{ProcessHeap, from_owned, to_owned};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn atom(value: &str) -> O {
    O::atom(value)
}

fn error(value: &str) -> O {
    O::Tuple(vec![atom("error"), atom(value)])
}

fn path(value: &Path) -> O {
    let mut bytes = value.as_os_str().as_encoded_bytes().to_vec();
    bytes.push(0);
    O::Binary(bytes)
}

fn name(value: &Path) -> O {
    O::Binary(value.as_os_str().as_encoded_bytes().to_vec())
}

fn call(function: &str, args: &[O]) -> Result<O, BifError> {
    let mut heap = ProcessHeap::with_words(2048);
    let mut alloc = ProcessHeapHandle(&mut heap);
    let terms = args
        .iter()
        .map(|arg| from_owned(arg, &mut alloc).unwrap())
        .collect::<Vec<_>>();
    let mut ctx = Ctx::new(&mut alloc);
    let nif = arinsal_nif_file::lookup("prim_file", function, args.len() as u8).unwrap();
    nif(&mut ctx, &terms).map(|term| to_owned(term).unwrap())
}

fn expected(reference: &RefErl, function: &str, args: &[O]) -> O {
    match reference.call("prim_file", function, args) {
        CallResult::Ok(value) => value,
        other => panic!("prim_file:{function} returned {other:?}"),
    }
}

fn reference() -> Option<&'static RefErl> {
    match RefErl::shared() {
        Ok(reference) => Some(reference),
        Err(RefError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipping OTP differential: erl or erlc not found");
            None
        }
        Err(error) => panic!("OTP reference failed: {error}"),
    }
}

struct RestoreCwds {
    own_cwd: PathBuf,
    reference: &'static RefErl,
    reference_cwd: O,
}

impl Drop for RestoreCwds {
    fn drop(&mut self) {
        let _ = env::set_current_dir(&self.own_cwd);
        let _ = self.reference.call(
            "prim_file",
            "set_cwd",
            std::slice::from_ref(&self.reference_cwd),
        );
    }
}

#[test]
fn directory_rename_and_removed_cwd_errors_match_otp() {
    let Some(reference) = reference() else {
        return;
    };
    let root = tempfile::tempdir().unwrap();
    let own_cwd = env::current_dir().unwrap();
    let reference_cwd = expected(reference, "get_cwd", &[]);
    let O::Tuple(ref cwd_parts) = reference_cwd else {
        panic!("prim_file:get_cwd returned no result tuple");
    };
    similar_asserts::assert_eq!(cwd_parts[0], atom("ok"));
    let _restore = RestoreCwds {
        own_cwd,
        reference,
        reference_cwd: cwd_parts[1].clone(),
    };

    let nonempty = root.path().join("nonempty");
    fs::create_dir(&nonempty).unwrap();
    fs::write(nonempty.join("child"), b"content").unwrap();
    let own = call("del_dir_nif", &[path(&nonempty)]).unwrap();
    let erl = expected(reference, "del_dir", &[name(&nonempty)]);
    similar_asserts::assert_eq!(erl, error("eexist"));
    similar_asserts::assert_eq!(own, erl);

    let source = root.path().join("source");
    let destination = root.path().join("destination");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("child"), b"source").unwrap();
    fs::create_dir(&destination).unwrap();
    fs::write(destination.join("child"), b"destination").unwrap();
    let own = call("rename_nif", &[path(&source), path(&destination)]).unwrap();
    let erl = expected(reference, "rename", &[name(&source), name(&destination)]);
    similar_asserts::assert_eq!(erl, error("eexist"));
    similar_asserts::assert_eq!(own, erl);

    let root_target = root.path().join("renamed-root");
    let own = call("rename_nif", &[path(Path::new("/")), path(&root_target)]).unwrap();
    let erl = expected(
        reference,
        "rename",
        &[name(Path::new("/")), name(&root_target)],
    );
    similar_asserts::assert_eq!(erl, error("einval"));
    similar_asserts::assert_eq!(own, erl);

    let missing = root.path().join("missing");
    let own = call("set_cwd_nif", &[path(&missing)]).unwrap();
    let erl = expected(reference, "set_cwd", &[name(&missing)]);
    similar_asserts::assert_eq!(erl, error("enoent"));
    similar_asserts::assert_eq!(own, erl);

    let current = root.path().join("current");
    fs::create_dir(&current).unwrap();
    fs::write(current.join("child"), b"content").unwrap();
    let own = call("set_cwd_nif", &[path(&current)]).unwrap();
    let erl = expected(reference, "set_cwd", &[name(&current)]);
    similar_asserts::assert_eq!(erl, atom("ok"));
    similar_asserts::assert_eq!(own, erl);
    let own = call("del_dir_nif", &[path(&current)]).unwrap();
    let erl = expected(reference, "del_dir", &[name(&current)]);
    similar_asserts::assert_eq!(erl, error("einval"));
    similar_asserts::assert_eq!(own, erl);

    let removed_cwd = root.path().join("removed-cwd");
    fs::create_dir(&removed_cwd).unwrap();
    let own = call("set_cwd_nif", &[path(&removed_cwd)]).unwrap();
    let erl = expected(reference, "set_cwd", &[name(&removed_cwd)]);
    similar_asserts::assert_eq!(erl, atom("ok"));
    similar_asserts::assert_eq!(own, erl);
    fs::remove_dir(&removed_cwd).unwrap();
    let own = call("get_cwd_nif", &[]).unwrap();
    let erl = expected(reference, "get_cwd", &[]);
    similar_asserts::assert_eq!(erl, error("enoent"));
    similar_asserts::assert_eq!(own, erl);
    let own = call("set_cwd_nif", &[path(&removed_cwd)]).unwrap();
    let erl = expected(reference, "set_cwd", &[name(&removed_cwd)]);
    similar_asserts::assert_eq!(erl, error("enoent"));
    similar_asserts::assert_eq!(own, erl);
}
