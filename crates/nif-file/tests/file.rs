use arinsal_bifs::{BifError, Ctx, ProcessHeapHandle};
use arinsal_difftest::{CallResult, Error as RefError, RefErl};
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{ProcessHeap, from_owned, to_owned};
use std::fs;
use std::os::fd::IntoRawFd;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;

fn atom(s: &str) -> O {
    O::atom(s)
}
fn iovec(bytes: &[u8]) -> O {
    O::list(vec![O::Binary(bytes.to_vec())])
}
fn path(p: &Path) -> O {
    let mut bytes = p.as_os_str().as_encoded_bytes().to_vec();
    bytes.push(0);
    O::Binary(bytes)
}
fn name(p: &Path) -> O {
    O::Binary(p.as_os_str().as_encoded_bytes().to_vec())
}
fn call(f: &str, args: &[O]) -> Result<O, BifError> {
    let mut heap = ProcessHeap::with_words(2048);
    let mut alloc = ProcessHeapHandle(&mut heap);
    let terms = args
        .iter()
        .map(|a| from_owned(a, &mut alloc).unwrap())
        .collect::<Vec<_>>();
    let mut ctx = Ctx::new(&mut alloc);
    let nif = arinsal_nif_file::lookup("prim_file", f, args.len() as u8).unwrap();
    nif(&mut ctx, &terms).map(|value| to_owned(value).unwrap())
}
fn success(value: O) -> O {
    O::Tuple(vec![atom("ok"), value])
}
fn error(value: &str) -> O {
    O::Tuple(vec![atom("error"), atom(value)])
}
fn expected(reference: &RefErl, fun: &str, args: &[O]) -> O {
    expected_module(reference, "prim_file", fun, args)
}
fn expected_module(reference: &RefErl, module: &str, fun: &str, args: &[O]) -> O {
    match reference.call(module, fun, args) {
        CallResult::Ok(o) => o,
        other => panic!("{fun} returned {other:?}"),
    }
}
fn reference() -> Option<&'static RefErl> {
    match RefErl::shared() {
        Ok(r) => Some(r),
        Err(RefError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipping OTP differential: erl or erlc not found");
            None
        }
        Err(e) => panic!("OTP reference failed: {e}"),
    }
}
#[test]
fn registry_exact() {
    let entries = [
        ("open_nif", 2),
        ("close_nif", 1),
        ("read_nif", 2),
        ("write_nif", 2),
        ("pread_nif", 3),
        ("pwrite_nif", 3),
        ("seek_nif", 3),
        ("sync_nif", 2),
        ("truncate_nif", 1),
        ("allocate_nif", 3),
        ("advise_nif", 4),
        ("read_handle_info_nif", 1),
        ("make_hard_link_nif", 2),
        ("make_soft_link_nif", 2),
        ("rename_nif", 2),
        ("read_info_nif", 2),
        ("set_permissions_nif", 2),
        ("set_owner_nif", 3),
        ("set_time_nif", 4),
        ("read_link_nif", 1),
        ("list_dir_nif", 1),
        ("make_dir_nif", 1),
        ("del_file_nif", 1),
        ("del_dir_nif", 1),
        ("get_device_cwd_nif", 1),
        ("set_cwd_nif", 1),
        ("get_cwd_nif", 0),
        ("ipread_s32bu_p32bu_nif", 3),
        ("read_file_nif", 1),
        ("get_handle_nif", 1),
        ("delayed_close_nif", 1),
        ("altname_nif", 1),
        ("file_desc_to_ref_nif", 1),
    ];
    for (name, arity) in entries {
        assert!(
            arinsal_nif_file::lookup("prim_file", name, arity).is_some(),
            "{name}"
        );
    }
    assert!(arinsal_nif_file::lookup("file", "open_nif", 2).is_none());
}
#[test]
fn handle_io_and_sparse_offsets() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("data");
    let opened = call(
        "open_nif",
        &[path(&file), O::list(vec![atom("read"), atom("write")])],
    )
    .unwrap();
    let O::Tuple(ref parts) = opened else {
        panic!("open failed")
    };
    assert_eq!(parts[0], atom("ok"));
    let handle = parts[1].clone();
    assert_eq!(
        call("write_nif", &[handle.clone(), iovec(b"abc")]).unwrap(),
        atom("ok")
    );
    assert_eq!(
        call("seek_nif", &[handle.clone(), atom("bof"), O::Int(0)]).unwrap(),
        success(O::Int(0))
    );
    assert_eq!(
        call("read_nif", &[handle.clone(), O::Int(3)]).unwrap(),
        success(O::Binary(b"abc".to_vec()))
    );
    assert_eq!(
        call("pread_nif", &[handle.clone(), O::Int(1), O::Int(2)]).unwrap(),
        success(O::Binary(b"bc".to_vec()))
    );
    assert_eq!(
        call(
            "pwrite_nif",
            &[handle.clone(), O::Int(4_294_967_310), iovec(b"Z")]
        )
        .unwrap(),
        atom("ok")
    );
    assert_eq!(
        call(
            "pread_nif",
            &[handle.clone(), O::Int(4_294_967_310), O::Int(1)]
        )
        .unwrap(),
        success(O::Binary(b"Z".to_vec()))
    );
    assert_eq!(
        call("sync_nif", &[handle.clone(), O::Int(0)]).unwrap(),
        atom("ok")
    );
    assert_eq!(
        call("sync_nif", &[handle.clone(), O::Int(1)]).unwrap(),
        atom("ok")
    );
    assert_eq!(
        call(
            "advise_nif",
            &[handle.clone(), O::Int(0), O::Int(8), atom("sequential")]
        )
        .unwrap(),
        atom("ok")
    );
    let O::Binary(ref raw_handle) = call("get_handle_nif", std::slice::from_ref(&handle)).unwrap()
    else {
        panic!("native handle")
    };
    assert_eq!(raw_handle.len(), 4);
    let info = call("read_handle_info_nif", std::slice::from_ref(&handle)).unwrap();
    let O::Tuple(ref fields) = info else {
        panic!("file_info")
    };
    assert_eq!(fields[1], O::Int(4_294_967_311));
    if let Some(reference) = reference() {
        assert_eq!(
            success(info),
            expected(
                reference,
                "read_file_info",
                &[
                    name(&file),
                    O::list(vec![O::Tuple(vec![atom("time"), atom("posix")])])
                ]
            )
        );
    }
    assert_eq!(
        call("read_nif", &[handle.clone(), O::Int(0)]).unwrap(),
        atom("eof")
    );
    assert_eq!(
        call("close_nif", std::slice::from_ref(&handle)).unwrap(),
        atom("ok")
    );
    assert_eq!(
        call("close_nif", std::slice::from_ref(&handle)).unwrap(),
        error("einval")
    );
    assert_eq!(
        call("read_nif", &[handle, O::Int(1)]).unwrap(),
        error("einval")
    );
}
#[test]
fn pointer_read_allocate_and_truncate() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("pointer");
    let opened = call(
        "open_nif",
        &[path(&file), O::list(vec![atom("read"), atom("write")])],
    )
    .unwrap();
    let O::Tuple(ref parts) = opened else {
        panic!("open")
    };
    let handle = parts[1].clone();
    assert_eq!(
        call(
            "write_nif",
            &[
                handle.clone(),
                iovec(&[4_u32.to_be_bytes(), 16_u32.to_be_bytes()].concat())
            ]
        )
        .unwrap(),
        atom("ok")
    );
    assert_eq!(
        call("pwrite_nif", &[handle.clone(), O::Int(16), iovec(b"data")]).unwrap(),
        atom("ok")
    );
    assert_eq!(
        call(
            "ipread_s32bu_p32bu_nif",
            &[handle.clone(), O::Int(0), O::Int(4)]
        )
        .unwrap(),
        success(O::Tuple(vec![
            O::Int(4),
            O::Int(16),
            O::Binary(b"data".to_vec())
        ]))
    );
    assert_eq!(
        call(
            "ipread_s32bu_p32bu_nif",
            &[handle.clone(), O::Int(0), O::Int(3)]
        )
        .unwrap(),
        atom("eof")
    );
    assert_eq!(
        call("allocate_nif", &[handle.clone(), O::Int(20), O::Int(32)]).unwrap(),
        atom("ok")
    );
    assert_eq!(fs::metadata(&file).unwrap().len(), 52);
    assert_eq!(
        call("seek_nif", &[handle.clone(), atom("bof"), O::Int(3)]).unwrap(),
        success(O::Int(3))
    );
    assert_eq!(
        call("truncate_nif", std::slice::from_ref(&handle)).unwrap(),
        atom("ok")
    );
    assert_eq!(fs::metadata(&file).unwrap().len(), 3);
    assert_eq!(
        call("close_nif", std::slice::from_ref(&handle)).unwrap(),
        atom("ok")
    );
}
#[test]
fn differential_path_operations() {
    let Some(reference) = reference() else { return };
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("file");
    let dir = root.path().join("dir");
    let link = root.path().join("link");
    fs::write(&file, b"hello").unwrap();
    fs::create_dir(&dir).unwrap();
    symlink(&file, &link).unwrap();
    for p in [&file, &dir, &link] {
        let direct = call("read_info_nif", &[path(p), O::Int(0)]).unwrap();
        let wrapped = expected(
            reference,
            "read_link_info",
            &[
                name(p),
                O::list(vec![O::Tuple(vec![atom("time"), atom("posix")])]),
            ],
        );
        assert_eq!(success(direct), wrapped, "{}", p.display());
        let direct = call("read_info_nif", &[path(p), O::Int(1)]).unwrap();
        let wrapped = expected(
            reference,
            "read_file_info",
            &[
                name(p),
                O::list(vec![O::Tuple(vec![atom("time"), atom("posix")])]),
            ],
        );
        assert_eq!(success(direct), wrapped, "{}", p.display());
    }
    assert_eq!(
        call("read_file_nif", &[path(&file)]).unwrap(),
        expected(reference, "read_file", &[name(&file)])
    );
    assert_eq!(
        call("get_device_cwd_nif", &[O::Int(0)]).unwrap(),
        error("enotsup")
    );
    assert_eq!(
        call("altname_nif", &[path(&file)]).unwrap(),
        expected(reference, "altname", &[name(&file)])
    );
    let mut cases = 0;
    for n in 0..250 {
        let missing = root.path().join(format!("missing-{n}"));
        let native = path(&missing);
        let erl = name(&missing);
        for (nif, wrapper) in [
            ("read_file_nif", "read_file"),
            ("read_link_nif", "read_link"),
            ("list_dir_nif", "list_dir"),
            ("make_dir_nif", "make_dir"),
            ("del_file_nif", "delete"),
            ("del_dir_nif", "del_dir"),
            ("altname_nif", "altname"),
        ] {
            let actual = call(nif, std::slice::from_ref(&native)).unwrap();
            if wrapper == "make_dir" {
                fs::remove_dir(&missing).unwrap();
            }
            let want = expected(reference, wrapper, std::slice::from_ref(&erl));
            if wrapper == "make_dir" {
                assert_eq!(actual, want);
                fs::remove_dir(&missing).unwrap();
            } else {
                assert_eq!(actual, want, "{nif} case {n}");
            }
            cases += 1;
        }
        let actual = call("read_info_nif", &[native.clone(), O::Int(0)]).unwrap();
        let want = expected(reference, "read_link_info", &[erl]);
        assert_eq!(actual, want, "read_info case {n}");
        cases += 1;
    }
    assert_eq!(cases, 2_000);
    eprintln!("{cases} OTP wrapper differential cases, zero mismatches");
}
#[test]
fn differential_real_directory_and_links() {
    let Some(reference) = reference() else { return };
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("parent");
    fs::create_dir(&dir).unwrap();
    let source = dir.join("source");
    fs::write(&source, b"content").unwrap();
    for n in 0..32 {
        fs::write(dir.join(format!("file-{n:02}")), [n as u8]).unwrap();
    }
    let O::Tuple(ref own) = call("list_dir_nif", &[path(&dir)]).unwrap() else {
        panic!("list_dir result")
    };
    assert_eq!(own[0], atom("ok"));
    let O::List {
        elems: own_names, ..
    } = &own[1]
    else {
        panic!("list_dir entries")
    };
    let mut own_names = own_names
        .iter()
        .map(|o| match o {
            O::Binary(b) => String::from_utf8(b.clone()).unwrap(),
            _ => panic!("binary name"),
        })
        .collect::<Vec<_>>();
    let wrapped = expected(reference, "list_dir", &[name(&dir)]);
    let O::Tuple(ref parts) = wrapped else {
        panic!("list_dir wrapper")
    };
    let O::List {
        elems: ref_names, ..
    } = &parts[1]
    else {
        panic!("list_dir wrapper entries")
    };
    let mut ref_names = ref_names
        .iter()
        .map(|o| match o {
            O::List { elems, .. } => elems
                .iter()
                .map(|c| match c {
                    O::Int(n) => *n as u8 as char,
                    _ => panic!("name char"),
                })
                .collect::<String>(),
            _ => panic!("name list"),
        })
        .collect::<Vec<_>>();
    own_names.sort();
    ref_names.sort();
    assert_eq!(own_names, ref_names);
    let hard = dir.join("hard");
    assert_eq!(
        call("make_hard_link_nif", &[path(&source), path(&hard)]).unwrap(),
        atom("ok")
    );
    fs::remove_file(&hard).unwrap();
    assert_eq!(
        expected(reference, "make_link", &[name(&source), name(&hard)]),
        atom("ok")
    );
    fs::remove_file(&hard).unwrap();
    let soft = dir.join("soft");
    assert_eq!(
        call("make_soft_link_nif", &[path(&source), path(&soft)]).unwrap(),
        atom("ok")
    );
    let direct = call("read_link_nif", &[path(&soft)]).unwrap();
    assert_eq!(
        direct,
        success(O::Binary(source.as_os_str().as_encoded_bytes().to_vec()))
    );
    assert_eq!(
        expected(reference, "read_link", &[name(&soft)]),
        success(O::charlist(source.to_str().unwrap()))
    );
    fs::remove_file(&soft).unwrap();
    assert_eq!(
        expected(reference, "make_symlink", &[name(&source), name(&soft)]),
        atom("ok")
    );
    fs::remove_file(&soft).unwrap();
    let moved = dir.join("moved");
    assert_eq!(
        call("rename_nif", &[path(&source), path(&moved)]).unwrap(),
        atom("ok")
    );
    fs::rename(&moved, &source).unwrap();
    assert_eq!(
        expected(reference, "rename", &[name(&source), name(&moved)]),
        atom("ok")
    );
    fs::rename(&moved, &source).unwrap();
}
#[test]
fn differential_permissions_and_timestamps() {
    let Some(reference) = reference() else { return };
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("permissions");
    let erl_file = root.path().join("permissions-erl");
    fs::write(&file, b"x").unwrap();
    fs::write(&erl_file, b"x").unwrap();
    let mode = O::Int(0o640);
    assert_eq!(
        call("set_permissions_nif", &[path(&file), mode.clone()]).unwrap(),
        expected_module(reference, "file", "change_mode", &[name(&erl_file), mode])
    );
    let own = call("read_info_nif", &[path(&file), O::Int(1)]).unwrap();
    let O::Tuple(ref fields) = own else {
        panic!("file_info")
    };
    assert_eq!(fields[7], O::Int(0o100640));
    let meta = fs::metadata(&file).unwrap();
    assert_eq!(
        call(
            "set_owner_nif",
            &[
                path(&file),
                O::Int(i64::from(std::os::unix::fs::MetadataExt::uid(&meta))),
                O::Int(i64::from(std::os::unix::fs::MetadataExt::gid(&meta)))
            ]
        )
        .unwrap(),
        expected_module(
            reference,
            "file",
            "change_owner",
            &[
                name(&erl_file),
                O::Int(i64::from(std::os::unix::fs::MetadataExt::uid(&meta))),
                O::Int(i64::from(std::os::unix::fs::MetadataExt::gid(&meta)))
            ]
        )
    );
    assert_eq!(
        call(
            "set_time_nif",
            &[
                path(&file),
                O::Int(1_000_000_000),
                O::Int(1_000_000_001),
                O::Int(1_000_000_002)
            ]
        )
        .unwrap(),
        atom("ok")
    );
    let own = call("read_info_nif", &[path(&file), O::Int(1)]).unwrap();
    let O::Tuple(ref fields) = own else {
        panic!("file_info")
    };
    assert_eq!(fields[4], O::Int(1_000_000_000));
    assert_eq!(fields[5], O::Int(1_000_000_001));
    assert_eq!(
        success(own),
        expected(
            reference,
            "read_file_info",
            &[
                name(&file),
                O::list(vec![O::Tuple(vec![atom("time"), atom("posix")])])
            ]
        )
    );
}

#[test]
fn differential_set_time_on_execute_only_file() {
    let Some(reference) = reference() else { return };
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("execute-only");
    let erl_file = root.path().join("execute-only-erl");
    fs::write(&file, b"x").unwrap();
    fs::write(&erl_file, b"x").unwrap();
    let mode = O::Int(0o100);
    assert_eq!(
        call("set_permissions_nif", &[path(&file), mode.clone()]).unwrap(),
        expected_module(reference, "file", "change_mode", &[name(&erl_file), mode])
    );
    let mut info = expected(
        reference,
        "read_file_info",
        &[
            name(&erl_file),
            O::list(vec![O::Tuple(vec![atom("time"), atom("posix")])]),
        ],
    );
    let O::Tuple(ref mut result) = info else {
        panic!("file_info")
    };
    assert_eq!(result[0], atom("ok"));
    let O::Tuple(ref mut fields) = result[1] else {
        panic!("file_info record")
    };
    fields[5] = O::Int(1_000_000_001);
    let expected_result = expected_module(
        reference,
        "file",
        "write_file_info",
        &[
            name(&erl_file),
            result[1].clone(),
            O::list(vec![O::Tuple(vec![atom("time"), atom("posix")])]),
        ],
    );
    assert_eq!(
        call(
            "set_time_nif",
            &[
                path(&file),
                O::Int(1_000_000_000),
                O::Int(1_000_000_001),
                O::Int(1_000_000_002),
            ]
        )
        .unwrap(),
        expected_result
    );
}
#[test]
fn differential_open_and_permission_errors() {
    let Some(reference) = reference() else { return };
    let root = tempfile::tempdir().unwrap();
    for n in 0..120 {
        let absent = root.path().join(format!("absent-{n}"));
        for modes in [
            vec![atom("read")],
            vec![atom("read"), atom("sync")],
            vec![atom("directory")],
        ] {
            assert_eq!(
                call("open_nif", &[path(&absent), O::list(modes.clone())]).unwrap(),
                expected(reference, "open", &[name(&absent), O::list(modes)])
            );
        }
    }
    let private = root.path().join("private");
    fs::create_dir(&private).unwrap();
    let protected = private.join("inside");
    fs::write(&protected, b"secret").unwrap();
    fs::set_permissions(&private, fs::Permissions::from_mode(0o0)).unwrap();
    let direct_read = call("read_file_nif", &[path(&protected)]).unwrap();
    let erl_read = expected(reference, "read_file", &[name(&protected)]);
    let direct_list = call("list_dir_nif", &[path(&private)]).unwrap();
    let erl_list = expected(reference, "list_dir", &[name(&private)]);
    fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(direct_read, erl_read);
    assert_eq!(direct_list, erl_list);
}
#[test]
fn iovec_continuation_and_badarg() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("segments");
    let opened = call(
        "open_nif",
        &[path(&file), O::list(vec![atom("read"), atom("write")])],
    )
    .unwrap();
    let O::Tuple(ref parts) = opened else {
        panic!("open")
    };
    let handle = parts[1].clone();
    assert_eq!(
        call("write_nif", &[handle.clone(), O::Binary(b"x".to_vec())]),
        Err(BifError::BADARG)
    );
    assert_eq!(
        call("read_nif", &[handle.clone(), O::Float(1.0)]).unwrap(),
        error("einval")
    );
    assert_eq!(
        call("pread_nif", &[handle.clone(), O::Float(1.0), O::Int(1)]).unwrap(),
        error("einval")
    );
    assert_eq!(
        call("pwrite_nif", &[handle.clone(), O::Float(1.0), iovec(b"x")]).unwrap(),
        error("einval")
    );
    assert_eq!(
        call("seek_nif", &[handle.clone(), atom("bof"), O::Float(1.0)]),
        Err(BifError::BADARG)
    );
    let segments = O::list((0..65).map(|_| O::Binary(b"x".to_vec())).collect());
    let result = call("write_nif", &[handle.clone(), segments.clone()]).unwrap();
    let O::Tuple(ref parts) = result else {
        panic!("continue")
    };
    assert_eq!(parts[0], atom("continue"));
    assert_eq!(
        call("write_nif", &[handle.clone(), parts[1].clone()]).unwrap(),
        atom("ok")
    );
    let result = call("pwrite_nif", &[handle.clone(), O::Int(100), segments]).unwrap();
    let O::Tuple(ref parts) = result else {
        panic!("continue")
    };
    assert_eq!(parts[0], atom("continue"));
    assert_eq!(parts[1], O::Int(64));
    assert_eq!(
        call(
            "pwrite_nif",
            &[handle.clone(), O::Int(164), parts[2].clone()]
        )
        .unwrap(),
        atom("ok")
    );
    assert_eq!(
        call("pread_nif", &[handle.clone(), O::Int(100), O::Int(65)]).unwrap(),
        success(O::Binary(vec![b'x'; 65]))
    );
    assert_eq!(
        call("close_nif", std::slice::from_ref(&handle)).unwrap(),
        atom("ok")
    );
}
#[test]
fn cwd_descriptor_and_delayed_close() {
    let root = tempfile::tempdir().unwrap();
    let cwd = std::env::current_dir().unwrap();
    assert_eq!(
        call("get_cwd_nif", &[]).unwrap(),
        success(O::Binary(cwd.as_os_str().as_encoded_bytes().to_vec()))
    );
    assert_eq!(call("set_cwd_nif", &[path(&cwd)]).unwrap(), atom("ok"));
    if let Some(reference) = reference() {
        assert_eq!(
            expected(reference, "get_cwd", &[]),
            success(O::charlist(cwd.to_str().unwrap()))
        );
        assert_eq!(expected(reference, "set_cwd", &[name(&cwd)]), atom("ok"));
        assert_eq!(
            call("file_desc_to_ref_nif", &[O::Int(-1)]).unwrap(),
            expected(
                reference,
                "file_desc_to_ref",
                &[O::Int(-1), O::list(vec![atom("read")])]
            )
        );
    }
    let file = root.path().join("delayed");
    let opened = call("open_nif", &[path(&file), O::list(vec![atom("write")])]).unwrap();
    let O::Tuple(ref parts) = opened else {
        panic!("open")
    };
    let handle = parts[1].clone();
    assert_eq!(
        call("delayed_close_nif", std::slice::from_ref(&handle)).unwrap(),
        atom("ok")
    );
    assert_eq!(
        call("close_nif", std::slice::from_ref(&handle)).unwrap(),
        error("einval")
    );
    fs::write(&file, b"fd").unwrap();
    let fd = fs::File::open(&file).unwrap().into_raw_fd();
    let wrapped = call("file_desc_to_ref_nif", &[O::Int(i64::from(fd))]).unwrap();
    let O::Tuple(ref parts) = wrapped else {
        panic!("descriptor")
    };
    let descriptor = parts[1].clone();
    assert_eq!(
        call("read_nif", &[descriptor.clone(), O::Int(2)]).unwrap(),
        success(O::Binary(b"fd".to_vec()))
    );
    assert_eq!(
        call("close_nif", std::slice::from_ref(&descriptor)).unwrap(),
        atom("ok")
    );
}

#[test]
fn handle_reference_decodes_on_any_node() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("handle");
    fs::write(&file, b"x").unwrap();
    let opened = call("open_nif", &[path(&file), O::list(vec![atom("read")])]).unwrap();
    let O::Tuple(ref parts) = opened else {
        panic!("open result")
    };
    let O::Ref { ref ids, .. } = parts[1] else {
        panic!("handle is a reference")
    };
    assert_eq!(ids.len(), 3);
    assert!(ids[0] < (1 << 18), "first reference word {:#x}", ids[0]);
    assert_eq!(
        call("close_nif", std::slice::from_ref(&parts[1])).unwrap(),
        atom("ok")
    );
}
