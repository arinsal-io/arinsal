//! The driver API table matches the installed OTP 29.1.1 `erl_driver.h`, and every
//! `Core` entry is a dynamic symbol of the executable.

use std::collections::BTreeSet;
use std::ffi::CString;
use std::path::PathBuf;
use std::process::Command;

use arinsal_drv::api::{DRIVER_API, Owner, exported_symbol};

fn header() -> String {
    let output = Command::new("erl")
        .args([
            "-noshell",
            "-eval",
            "io:format(\"~s/usr/include\",[code:root_dir()]), halt().",
        ])
        .output()
        .expect("erl on PATH");
    assert!(output.status.success());
    let dir = PathBuf::from(String::from_utf8(output.stdout).unwrap());
    std::fs::read_to_string(dir.join("erl_driver.h")).unwrap()
}

/// Names of all `EXTERN` declarations; a declaration may span lines.
fn declared(header: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut pending = String::new();
    for line in header.lines() {
        if pending.is_empty() && !line.starts_with("EXTERN") {
            continue;
        }
        pending.push_str(line);
        pending.push(' ');
        if !pending.contains(';') {
            continue;
        }
        let decl = std::mem::take(&mut pending);
        let head = decl.split('(').next().unwrap();
        let head = head.split(';').next().unwrap();
        let name = head
            .trim()
            .rsplit(|c: char| c.is_whitespace() || c == '*')
            .next()
            .unwrap()
            .to_owned();
        names.insert(name);
    }
    names
}

#[test]
fn table_covers_erl_driver_h() {
    let declared = declared(&header());
    let table = DRIVER_API
        .iter()
        .map(|(name, _)| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(table.len(), DRIVER_API.len(), "duplicate table entries");
    assert_eq!(
        declared.difference(&table).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "missing from DRIVER_API"
    );
    assert_eq!(
        table.difference(&declared).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "not in erl_driver.h"
    );
}

#[test]
fn core_entries_are_dynamic_symbols() {
    arinsal_drv::ensure_exports();
    for (name, owner) in DRIVER_API {
        let symbol = CString::new(*name).unwrap();
        // SAFETY: dlsym with RTLD_DEFAULT only reads the symbol tables.
        let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, symbol.as_ptr()) } as usize;
        if *owner == Owner::Core {
            assert_eq!(Some(address), exported_symbol(name), "{name} not exported");
        } else {
            assert_eq!(address, 0, "{name} exported but not marked Core");
        }
    }
}
