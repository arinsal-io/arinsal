use similar_asserts::assert_eq;

#[cfg(unix)]
#[test]
fn root_discovery_ignores_a_current_executable_named_erl() {
    use std::collections::HashMap;
    use std::os::unix::fs::symlink;

    let current = std::env::current_exe().unwrap();
    let directory = std::env::temp_dir().join(format!("erl-self-shim-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let shim = directory.join("erl");
    let _ = std::fs::remove_file(&shim);
    symlink(current, &shim).unwrap();

    let env = HashMap::from([("PATH".to_owned(), directory.to_string_lossy().into_owned())]);
    assert_eq!(arinsal_args::discover_otp_root(&env), None);

    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn bundled_root_is_resolved_relative_to_the_arinsal_executable() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let prefix = std::env::temp_dir().join(format!("arinsal-bundle-root-{nonce}"));
    let executable = prefix.join("bin/arinsal");
    let root = prefix.join("lib/arinsal/otp");
    std::fs::create_dir_all(root.join("lib/erts-17.1/ebin")).unwrap();
    std::fs::create_dir_all(root.join("lib/kernel-11.0.4/ebin")).unwrap();
    std::fs::create_dir_all(executable.parent().unwrap()).unwrap();

    assert_eq!(
        arinsal_args::bundled_otp_root_for_executable(&executable),
        Some(root.clone())
    );

    std::fs::remove_dir_all(prefix).unwrap();
}
