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
