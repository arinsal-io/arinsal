use std::ffi::OsString;
use std::process::Command;

/// Re-exec a comparison without Cargo's test-binary-only dynamic-loader paths.
pub(crate) fn isolate_dyld_environment(test_name: &str) -> bool {
    const CHILD_MARKER: &str = "ARINSAL_DYLD_ENV_CHILD";
    if std::env::var_os(CHILD_MARKER).is_some() {
        return true;
    }

    let dyld_vars: Vec<OsString> = std::env::vars_os()
        .filter_map(|(key, _)| key.to_string_lossy().starts_with("DYLD_").then_some(key))
        .collect();
    if dyld_vars.is_empty() {
        return true;
    }

    let mut command = Command::new("timeout");
    command
        .arg("120")
        .arg(std::env::current_exe().expect("current test executable"))
        .args(["--exact", test_name, "--nocapture"])
        .env(CHILD_MARKER, "1");
    for key in dyld_vars {
        command.env_remove(key);
    }
    let output = command.output().expect("start isolated test process");
    assert!(
        output.status.success(),
        "isolated {test_name} exited {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    false
}
