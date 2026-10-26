//! Helpers for the vm unit tests.

/// Runs the calling test again in a child process that starts the interpreter flavor
/// (`-emu_flavor emu`, here its `ARINSAL_INTERP` alias) and returns `true` in the parent, where
/// the caller returns. In the child it returns `false` and the test body runs. For tests of
/// interpreter behavior: the flavor is chosen once per process, so a test cannot switch it.
pub(crate) fn in_interpreter_flavor(test: &str) -> bool {
    if std::env::var_os("ARINSAL_UNIT_EMU_CHILD").is_some() {
        return false;
    }
    let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env("ARINSAL_UNIT_EMU_CHILD", "1")
        .env("ARINSAL_INTERP", "1")
        .output()
        .expect("spawn the interpreter-flavor child");
    assert!(
        output.status.success(),
        "{test} under the interpreter flavor failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    true
}
