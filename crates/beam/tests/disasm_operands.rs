//! Whole-installation operand differential test against OTP's `beam_disasm`.

#[path = "../../cli/src/disasm.rs"]
mod disasm;

#[test]
#[ignore = "slow (~40 s): full operand cross-check of all OTP/Elixir modules; run with --ignored"]
fn all_installed_modules_match_beam_disasm_operands() {
    if std::process::Command::new("escript")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("escript unavailable; skipping operand differential test");
        return;
    }
    let otp_root = std::env::var_os("ARINSAL_OTP_ROOT")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            let output = std::process::Command::new("erl")
                .args([
                    "-noshell",
                    "-eval",
                    "io:format(\"~s\",[code:root_dir()]),halt().",
                ])
                .output()
                .ok()?;
            output
                .status
                .success()
                .then(|| String::from_utf8(output.stdout).ok())
                .flatten()
                .map(std::path::PathBuf::from)
        });
    if !otp_root.is_some_and(|root| root.join("lib").exists()) {
        eprintln!("OTP 29.1.1 absent; skipping operand differential test");
        return;
    }
    disasm::command(&["--check-all".into()]).unwrap();
}
