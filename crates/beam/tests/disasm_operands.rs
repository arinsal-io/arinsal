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
    if !std::path::Path::new("$HOME/.asdf/installs/erlang/29.1.1/lib").exists() {
        eprintln!("OTP 29.1.1 absent; skipping operand differential test");
        return;
    }
    disasm::command(&["--check-all".into()]).unwrap();
}
