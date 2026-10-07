use std::{fs, process::Command};

#[test]
fn rejects_unknown_bs_match_commands_at_load_time() {
    let temp = std::env::temp_dir().join(format!("arinsal-bad-bs-match-{}", std::process::id()));
    fs::create_dir_all(&temp).unwrap();
    let source = temp.join("bad_bs_match.erl");
    fs::write(
        &source,
        "-module(bad_bs_match).\n-export([f/1]).\nf(<<X:16,_/binary>>) -> X.\n",
    )
    .unwrap();
    let compile = Command::new("timeout")
        .args(["30", "erlc", "-W0", "-o"])
        .arg(&temp)
        .arg(&source)
        .output();
    let Ok(compile) = compile else {
        eprintln!("OTP erlc unavailable; skipping bad bs_match regression");
        let _ = fs::remove_dir_all(&temp);
        return;
    };
    if !compile.status.success() {
        eprintln!(
            "OTP erlc unavailable or fixture compile failed; skipping: {}",
            String::from_utf8_lossy(&compile.stderr)
        );
        let _ = fs::remove_dir_all(&temp);
        return;
    }

    let beam_path = temp.join("bad_bs_match.beam");
    let bytes = fs::read(&beam_path).unwrap();
    assert!(arinsal_loader::load(&arinsal_beam::parse(&bytes).unwrap()).is_ok());
    let needle = b"ensure_at_least";
    let replacement = b"future_cool_cmd";
    assert_eq!(needle.len(), replacement.len());
    let offset = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("compiled module should contain a bs_match command");
    let mut malformed = bytes;
    malformed[offset..offset + needle.len()].copy_from_slice(replacement);
    let parsed = arinsal_beam::parse(&malformed).unwrap();
    assert!(matches!(
        arinsal_loader::validate_bit_matches(&parsed),
        Err(arinsal_loader::LoadError::BadBitMatch)
    ));
    assert!(matches!(
        arinsal_loader::load(&parsed),
        Err(arinsal_loader::LoadError::BadBitMatch)
    ));
    fs::remove_dir_all(temp).unwrap();
}
