use std::{
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

mod support;

fn files(path: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "beam") {
            out.push(path);
        }
    }
}

#[test]
fn parse_installed_beams() {
    let mut paths = Vec::new();
    if let Some(otp) = support::otp_root() {
        files(&otp.join("lib"), &mut paths);
        if let Ok(entries) = fs::read_dir(&otp) {
            for entry in entries
                .flatten()
                .filter(|entry| entry.file_name().to_string_lossy().starts_with("erts-"))
            {
                files(&entry.path(), &mut paths);
            }
        }
    }
    if let Some(elixir) = support::elixir_lib() {
        files(&elixir, &mut paths);
    }
    if paths.is_empty() {
        eprintln!("installed OTP/Elixir corpus absent; skipping");
        return;
    }
    let start = Instant::now();
    let mut failures = Vec::new();
    for path in &paths {
        match fs::read(path).map_err(|e| e.to_string()).and_then(|bytes| {
            arinsal_beam::parse(&bytes)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }) {
            Ok(()) => {}
            Err(e) => failures.push(format!("{}: {e}", path.display())),
        }
    }
    eprintln!(
        "parsed {} BEAM files in {:.3}s; {} failures",
        paths.len(),
        start.elapsed().as_secs_f64(),
        failures.len()
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn malformed_inputs_do_not_panic() {
    let Some(path) = support::otp_root().map(|root| root.join("lib/stdlib-8.1/ebin/lists.beam"))
    else {
        eprintln!("OTP unavailable; skipping malformed-input corpus test");
        return;
    };
    let Ok(bytes) = fs::read(path) else {
        eprintln!("lists.beam absent; skipping");
        return;
    };
    for len in (0..bytes.len()).step_by(521).chain(0..128) {
        assert!(
            std::panic::catch_unwind(|| arinsal_beam::parse(&bytes[..len])).is_ok(),
            "truncation {len}"
        );
    }
    let mut changed = bytes.clone();
    for i in (0..bytes.len()).step_by(257) {
        changed[i] ^= 0xff;
        assert!(
            std::panic::catch_unwind(|| arinsal_beam::parse(&changed)).is_ok(),
            "bit flip {i}"
        );
        changed[i] ^= 0xff;
    }
}

#[test]
fn decode_all_installed_literals() {
    let mut paths = Vec::new();
    if let Some(otp) = support::otp_root() {
        files(&otp.join("lib"), &mut paths);
    }
    if let Some(elixir) = support::elixir_lib() {
        files(&elixir, &mut paths);
    }
    for path in paths {
        let bytes = fs::read(path).unwrap();
        let beam = arinsal_beam::parse(&bytes).unwrap();
        for i in 0..beam.literals.len() {
            beam.literal(i as u32).unwrap();
        }
    }
}
