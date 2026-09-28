use std::path::{Path, PathBuf};

fn beams(root: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            beams(&path, files);
        } else if path.extension().is_some_and(|ext| ext == "beam") {
            files.push(path);
        }
    }
}

#[test]
fn otp_and_elixir_corpus_loads() {
    let roots = [
        std::env::var_os("ARINSAL_OTP_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("$HOME/.asdf/installs/erlang/29.1.1")),
        std::env::var_os("ARINSAL_ELIXIR_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("$HOME/.asdf/installs/elixir/1.20.4-otp-29")),
    ];
    let mut files = Vec::new();
    for root in &roots {
        beams(root, &mut files);
    }
    if files.is_empty() {
        eprintln!("OTP and Elixir BEAM corpus absent; skipping");
        return;
    }
    let start = std::time::Instant::now();
    let mut unsupported = std::collections::BTreeMap::<String, usize>::new();
    for path in &files {
        let bytes = std::fs::read(path).unwrap();
        let beam =
            arinsal_beam::parse(&bytes).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let module =
            arinsal_loader::load(&beam).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        for (op, count) in module.unsupported {
            *unsupported.entry(op).or_default() += count;
        }
    }
    eprintln!(
        "loaded {} BEAM files in {:.3}s; unsupported {:?}",
        files.len(),
        start.elapsed().as_secs_f64(),
        unsupported
    );
}
