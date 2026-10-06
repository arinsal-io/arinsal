//! Measure moving independent module compilation off a caller thread.

use adr_jit_copy::{JitEngine, JitState};
use std::path::{Path, PathBuf};
use std::time::Instant;

extern "C" fn ensure(_: *mut JitState, _: u32, _: u32) -> u32 {
    1
}

extern "C" fn materialize(_: *mut JitState, _: u64, _: u64) -> u32 {
    1
}

fn collect(root: &Path, paths: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(root).unwrap().flatten() {
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "beam")
        {
            paths.push(path);
        }
    }
}

fn compile(paths: Vec<PathBuf>) -> usize {
    let mut compiled = 0;
    for path in paths {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let Ok(beam) = arinsal_beam::parse(&bytes) else {
            continue;
        };
        let Ok(module) = arinsal_loader::load(&beam) else {
            continue;
        };
        let Ok(mut jit) = JitEngine::new(ensure, materialize) else {
            continue;
        };
        for (start, _, _) in &module.functions {
            compiled += usize::from(jit.compile(0, &module, start + 1).is_ok());
        }
    }
    compiled
}

fn median(mut samples: Vec<f64>) -> f64 {
    samples.sort_by(f64::total_cmp);
    samples[samples.len() / 2]
}

fn main() {
    let mut files = Vec::new();
    let otp = std::env::var_os("ARINSAL_OTP_ROOT")
        .map(PathBuf::from)
        .or_else(|| discover("erl", "io:format(\"~s\",[code:root_dir()]),halt()."));
    let Some(otp) = otp else {
        eprintln!("Skipping thread probe: erl is unavailable and ARINSAL_OTP_ROOT is unset");
        return;
    };
    let otp_lib = otp.join("lib");
    for app in ["kernel", "stdlib", "compiler"] {
        if let Some(ebin) = std::fs::read_dir(&otp_lib).ok().into_iter().flatten()
            .flatten().map(|entry| entry.path())
            .find(|path| path.file_name().is_some_and(|name| name.to_string_lossy().starts_with(&format!("{app}-"))))
            .map(|path| path.join("ebin"))
        {
            collect(&ebin, &mut files);
        }
    }
    if let Some(ebin) = discover("elixir", "IO.write(:code.lib_dir(:elixir))") {
        collect(&ebin, &mut files);
    }
    files.sort();
    for workers in [1, 2] {
        let mut queued = Vec::new();
        let mut walls = Vec::new();
        let mut count = 0;
        for _ in 0..5 {
            let started = Instant::now();
            let mut handles = Vec::new();
            for worker in 0..workers {
                let share: Vec<_> = files
                    .iter()
                    .skip(worker)
                    .step_by(workers)
                    .cloned()
                    .collect();
                handles.push(std::thread::spawn(move || compile(share)));
            }
            queued.push(started.elapsed().as_micros() as f64);
            count = handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .sum();
            walls.push(started.elapsed().as_millis() as f64);
        }
        println!(
            "workers={workers} files={} compiled={count} queue_us_median={:.0} wall_ms_median={:.0} wall_range={:.0}-{:.0}",
            files.len(),
            median(queued),
            median(walls.clone()),
            walls.iter().copied().reduce(f64::min).unwrap(),
            walls.iter().copied().reduce(f64::max).unwrap(),
        );
    }
}

fn discover(program: &str, expression: &str) -> Option<PathBuf> {
    let output = if program == "elixir" {
        std::process::Command::new(program).args(["-e", expression]).output().ok()?
    } else {
        std::process::Command::new(program).args(["-noshell", "-eval", expression]).output().ok()?
    };
    output.status.success().then(|| String::from_utf8(output.stdout).ok()).flatten().map(PathBuf::from)
}
