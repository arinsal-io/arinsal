//! Reports the specific instructions the arm module assembler driver has no emitter for. On
//! x86 the driver dispatches through the generated `beamasm_emit!`, so a missing emitter
//! fails the build and there is nothing to report at run time.

#[cfg(target_arch = "aarch64")]
use arinsal_beamjit::coverage;

#[cfg(target_arch = "aarch64")]
fn main() {
    let directories = std::env::args().skip(1).collect::<Vec<_>>();
    if directories.is_empty() {
        eprintln!("usage: coverage <beam-directory>...");
        std::process::exit(2);
    }
    if let Err(error) = coverage(&directories) {
        eprintln!("coverage failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_arch = "aarch64"))]
fn main() {
    eprintln!("coverage: the x86 emitter set is checked when beamasm_emit! is compiled");
    std::process::exit(2);
}
