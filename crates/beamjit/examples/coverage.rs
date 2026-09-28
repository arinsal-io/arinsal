use arinsal_beamjit::coverage;

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
