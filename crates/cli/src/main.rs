//! `arinsal` developer commands.

#![forbid(unsafe_code)]

use arinsal_beam::{BeamFile, Operand};
mod disasm;
mod eval;

fn main() {
    arinsal_nif::ensure_exports();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version") => println!("arinsal {}", env!("CARGO_PKG_VERSION")),
        Some("beam-info") => {
            let code = args.iter().any(|arg| arg == "--code");
            let files: Vec<_> = args[1..]
                .iter()
                .filter(|arg| arg.as_str() != "--code")
                .collect();
            if files.len() != 1 {
                usage();
            }
            let result = std::fs::read(files[0])
                .map_err(|e| e.to_string())
                .and_then(|data| arinsal_beam::parse(&data).map_err(|e| e.to_string()));
            match result {
                Ok(file) => show(&file, code),
                Err(e) => {
                    eprintln!("{}: {e}", files[0]);
                    std::process::exit(1);
                }
            }
        }
        Some("disasm") => {
            if let Err(error) = disasm::command(&args[1..]) {
                eprintln!("disasm: {error}");
                std::process::exit(1);
            }
        }
        Some("eval") => {
            if let Err(error) = eval::command(&args[1..]) {
                match error {
                    arinsal_vm::VmError::Unsupported(message) => {
                        println!("unsupported: {message}");
                        std::process::exit(3);
                    }
                    other => {
                        eprintln!("{other}");
                        std::process::exit(1);
                    }
                }
            }
        }
        _ if args.first().is_some_and(|arg| arg == "erl") => erl_launch(&args[1..]),
        _ => erl_launch(&args),
    }
}

fn erl_launch(args: &[String]) -> ! {
    use arinsal_args::{Env, parse};
    use std::collections::BTreeMap;
    use std::io::Write;
    use std::path::PathBuf;

    struct LaunchEnv(BTreeMap<String, String>);
    impl Env for LaunchEnv {
        fn get(&self, name: &str) -> Option<String> {
            self.0.get(name).cloned()
        }
    }

    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    let mut argv = vec!["arinsal".to_owned()];
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--root" => {
                let Some(root) = args.get(index + 1) else {
                    eprintln!("arinsal: --root needs a directory");
                    std::process::exit(2);
                };
                environment.insert("ERL_ROOTDIR".into(), root.clone());
                index += 2;
            }
            _ => {
                argv.push(args[index].clone());
                index += 1;
            }
        }
    }
    if args.iter().any(|arg| arg == "-emu_args") {
        eprintln!("arinsal: ignoring -emu_args");
    }
    let launch = match parse(&argv, &LaunchEnv(environment)) {
        Ok(launch) => launch,
        Err(error) => {
            let (status, text) = error.exit_report();
            let _ = std::io::stderr().write_all(text.as_bytes());
            std::process::exit(status);
        }
    };
    if launch.detached {
        // erlexec forks and calls setsid (erlexec.c:1199). Arinsal does not detach.
        eprintln!("arinsal: -detached is not supported");
        std::process::exit(1);
    }
    // -sname/-name are delivered to init. Distribution is started later by
    // kernel's erl_distribution, which calls net_kernel:start_link/1
    // (lib/kernel/src/net_kernel.erl:2689). A missing listen/1 is
    // `Protocol 'inet_tcp': not supported`. A dead epmd is
    // `Protocol 'inet_tcp': register/listen error:` plus `no_reg_reply_from_epmd`
    // (net_kernel.erl:2702). Failing here would reject names erl accepts.
    let root = PathBuf::from(&launch.root_dir);
    let workers = launch.emulator.schedulers.map_or_else(
        || std::thread::available_parallelism().map_or(1, |count| count.get()),
        |count| usize::try_from(count.total).unwrap_or(1).max(1),
    );
    match arinsal_vm::boot::run_with_debugger_flags(
        &root,
        &launch.boot_args,
        &[],
        workers,
        launch.emulator.debugger_support,
        launch.emulator.debugger_line_breakpoints.unwrap_or(true),
        launch.emulator.distribution_buffer_busy_limit,
    ) {
        Ok(_) => std::process::exit(0),
        Err(arinsal_vm::VmError::Unsupported(message)) => {
            // Native gaps are reported at the call site by the VM with the caller frame.
            if !message.starts_with("BIF ") {
                eprintln!("arinsal: {message}");
            }
            std::process::exit(3)
        }
        Err(arinsal_vm::VmError::Raised(raised)) => {
            let reason = raised.reason;
            let heading = if format!("{:?}", raised.class) == "Exit" {
                format!("System process <0.0.0> terminated: {reason}")
            } else {
                format!("Runtime terminating during boot ({reason})")
            };
            use std::io::Write;
            let _ = write!(
                std::io::stderr().lock(),
                "{heading}\r\n\r\nCrash dump is being written to: erl_crash.dump...done\r\n"
            );
            let _ = std::io::stderr().flush();
            std::process::exit(1)
        }
        Err(error) => {
            eprintln!("arinsal: {error}");
            std::process::exit(1)
        }
    }
}
fn usage() -> ! {
    eprintln!(
        "usage: arinsal --version | beam-info [--code] <file.beam> | disasm <file.beam> [--format erl] | disasm --check-all <dirs...> | eval [-pa DIR]... <module> <function> [ARG]..."
    );
    std::process::exit(2)
}
fn show(file: &BeamFile, code: bool) {
    println!("module: {}", file.module);
    println!("chunks:");
    for (id, size) in &file.chunks {
        println!("  {}: {size}", String::from_utf8_lossy(id));
    }
    println!(
        "atoms: {}  imports: {}  exports: {}  lambdas: {}  literals: {}",
        file.atoms.len(),
        file.imports.len(),
        file.exports.len(),
        file.lambdas.len(),
        file.literals.len()
    );
    println!(
        "functions: {}  labels: {}  instructions: {}",
        file.code.function_count,
        file.code.label_count,
        file.code.instructions.len()
    );
    if code {
        for instr in &file.code.instructions {
            let args = instr
                .args
                .iter()
                .map(|a| format_operand(a, file))
                .collect::<Vec<_>>()
                .join(",");
            if args.is_empty() {
                println!("{:06x}: {{{}}}.", instr.offset, instr.op.name());
            } else {
                println!("{:06x}: {{{},{}}}.", instr.offset, instr.op.name(), args);
            }
        }
    }
}
fn format_operand(operand: &Operand, file: &BeamFile) -> String {
    match operand {
        Operand::U(n) => n.to_string(),
        Operand::Int(n) => format!("{{integer,{n}}}"),
        Operand::BigInt(n) => format!("{{integer,{n}}}"),
        Operand::Atom(n) => format!("{{atom,{}}}", file.atom(*n).unwrap_or("?")),
        Operand::Nil => "nil".into(),
        Operand::X(n) => format!("{{x,{n}}}"),
        Operand::Y(n) => format!("{{y,{n}}}"),
        Operand::FR(n) => format!("{{fr,{n}}}"),
        Operand::Label(n) => format!("{{f,{n}}}"),
        Operand::Char(n) => format!("{{char,{n}}}"),
        Operand::Literal(n) => format!("{{literal,{n}}}"),
        Operand::List(items) => format!(
            "[{}]",
            items
                .iter()
                .map(|a| format_operand(a, file))
                .collect::<Vec<_>>()
                .join(",")
        ),
        Operand::Alloc(items) => format!("{{alloc,{items:?}}}"),
        Operand::TypedReg { reg, type_index } => {
            format!("{{tr,{},{type_index}}}", format_operand(reg, file))
        }
    }
}
