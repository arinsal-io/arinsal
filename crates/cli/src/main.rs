//! `arinsal` developer commands.

#![forbid(unsafe_code)]

use arinsal_beam::{BeamFile, Operand};
mod disasm;
mod eval;

fn main() {
    arinsal_nif::ensure_exports();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--port-exec-config") if args.len() == 2 => port_exec_config(&args[1]),
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

// Port of erts/emulator/sys/unix/erl_child_setup.c:220-363, OTP-29.1.1.
fn port_exec_config(path: &str) -> ! {
    use std::io;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    fn take_u32(bytes: &[u8], offset: &mut usize) -> io::Result<usize> {
        let end = offset
            .checked_add(4)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short port config"))?;
        let value = u32::from_le_bytes(bytes[*offset..end].try_into().unwrap()) as usize;
        *offset = end;
        Ok(value)
    }

    fn take_bytes(bytes: &[u8], offset: &mut usize) -> io::Result<std::ffi::OsString> {
        let len = take_u32(bytes, offset)?;
        let end = offset
            .checked_add(len)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short port config"))?;
        let value = bytes[*offset..end].to_vec();
        *offset = end;
        Ok(std::ffi::OsString::from_vec(value))
    }

    fn take_optional_bytes(
        bytes: &[u8],
        offset: &mut usize,
    ) -> io::Result<Option<std::ffi::OsString>> {
        let present = *bytes
            .get(*offset)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short port config"))?;
        *offset += 1;
        match present {
            0 => Ok(None),
            1 => take_bytes(bytes, offset).map(Some),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid optional port config field",
            )),
        }
    }

    let result = (|| -> io::Result<Command> {
        let bytes = std::fs::read(path)?;
        if !bytes.starts_with(b"ARPC\x01") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid port config header",
            ));
        }
        let mut offset = 5;
        let program = take_bytes(&bytes, &mut offset)?;
        let arg0 = take_optional_bytes(&bytes, &mut offset)?;
        let cwd = take_optional_bytes(&bytes, &mut offset)?;
        let arg_count = take_u32(&bytes, &mut offset)?;
        let mut args = Vec::with_capacity(arg_count);
        for _ in 0..arg_count {
            args.push(take_bytes(&bytes, &mut offset)?);
        }
        let env_count = take_u32(&bytes, &mut offset)?;
        let mut env = Vec::with_capacity(env_count);
        for _ in 0..env_count {
            env.push((
                take_bytes(&bytes, &mut offset)?,
                take_bytes(&bytes, &mut offset)?,
            ));
        }
        if offset != bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trailing port config bytes",
            ));
        }
        let _ = std::fs::remove_file(path);
        let mut command = Command::new(program);
        command.args(args).env_clear().envs(env);
        if let Some(cwd) = cwd {
            command.current_dir(cwd);
        }
        if let Some(arg0) = arg0 {
            command.arg0(arg0);
        }
        Ok(command)
    })();

    match result {
        Ok(mut command) => {
            let error = command.exec();
            eprintln!("arinsal port child: {error}");
            std::process::exit(if error.kind() == io::ErrorKind::NotFound {
                127
            } else {
                126
            });
        }
        Err(error) => {
            eprintln!("arinsal port child: {error}");
            std::process::exit(126);
        }
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
    let default_dirty_allocators = launch
        .emulator
        .dirty_cpu_schedulers
        .map(|count| usize::try_from(count.total).unwrap_or(0))
        .or_else(|| {
            launch
                .emulator
                .schedulers
                .map(|count| usize::try_from(count.total).unwrap_or(0))
        })
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, usize::from));
    arinsal_args::configure_allocator_options(arinsal_args::ActiveAllocatorOptions {
        schedulers: launch.emulator.schedulers.map(|count| count.total),
        dirty_instances: launch
            .emulator
            .allocator_options
            .iter()
            .find(|flag| flag.name == "+Mdai")
            .and_then(|flag| flag.value.as_deref())
            .and_then(|value| {
                if value == "max" {
                    Some(default_dirty_allocators)
                } else {
                    value.parse().ok()
                }
            }),
        flags: launch.emulator.allocator_options.clone(),
    });
    arinsal_args::configure_scheduler_options(arinsal_args::ActiveSchedulerOptions(
        launch.emulator.scheduler.clone(),
    ));
    // Port of erts/emulator/beam/erl_init.c:1874 (+P) and erl_process.c:765
    // (erts_ptab_init_table), OTP-29.1.1: the table rounds the limit up to a power of two.
    // `+P legacy` keeps the default size; the legacy id algorithm is not ported.
    if let Some(arinsal_args::Limit::Value(limit)) = launch.emulator.process_limit {
        arinsal_term::ptab::set_process_table_layout(arinsal_term::ptab::PtabLayout::new(
            u32::try_from(limit).unwrap_or(u32::MAX),
        ));
    }
    // Port of erts/emulator/beam/erl_init.c:2427 (+Q) and io.c:3016 (erts_ptab_init_table), OTP-29.1.1.
    if let Some(arinsal_args::Limit::Value(limit)) = launch.emulator.port_limit {
        arinsal_term::ptab::set_port_table_layout(arinsal_term::ptab::PtabLayout::new(
            u32::try_from(limit).unwrap_or(u32::MAX),
        ));
    }
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
    // erlexec exports PATH, then applies `-env` assignments (erlexec.c:553-618).
    let mut seeded = vec![("PATH".to_owned(), launch.path.clone())];
    seeded.extend(launch.set_env.iter().map(|(k, v)| (k.clone(), v.clone())));
    arinsal_vm::boot::seed_environment(&seeded);
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
