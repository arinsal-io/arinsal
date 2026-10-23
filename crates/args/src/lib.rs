//! Argument preparation for an OTP 29 `erl` compatible launcher.
//!
//! `parse` reproduces the launcher's source ordering and the preloaded `init`
//! module's argument grouping. It does not start an emulator.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use thiserror::Error;

/// A read-only environment supplied by the caller.
pub trait Env {
    /// Return the value of an environment variable, if set.
    fn get(&self, name: &str) -> Option<String>;
}

/// The host environment adapter for a future CLI entry point.
pub struct ProcessEnv;

impl Env for ProcessEnv {
    fn get(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
}

impl Env for BTreeMap<String, String> {
    fn get(&self, name: &str) -> Option<String> {
        self.get(name).cloned()
    }
}

impl Env for std::collections::HashMap<String, String> {
    fn get(&self, name: &str) -> Option<String> {
        self.get(name).cloned()
    }
}

/// A flag and its values as returned by `init:get_arguments/0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitFlag {
    /// Flag name without the leading hyphen.
    pub name: String,
    /// Values up to the next flag or separator.
    pub values: Vec<String>,
}

/// The argument data passed to the preloaded `init` module.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InitArgs {
    /// Flags in the order returned by `init:get_arguments/0`.
    pub flags: Vec<InitFlag>,
    /// Arguments exposed by `init:get_plain_arguments/0`.
    pub plain_args: Vec<String>,
}

/// Code-path pieces `init` and `code_server` derive from boot arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodePath {
    /// `-pa` directories. Later groups come first.
    pub prepend: Vec<String>,
    /// `-pz` directories, in command order.
    pub append: Vec<String>,
    /// First non-empty `-path`, which replaces the default loader path.
    pub replace: Option<Vec<String>>,
    /// False only when the first `-mode` value is `embedded`.
    pub interactive: bool,
}

impl InitArgs {
    /// Return every occurrence of a flag, like `init:get_argument/1`.
    pub fn get_argument(&self, name: &str) -> Option<Vec<&[String]>> {
        let values: Vec<_> = self
            .flags
            .iter()
            .filter(|flag| flag.name == name)
            .map(|flag| flag.values.as_slice())
            .collect();
        (!values.is_empty()).then_some(values)
    }

    /// Directories `init:boot/1` and `code_server` take from these arguments.
    ///
    /// Port of `erts/preloaded/src/init.erl:1259` (`path_flags`) and
    /// `lib/kernel/src/code.erl:1741` (`start_get_mode`), OTP-29.1.1.
    pub fn code_path(&self) -> CodePath {
        let groups = |name: &str| -> Vec<&[String]> { self.get_argument(name).unwrap_or_default() };
        let mut prepend = Vec::new();
        for group in groups("pa").into_iter().rev() {
            prepend.extend(group.iter().cloned());
        }
        let mut append = Vec::new();
        for group in groups("pz") {
            append.extend(group.iter().cloned());
        }
        let replace = groups("path")
            .into_iter()
            .find(|values| !values.is_empty())
            .map(|values| values.to_vec());
        let interactive = groups("mode")
            .first()
            .is_none_or(|values| !(values.len() == 1 && values[0] == "embedded"));
        CodePath {
            prepend,
            append,
            replace,
            interactive,
        }
    }
}

/// Group a boot-argument vector the way `init:boot/1` does.
///
/// Port of `erts/preloaded/src/init.erl:1668` (`parse_boot_args`), OTP-29.1.1.
pub fn arguments_from_boot(tokens: &[String]) -> InitArgs {
    parse_init(tokens)
}

/// A total and optional online scheduler count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedulerCount {
    /// Requested total schedulers.
    pub total: i32,
    /// Requested online schedulers, if specified.
    pub online: Option<i32>,
}

/// Resolve a parsed `+S`/`+SDcpu` count against the machine CPU count.
pub fn resolve_scheduler_count(
    count: Option<SchedulerCount>,
    cpus: usize,
) -> Option<(usize, usize)> {
    resolve_scheduler_count_online(count, cpus, cpus)
}

/// Like [`resolve_scheduler_count`] with a separate default for the online count, which on
/// Linux is limited by the affinity mask and the cgroup CPU quota.
// Port of erts/emulator/beam/erl_init.c (erl_start, `+S` and `+SDcpu` parsing), OTP-29.1.1.
pub fn resolve_scheduler_count_online(
    count: Option<SchedulerCount>,
    cpus: usize,
    cpus_online: usize,
) -> Option<(usize, usize)> {
    let Some(count) = count else {
        return Some((cpus, cpus_online));
    };
    let resolve = |value: i32, base: usize| {
        let base = i32::try_from(base).unwrap_or(i32::MAX);
        let count = if value > 0 {
            value
        } else {
            base.saturating_add(value)
        };
        usize::try_from(count).ok().filter(|count| *count > 0)
    };
    let total = resolve(count.total, cpus)?;
    // `+S Total` alone: online = min(Total as scanned, default online), then as below.
    let online = match count.online {
        Some(value) => resolve(value, cpus_online)?,
        None => resolve(
            count
                .total
                .min(i32::try_from(cpus_online).unwrap_or(i32::MAX)),
            cpus_online,
        )?,
    };
    (online <= total).then_some((total, online))
}

/// An OTP process or port limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// Explicit maximum.
    Value(u64),
    /// OTP's `legacy` setting.
    Legacy,
}

/// Time warp mode selected with `+C`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeWarp {
    /// `no_time_warp`.
    None,
    /// `single_time_warp`.
    Single,
    /// `multi_time_warp`.
    Multi,
}

/// A deterministic simulation pool requested with the Arinsal extension `+Spool`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorePool {
    /// Pool name.
    pub name: String,
    /// CPUs assigned to the pool.
    pub cpus: Vec<u32>,
}

/// An accepted emulator option that Arinsal does not yet implement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnoredFlag {
    /// Option spelling, including the leading plus.
    pub name: String,
    /// Value consumed from the following argument, if any.
    pub value: Option<String>,
}

/// Startup allocator switches made available to `system_info/1` in this process.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ActiveAllocatorOptions {
    /// Normal scheduler count selected by `+S`, if specified.
    pub schedulers: Option<i32>,
    /// Dirty allocator instance count selected by `+Mdai`, if specified.
    pub dirty_instances: Option<usize>,
    /// Valid allocator flags in original order.
    pub flags: Vec<IgnoredFlag>,
}

static ACTIVE_ALLOCATOR_OPTIONS: OnceLock<Mutex<ActiveAllocatorOptions>> = OnceLock::new();

/// Set allocator startup options before the VM starts.
pub fn configure_allocator_options(options: ActiveAllocatorOptions) {
    *ACTIVE_ALLOCATOR_OPTIONS
        .get_or_init(|| Mutex::new(ActiveAllocatorOptions::default()))
        .lock()
        .expect("allocator options lock poisoned") = options;
}

/// Return the active allocator startup options.
pub fn active_allocator_options() -> ActiveAllocatorOptions {
    ACTIVE_ALLOCATOR_OPTIONS
        .get_or_init(|| Mutex::new(ActiveAllocatorOptions::default()))
        .lock()
        .expect("allocator options lock poisoned")
        .clone()
}

/// Parsed emulator options; `None` means the emulator keeps its default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EmulatorFlags {
    /// `+D` enables the debugger BIFs.
    pub debugger_support: bool,
    /// `+Dibpl` selects line breakpoint instrumentation for subsequently loaded modules.
    pub debugger_line_breakpoints: Option<bool>,
    /// `+A` async thread count.
    pub async_threads: Option<u32>,
    /// `+S`.
    pub schedulers: Option<SchedulerCount>,
    /// `+SDcpu`.
    pub dirty_cpu_schedulers: Option<SchedulerCount>,
    /// `+SDio`.
    pub dirty_io_schedulers: Option<u32>,
    /// `+IOs`: schedulers poll the descriptors that are re-enabled often (default true).
    pub scheduler_polling: Option<bool>,
    /// `+P`.
    pub process_limit: Option<Limit>,
    /// `+Q`.
    pub port_limit: Option<Limit>,
    /// `+t`.
    pub atom_limit: Option<u64>,
    /// `+hms`.
    pub min_heap_size: Option<u64>,
    /// `+hmbs`.
    pub min_binary_heap_size: Option<u64>,
    /// `+zdbbl` in kilobytes.
    pub distribution_buffer_busy_limit: Option<u64>,
    /// `+C`.
    pub time_warp: Option<TimeWarp>,
    /// `+c`.
    pub time_correction: Option<bool>,
    /// Scheduler emulator options controlled by the `+s*` flags.
    pub scheduler: SchedulerOptions,
    /// Arinsal's `+Zsim` seed.
    pub simulation_seed: Option<u64>,
    /// Arinsal's `+Spool` assignments.
    pub core_pools: Vec<CorePool>,
    /// Recognised options whose implementation belongs to later stages.
    pub ignored: Vec<IgnoredFlag>,
    /// Validated OTP allocator switches, retained in command-line order.
    pub allocator_options: Vec<IgnoredFlag>,
}

/// Scheduler startup options parsed from OTP's scheduler emulator flags.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SchedulerOptions {
    /// `+scl` compact run-queue load balancing.
    pub compact_load: Option<bool>,
    /// `+sub` utilization balancing.
    pub utilization_balancing: Option<bool>,
    /// `+sbwt`, `+sbwtdcpu`, and `+sbwtdio` busy-wait thresholds.
    pub busy_wait: [Option<String>; 3],
    /// `+swt`, `+swtdcpu`, and `+swtdio` wakeup thresholds.
    pub wakeup: [Option<String>; 3],
    /// `+sfwi` forced wakeup interval.
    pub forced_wakeup_interval: Option<u64>,
    /// `+spp` port parallelism hint.
    pub port_parallelism: Option<bool>,
    /// `+sbt` scheduler bind type.
    pub bind_type: Option<String>,
}

static ACTIVE_EMULATOR_FLAGS: OnceLock<Mutex<EmulatorFlags>> = OnceLock::new();

/// Set parsed emulator startup options before the VM starts.
pub fn configure_emulator_flags(flags: EmulatorFlags) {
    *ACTIVE_EMULATOR_FLAGS
        .get_or_init(|| Mutex::new(EmulatorFlags::default()))
        .lock()
        .expect("emulator flags lock poisoned") = flags;
}

/// Return the active emulator startup options.
pub fn active_emulator_flags() -> EmulatorFlags {
    ACTIVE_EMULATOR_FLAGS
        .get_or_init(|| Mutex::new(EmulatorFlags::default()))
        .lock()
        .expect("emulator flags lock poisoned")
        .clone()
}

/// Scheduler options visible to the runtime after CLI startup parsing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ActiveSchedulerOptions(pub SchedulerOptions);

static ACTIVE_SCHEDULER_OPTIONS: OnceLock<Mutex<ActiveSchedulerOptions>> = OnceLock::new();

/// Set scheduler startup options before the VM starts.
pub fn configure_scheduler_options(options: ActiveSchedulerOptions) {
    *ACTIVE_SCHEDULER_OPTIONS
        .get_or_init(|| Mutex::new(ActiveSchedulerOptions::default()))
        .lock()
        .expect("scheduler options lock poisoned") = options;
}

/// Return the active scheduler startup options.
pub fn active_scheduler_options() -> ActiveSchedulerOptions {
    ACTIVE_SCHEDULER_OPTIONS
        .get_or_init(|| Mutex::new(ActiveSchedulerOptions::default()))
        .lock()
        .expect("scheduler options lock poisoned")
        .clone()
}

impl EmulatorFlags {
    /// Messages the CLI can show for accepted options without VM support.
    ///
    /// `+sbwt` and `+M*` are accepted and ignored with no diagnostic,
    /// matching an `erl` that starts successfully.
    pub fn warnings(&self) -> Vec<String> {
        self.ignored
            .iter()
            .filter(|flag| !silent_emulator_flag(&flag.name))
            .map(|flag| format!("{} is accepted but not implemented", flag.name))
            .collect()
    }
}

fn silent_emulator_flag(name: &str) -> bool {
    matches!(name, "+A" | "+sbwt" | "+sbwtdcpu" | "+sbwtdio") || name.starts_with("+M")
}

/// Fully prepared launch data for the VM and `init`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    /// Parsed emulator options.
    pub emulator: EmulatorFlags,
    /// Arguments visible to `init`.
    pub init: InitArgs,
    /// Erlang installation root.
    pub root_dir: String,
    /// ERTS executable directory.
    pub bin_dir: String,
    /// First `-boot` value. `init:boot/1` uses the first occurrence.
    pub boot_script: Option<String>,
    /// First `-mode` value. `code` treats only `embedded` as embedded mode.
    pub mode: Option<String>,
    /// Whether `-noshell` was selected.
    pub noshell: bool,
    /// Whether `-detached` was selected.
    pub detached: bool,
    /// First `-sname` value. `erl_distribution` uses the first occurrence.
    pub sname: Option<String>,
    /// First `-name` value. `erl_distribution` uses the first occurrence.
    pub name: Option<String>,
    /// `-env` assignments, in their final values.
    pub set_env: BTreeMap<String, String>,
    /// Exact binary strings passed as the second argument to `erl_init:start/2`.
    pub boot_args: Vec<String>,
    /// `PATH` as erlexec leaves it for the emulator and its children.
    pub path: String,
}

/// Compute the `PATH` erlexec exports: ERTS bindir first, then `<root>/bin`
/// when the root is not on `PATH` yet, with later bindir duplicates removed.
// Port of erts/etc/common/erlexec.c:553-618, OTP-29.1.1.
pub fn erlexec_path(bin_dir: &str, root_dir: &str, path: Option<&str>) -> String {
    match path {
        None => format!("{bin_dir}:{root_dir}/bin"),
        Some(path) if !path.contains(root_dir) => format!("{bin_dir}:{root_dir}/bin:{path}"),
        Some(path) => {
            let mut out = bin_dir.to_owned();
            for element in path.split(':').filter(|element| *element != bin_dir) {
                out.push(':');
                out.push_str(element);
            }
            out
        }
    }
}

/// An argument rejected before VM boot.
#[derive(Debug, Error)]
pub enum ArgsError {
    /// A flag requires a following value.
    #[error("missing value for {0}")]
    MissingValue(String),
    /// A value is invalid for its flag.
    #[error("invalid value for {flag}: {value}")]
    InvalidValue { flag: String, value: String },
    /// The emulator does not recognize a plus option.
    #[error("unknown emulator flag {0}")]
    UnknownEmulatorFlag(String),
    /// An arguments file cannot be read.
    #[error("cannot read arguments file {path}: {source}")]
    ArgsFile {
        /// Requested filename.
        path: String,
        /// Filesystem failure.
        #[source]
        source: std::io::Error,
    },
    /// Nested arguments files exceed the supported limit.
    #[error("arguments files nested more than 64 levels")]
    ArgsFileDepth,
    /// A launcher action requires a later integration stage.
    #[error("unsupported launcher option {0}")]
    UnsupportedOption(String),
    /// Stderr text `erl` writes before exiting 1.
    #[error("{0}")]
    ErlDiagnostic(String),
}

impl ArgsError {
    /// Process status and stderr bytes a launcher should produce.
    pub fn exit_report(&self) -> (i32, String) {
        match self {
            ArgsError::ErlDiagnostic(text) => {
                let mut text = text.clone();
                if !text.ends_with('\n') {
                    text.push('\n');
                }
                (1, text)
            }
            other => (2, format!("arinsal: {other}\n")),
        }
    }
}

// Port of erts/etc/common/erlexec.c:1282 (usage_aux), OTP-29.1.1.
const ERL_USAGE: &str = "Usage: erl [-version] [-sname NAME | -name NAME] [-noshell] [-noinput] [-env VAR VALUE] [-compile file ...] [-make] [-man [manopts] MANPAGE] [-x] [-emu_args] [-start_epmd BOOLEAN] [-emu_type TYPE] [-emu_flavor FLAVOR] [-args_file FILENAME] [+A THREADS] [+a SIZE] [+B[c|d|i]] [+c [BOOLEAN]] [+C MODE] [+dcg DECENTRALIZED_COUNTER_GROUPS_LIMIT] [+h HEAP_SIZE_OPTION] [+J[Pperf|Msingle] JIT_OPTION] [+M<SUBSWITCH> <ARGUMENT>] [+P MAX_PROCS] [+Q MAX_PORTS] [+r] [+rg READER_GROUPS_LIMIT] [+s<SUBSWITCH> SCHEDULER_OPTION] [+S NO_SCHEDULERS:NO_SCHEDULERS_ONLINE] [+SP PERCENTAGE_SCHEDULERS:PERCENTAGE_SCHEDULERS_ONLINE] [+T LEVEL] [+V] [+v] [+W<i|w|e>] [+z MISC_OPTION] [args ...]";

// Port of erts/emulator/beam/erl_alloc.c:1324 (handle_au_arg "as"), OTP-29.1.1.
const MBAS_ALGS: &[&str] = &[
    "bf",
    "aobf",
    "gf",
    "af",
    "aoff",
    "aoffcbf",
    "aoffcaobf",
    "ageffcaoff",
    "ageffcbf",
    "ageffcaobf",
];

const OTP_29_USAGE: &str = include_str!("otp_29_1_1_usage.txt");

fn allocator_diagnostic(message: String) -> ArgsError {
    ArgsError::ErlDiagnostic(format!("{message}\r\n{OTP_29_USAGE}"))
}

// Port of erts/emulator/beam/erl_alloc.c:1088-1554 and :1556-1858, OTP-29.1.1.
fn validate_allocator_flag(name: &str, value: &str) -> Result<(), ArgsError> {
    let rest = name.strip_prefix("+M").unwrap_or("");
    let bad_param = || {
        let prefix_len = if rest == "ea" || rest.starts_with('u') {
            3
        } else {
            2.min(name.len().saturating_sub(1))
        };
        allocator_diagnostic(format!(
            "bad \"{}\" parameter",
            &name[1..1 + prefix_len.min(name.len().saturating_sub(1))]
        ))
    };
    let bad_value = || allocator_diagnostic(format!("bad \"{}\" value: {value}", &name[1..]));
    let is_number = |nonzero: bool| {
        allocator_signed_prefix(value)
            .is_some_and(|number| if nonzero { number > 0 } else { number >= 0 })
    };
    let is_bool = matches!(value, "true" | "false");
    if let Some(allocator) = rest.chars().next()
        && "BIDEFHLRSTZ".contains(allocator)
    {
        let switch = &rest[allocator.len_utf8()..];
        return match switch {
            "as" => {
                if MBAS_ALGS.contains(&value) || allocator == 'Z' && value == "chaosff" {
                    Ok(())
                } else {
                    Err(bad_value())
                }
            }
            "e" | "t" | "ramv" => {
                if switch == "e" && value == "false" && matches!(allocator, 'T' | 'I')
                    || switch == "t" && value == "true" && allocator == 'I'
                {
                    return Err(bad_value());
                }
                if is_bool { Ok(()) } else { Err(bad_value()) }
            }
            "atags" => {
                if matches!(value, "true" | "false" | "code") {
                    Ok(())
                } else {
                    Err(bad_value())
                }
            }
            "acul" | "acful" => {
                if matches!(allocator, 'T' | 'I') {
                    return Err(bad_param());
                }
                if value == "de"
                    || allocator_signed_prefix(value)
                        .is_some_and(|number| (0..=100).contains(&number))
                {
                    Ok(())
                } else {
                    Err(bad_value())
                }
            }
            "acnl" | "acfml" | "asbcst" | "mbcgs" | "mbsd" | "mmmbc" | "mmsbc" => {
                if is_number(false) {
                    Ok(())
                } else {
                    Err(bad_value())
                }
            }
            "sbct" | "smbcs" | "mmbcs" | "lmbcs" => {
                if is_number(false) {
                    Ok(())
                } else {
                    Err(bad_value())
                }
            }
            "rsbcst" | "rsbcmt" | "rmbcmt" => {
                if is_number(false) {
                    Ok(())
                } else {
                    Err(bad_value())
                }
            }
            "cp" => {
                if matches!(allocator, 'T' | 'I') {
                    return Err(bad_param());
                }
                if matches!(
                    value,
                    "B" | "D" | "E" | "F" | "H" | "L" | "R" | "S" | "@" | ":"
                ) {
                    Ok(())
                } else {
                    Err(bad_value())
                }
            }
            _ => Err(bad_param()),
        };
    }
    if let Some(switch) = rest.strip_prefix('u') {
        return match switch {
            "as" => {
                if MBAS_ALGS.contains(&value) {
                    Ok(())
                } else {
                    Err(bad_value())
                }
            }
            "e" | "t" | "ramv" => {
                if is_bool {
                    Ok(())
                } else {
                    Err(bad_value())
                }
            }
            "atags" => {
                if matches!(value, "true" | "false" | "code") {
                    Ok(())
                } else {
                    Err(bad_value())
                }
            }
            "acul" | "acful" => {
                if value == "de"
                    || allocator_signed_prefix(value)
                        .is_some_and(|number| (0..=100).contains(&number))
                {
                    Ok(())
                } else {
                    Err(bad_value())
                }
            }
            "cp" => {
                if matches!(
                    value,
                    "B" | "D" | "E" | "F" | "H" | "L" | "R" | "S" | "@" | ":"
                ) {
                    Ok(())
                } else {
                    Err(bad_value())
                }
            }
            "acnl" | "acfml" | "asbcst" | "mbcgs" | "mbsd" | "mmmbc" | "mmsbc" | "sbct"
            | "smbcs" | "mmbcs" | "lmbcs" | "rsbcst" | "rsbcmt" | "rmbcmt" => {
                if is_number(false) {
                    Ok(())
                } else {
                    Err(bad_value())
                }
            }
            _ => Err(bad_param()),
        };
    }
    match rest {
        "ea" => {
            if matches!(value, "min" | "max" | "r9c" | "r10b" | "r11b") {
                Ok(())
            } else {
                Err(bad_param())
            }
        }
        "lpm" => {
            if matches!(value, "all" | "no") {
                Ok(())
            } else {
                Err(bad_value())
            }
        }
        "dai" => {
            if value == "max" || is_number(false) {
                Ok(())
            } else {
                Err(bad_value())
            }
        }
        "ycs" | "mmc" | "sac" | "madtn" => {
            if is_bool || is_number(false) {
                Ok(())
            } else {
                Err(bad_value())
            }
        }
        "Msco" | "Mscrpm" => {
            if is_bool {
                Ok(())
            } else {
                Err(bad_value())
            }
        }
        "Mscs" | "Iscs" => {
            if is_number(false) {
                Ok(())
            } else {
                Err(bad_value())
            }
        }
        "Mscrfsd" | "Mrmcbf" | "Mmcs" => {
            if is_number(false) {
                Ok(())
            } else {
                Err(bad_value())
            }
        }
        "Mamcbf" => {
            if is_number(false) {
                Ok(())
            } else {
                Err(bad_value())
            }
        }
        "Mlp" => {
            if matches!(value, "on" | "off") {
                Ok(())
            } else {
                Err(bad_value())
            }
        }
        "Ytt" | "Ytp" => {
            if is_number(false) {
                Ok(())
            } else {
                Err(bad_value())
            }
        }
        "Ym" => Ok(()),
        "Ye" => {
            if value == "true" {
                Ok(())
            } else {
                Err(bad_value())
            }
        }
        _ => Err(bad_param()),
    }
}

fn allocator_signed_prefix(value: &str) -> Option<i64> {
    let value = value.trim_start();
    let (negative, digits) = if let Some(rest) = value.strip_prefix('-') {
        (true, rest)
    } else {
        (false, value.strip_prefix('+').unwrap_or(value))
    };
    let digits = digits
        .bytes()
        .take_while(u8::is_ascii_digit)
        .collect::<Vec<_>>();
    if digits.is_empty() {
        return None;
    }
    let magnitude = digits.iter().try_fold(0_i128, |number, digit| {
        number
            .checked_mul(10)?
            .checked_add(i128::from(digit - b'0'))
    })?;
    let signed = if negative { -magnitude } else { magnitude };
    i64::try_from(signed).ok()
}

/// Parse launcher `argv` (including `argv[0]`) using only the supplied environment.
///
/// Port of `erts/etc/common/erlexec.c` (`initial_argv_massage` and the main
/// option loop) and `erts/preloaded/src/init.erl` (`parse_boot_args`), OTP-29.1.1.
pub fn parse<S: AsRef<str>>(argv: &[S], env: &impl Env) -> Result<Launch, ArgsError> {
    let argv: Vec<&str> = argv.iter().map(AsRef::as_ref).collect();
    // An installed Arinsal release is self-contained. Only the explicit
    // Arinsal override may take precedence over its adjacent OTP bundle.
    let arinsal_override = env.get("ARINSAL_OTP_ROOT").filter(|root| !root.is_empty());
    let bundled_root = bundled_otp_root().map(|root| root.to_string_lossy().into_owned());
    let erl_root_override = env.get("ERL_ROOTDIR").filter(|root| !root.is_empty());
    let root_override = arinsal_override.or(bundled_root).or(erl_root_override);
    let root_dir = root_override
        .clone()
        .or_else(|| env.get("ROOTDIR").filter(|root| !root.is_empty()))
        .or_else(|| infer_root(argv.first().copied().unwrap_or("")))
        .or_else(|| discover_otp_root(env))
        .unwrap_or_default();
    let bin_dir = root_override
        .map(|root| format!("{root}/erts-17.1/bin"))
        .or_else(|| env.get("BINDIR"))
        .unwrap_or_else(|| {
            if root_dir.is_empty() {
                String::new()
            } else {
                format!("{root_dir}/erts-17.1/bin")
            }
        });
    let progname = env.get("PROGNAME").unwrap_or_else(|| "erl".into());

    let mut args = Vec::new();
    let mut extras = Vec::new();
    let mut ending_start = Vec::new();
    let release_flags = tokenize(&env.get("ERL_OTP29_FLAGS").unwrap_or_default(), false);
    massage_source(
        release_flags,
        true,
        &mut args,
        &mut extras,
        &mut ending_start,
    )?;
    let aflags = tokenize(&env.get("ERL_AFLAGS").unwrap_or_default(), false);
    massage_source(aflags, true, &mut args, &mut extras, &mut ending_start)?;
    massage_source(
        argv.iter().skip(1).map(|s| (*s).to_owned()).collect(),
        false,
        &mut args,
        &mut extras,
        &mut ending_start,
    )?;
    let flags = tokenize(&env.get("ERL_FLAGS").unwrap_or_default(), false);
    massage_source(flags, true, &mut args, &mut extras, &mut ending_start)?;
    let zflags = tokenize(&env.get("ERL_ZFLAGS").unwrap_or_default(), false);
    massage_source(zflags, true, &mut args, &mut extras, &mut ending_start)?;
    if !extras.is_empty() {
        args.push("-extra".into());
        args.extend(extras);
    }
    args.extend(ending_start);

    let mut emulator = EmulatorFlags::default();
    let mut set_env = BTreeMap::new();
    let mut init_tokens = Vec::new();
    if let Some(home) = env.get("HOME") {
        init_tokens.extend(["-home".into(), home]);
    }
    // Port of erts/etc/common/erlexec.c:1754 (add_epmd_port), OTP-29.1.1.
    if let Some(port) = env.get("ERL_EPMD_PORT") {
        init_tokens.extend(["-epmd_port".into(), port]);
    }
    init_tokens.push("--".into());
    let mut i = 0;
    let mut extra = false;
    let mut emu_type: Option<String> = None;
    let mut emu_flavor: Option<String> = None;
    let mut saw_emulator_selector = false;
    while i < args.len() {
        let token = &args[i];
        if extra {
            init_tokens.push(token.clone());
            i += 1;
            continue;
        }
        if token == "-extra" {
            extra = true;
            init_tokens.push(token.clone());
            i += 1;
            continue;
        }
        if token == "-env" {
            let name = args
                .get(i + 1)
                .ok_or_else(|| ArgsError::MissingValue(token.clone()))?;
            let value = args
                .get(i + 2)
                .ok_or_else(|| ArgsError::MissingValue(token.clone()))?;
            set_env.insert(name.clone(), value.clone());
            i += 3;
            continue;
        }
        if matches!(
            token.as_str(),
            "-sname" | "-name" | "-emu_type" | "-emu_flavor"
        ) {
            // Port of erts/etc/common/erlexec.c:412 (NEXT_ARG_CHECK) and the
            // -sname/-name/-emu_type/-emu_flavor arms, OTP-29.1.1.
            let value = require_erl_value(&args, i, token)?;
            if token == "-emu_type" {
                emu_type = Some(value.clone());
                saw_emulator_selector = true;
            } else if token == "-emu_flavor" {
                emu_flavor = Some(value.clone());
                saw_emulator_selector = true;
            }
            init_tokens.push(token.clone());
            init_tokens.push(value);
            i += 2;
            continue;
        }
        if matches!(
            token.as_str(),
            "-compile"
                | "-make"
                | "-man"
                | "-version"
                | "-start_erl"
                | "-emu_args_exit"
                | "-emu_name_exit"
                | "-emu_qouted_cmd_exit"
        ) {
            return Err(ArgsError::UnsupportedOption(token.clone()));
        }
        if token == "-emu_args" {
            i += 1;
            continue;
        }
        if token == "-detached" {
            init_tokens.extend(["-detached".into(), "-noshell".into(), "-noinput".into()]);
            i += 1;
            continue;
        }
        if token == "-noinput" {
            init_tokens.extend(["-noshell".into(), "-noinput".into()]);
            i += 1;
            continue;
        }
        if token == "++S" {
            init_tokens.extend(["-noshell".into(), "-S".into()]);
            init_tokens.extend(args[i + 1..].iter().cloned());
            break;
        }
        if token.starts_with('+') {
            i += parse_emulator_flag(&args, i, &mut emulator)?;
            continue;
        }
        init_tokens.push(token.clone());
        i += 1;
    }
    if saw_emulator_selector {
        // Port of erts/etc/common/erlexec.c:350 (add_extra_suffixes) and
        // :1240 (ENOENT emulator type/flavor), OTP-29.1.1.
        validate_emulator(
            &bin_dir,
            emu_type.as_deref(),
            emu_flavor.as_deref().unwrap_or("smp"),
        )?;
    }
    let mut boot_tokens = vec![
        "-root".into(),
        root_dir.clone(),
        "-bindir".into(),
        bin_dir.clone(),
        "-progname".into(),
        progname,
    ];
    boot_tokens.push("--".into());
    boot_tokens.extend(init_tokens);
    let boot_args = boot_tokens.clone();
    let init = parse_init(&boot_tokens);
    // init:get_flag/3 and erl_distribution use the first occurrence.
    let first = |name: &str| {
        init.get_argument(name)
            .and_then(|groups| groups.first().and_then(|values| values.first()).cloned())
    };
    let path = erlexec_path(&bin_dir, &root_dir, env.get("PATH").as_deref());
    Ok(Launch {
        path,
        boot_script: first("boot"),
        mode: first("mode"),
        noshell: init.get_argument("noshell").is_some(),
        detached: init.get_argument("detached").is_some(),
        sname: first("sname"),
        name: first("name"),
        emulator,
        init,
        root_dir,
        bin_dir,
        set_env,
        boot_args,
    })
}

/// Find the OTP tree bundled beside the running `arinsal` executable.
pub fn bundled_otp_root() -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?;
    bundled_otp_root_for_executable(&executable)
}

/// Resolve the bundle location for an executable at `<prefix>/bin/arinsal`.
pub fn bundled_otp_root_for_executable(executable: &Path) -> Option<PathBuf> {
    let bin = executable.parent()?;
    if bin.file_name()?.to_str()? != "bin" {
        return None;
    }
    let prefix = bin.parent()?;
    let root = prefix.join("lib/arinsal/otp");
    // `lib/arinsal` marks an installed release: a missing bundle inside it
    // must fail loudly rather than fall back to a system Erlang.
    prefix.join("lib/arinsal").is_dir().then_some(root)
}

/// Discover the OTP root through an `erl` executable other than this process.
///
/// A launcher shim may itself be named `erl`; excluding the current executable
/// prevents root discovery from recursively starting the same emulator.
// Port of erts/etc/common/erlexec.c:1632-1650, OTP-29.1.1.
pub fn discover_otp_root(env: &impl Env) -> Option<String> {
    let path = env.get("PATH")?;
    let current = std::env::current_exe()
        .ok()
        .and_then(|executable| executable.canonicalize().ok())?;
    let executable = if cfg!(windows) { "erl.exe" } else { "erl" };
    let directories: Vec<PathBuf> = std::env::split_paths(&path)
        .filter(|directory| {
            let candidate = directory.join(executable);
            if !candidate.exists() {
                return true;
            }
            candidate
                .canonicalize()
                .is_ok_and(|resolved| resolved != current)
        })
        .collect();
    let candidates: Vec<PathBuf> = directories
        .iter()
        .map(|directory| directory.join(executable))
        .filter(|candidate| candidate.is_file())
        .collect();
    let safe_path = std::env::join_paths(&directories).ok()?;
    for candidate in candidates {
        let Ok(output) = std::process::Command::new(candidate)
            .env("PATH", &safe_path)
            .args([
                "-noshell",
                "-eval",
                "io:format(\"~s\",[code:root_dir()]),halt().",
            ])
            .output()
        else {
            continue;
        };
        if output.status.success()
            && let Ok(root) = String::from_utf8(output.stdout)
            && !root.is_empty()
        {
            return Some(root);
        }
    }
    None
}

fn infer_root(executable: &str) -> Option<String> {
    let path = Path::new(executable);
    let parent = path.parent()?;
    if parent.file_name()?.to_str()? == "bin" {
        let grandparent = parent.parent()?;
        if grandparent.file_name()?.to_str()?.starts_with("erts-") {
            return Some(grandparent.parent()?.to_string_lossy().into_owned());
        }
        return Some(grandparent.to_string_lossy().into_owned());
    }
    None
}

// Port of erlexec.c:1770-1929 (build_args_from_string), OTP-29.1.1.
fn tokenize(input: &str, comments: bool) -> Vec<String> {
    let mut result = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(&ch) = chars.peek() {
        if ch.is_ascii_whitespace() {
            chars.next();
            continue;
        }
        if comments && ch == '#' {
            for c in chars.by_ref() {
                if c == '\n' {
                    break;
                }
            }
            continue;
        }
        let mut token = String::new();
        let mut quote = None;
        while let Some(&c) = chars.peek() {
            if quote.is_none() && (c.is_ascii_whitespace() || (comments && c == '#')) {
                break;
            }
            chars.next();
            match (quote, c) {
                (None, '\'') | (None, '"') => quote = Some(c),
                (Some(q), c) if q == c => quote = None,
                (None, '\\') => {
                    if let Some(next) = chars.next() {
                        token.push(next);
                    }
                }
                _ => token.push(c),
            }
        }
        result.push(token);
    }
    result
}

// Port of erlexec.c:2106-2259 (args_file expansion and source merge), OTP-29.1.1.
fn massage_source(
    mut tokens: Vec<String>,
    from_string: bool,
    args: &mut Vec<String>,
    extras: &mut Vec<String>,
    ending_start: &mut Vec<String>,
) -> Result<(), ArgsError> {
    if tokens.is_empty() {
        return Ok(());
    }
    if from_string && !tokens.iter().any(|s| s == "-extra") {
        tokens.push("--".into());
    }
    massage_tokens(&tokens, args, extras, ending_start, 0, !from_string)?;
    if !from_string {
        args.push("--".into());
    }
    Ok(())
}

fn massage_tokens(
    tokens: &[String],
    args: &mut Vec<String>,
    extras: &mut Vec<String>,
    ending_start: &mut Vec<String>,
    depth: usize,
    command_line: bool,
) -> Result<(), ArgsError> {
    let mut i = 0;
    while i < tokens.len() {
        match tokens[i].as_str() {
            "-args_file" => {
                let file = tokens
                    .get(i + 1)
                    .ok_or_else(|| ArgsError::MissingValue("-args_file".into()))?;
                if depth >= 64 {
                    return Err(ArgsError::ArgsFileDepth);
                }
                let contents = fs::read_to_string(file).map_err(|source| ArgsError::ArgsFile {
                    path: file.clone(),
                    source,
                })?;
                let mut nested = tokenize(&contents, true);
                if !nested.is_empty() {
                    if !nested.iter().any(|s| s == "-extra") {
                        nested.push("--".into());
                    }
                    massage_tokens(&nested, args, extras, ending_start, depth + 1, false)?;
                }
                i += 2;
            }
            "-extra" => {
                extras.extend_from_slice(&tokens[i + 1..]);
                args.push("--".into());
                return Ok(());
            }
            "-S" if command_line => {
                ending_start.push("++S".into());
                ending_start.extend(
                    tokens[i + 1..]
                        .iter()
                        .map(|v| if v == "--" { "\\--".into() } else { v.clone() }),
                );
                args.push("--".into());
                return Ok(());
            }
            _ => {
                args.push(tokens[i].clone());
                i += 1;
            }
        }
    }
    Ok(())
}

// Port of init.erl:1668-1748 (parse_boot_args, check, get_args), OTP-29.1.1.
fn parse_init(tokens: &[String]) -> InitArgs {
    let mut result = InitArgs::default();
    let mut i = 0;
    while i < tokens.len() {
        let token = &tokens[i];
        if token == "-extra" {
            result.plain_args.extend_from_slice(&tokens[i + 1..]);
            break;
        }
        if token == "--" {
            i += 1;
            continue;
        }
        if token == "-S" && !tokens[i + 1..].iter().any(|v| v == "--") {
            break;
        }
        if token == "-s" || token == "-run" || token == "-eval" {
            i += 1;
            while i < tokens.len() && !is_boundary(&tokens[i], &tokens[i + 1..]) {
                i += 1;
            }
            continue;
        }
        if let Some(name) = token.strip_prefix('-') {
            i += 1;
            let start = i;
            while i < tokens.len() && !is_boundary(&tokens[i], &tokens[i + 1..]) {
                i += 1;
            }
            result.flags.push(InitFlag {
                name: name.into(),
                values: tokens[start..i].to_vec(),
            });
            continue;
        }
        result.plain_args.push(token.clone());
        i += 1;
    }
    result
}

fn is_boundary(token: &str, rest: &[String]) -> bool {
    token == "--"
        || token == "-extra"
        || token == "-s"
        || token == "-run"
        || token == "-eval"
        || (token == "-S" && !rest.iter().any(|s| s == "--"))
        || token.starts_with('-')
}

fn parse_emulator_flag(
    args: &[String],
    i: usize,
    out: &mut EmulatorFlags,
) -> Result<usize, ArgsError> {
    let token = &args[i];
    let (name, inline) = split_emulator_flag(token);
    let mut consumed = 1;
    let value = |required: bool, consumed: &mut usize| -> Result<Option<String>, ArgsError> {
        if let Some(v) = inline {
            return Ok(Some(v.into()));
        }
        if let Some(next) = args.get(i + 1)
            && next != "--"
            && (required || (!next.starts_with('-') && !next.starts_with('+')))
        {
            *consumed = 2;
            return Ok(Some(next.clone()));
        }
        if required {
            Err(ArgsError::MissingValue(token.clone()))
        } else {
            Ok(None)
        }
    };
    match name {
        // Port of erts/emulator/beam/erl_init.c:1935-2038 (scheduler option parsing), OTP-29.1.1.
        "+scl" | "+sub" | "+spp" => {
            let v = value(true, &mut consumed)?.unwrap();
            let parsed = match v.as_str() {
                "true" => true,
                "false" => false,
                _ => {
                    let message = match name {
                        "+scl" => format!("bad scheduler compact load value '{v}'"),
                        "+sub" => format!("bad scheduler utilization balancing  value '{v}'"),
                        _ => format!("bad port parallelism scheduling hint {v}"),
                    };
                    return Err(scheduler_diagnostic(message));
                }
            };
            match name {
                "+scl" => {
                    out.scheduler.compact_load = Some(parsed);
                    if parsed {
                        out.scheduler.utilization_balancing = Some(false);
                    }
                }
                "+sub" => out.scheduler.utilization_balancing = Some(parsed),
                _ => out.scheduler.port_parallelism = Some(parsed),
            }
        }
        // Port of erts/emulator/beam/erl_init.c:1925-1978 and erl_process.c:5814-5899,
        // OTP-29.1.1.
        "+sbwt" | "+sbwtdcpu" | "+sbwtdio" => {
            let v = value(true, &mut consumed)?.unwrap();
            if !matches!(
                v.as_str(),
                "none" | "very_short" | "short" | "medium" | "long" | "very_long"
            ) {
                let scheduler = match name {
                    "+sbwt" => "scheduler",
                    "+sbwtdcpu" => "dirty CPU scheduler",
                    _ => "dirty IO scheduler",
                };
                return Err(scheduler_diagnostic(format!(
                    "bad {scheduler} busy wait threshold: {v}"
                )));
            }
            let index = match name {
                "+sbwt" => 0,
                "+sbwtdcpu" => 1,
                _ => 2,
            };
            out.scheduler.busy_wait[index] = Some(v);
        }
        // Port of erts/emulator/beam/erl_init.c:2095-2124 and erl_process.c:5814-5837,
        // OTP-29.1.1.
        "+swt" | "+swtdcpu" | "+swtdio" => {
            let v = value(true, &mut consumed)?.unwrap();
            if !matches!(
                v.as_str(),
                "very_low" | "low" | "medium" | "high" | "very_high"
            ) {
                let scheduler = match name {
                    "+swt" => "scheduler",
                    "+swtdcpu" => "dirty CPU scheduler",
                    _ => "dirty IO scheduler",
                };
                return Err(scheduler_diagnostic(format!(
                    "{scheduler} wakeup threshold: {v}"
                )));
            }
            let index = match name {
                "+swt" => 0,
                "+swtdcpu" => 1,
                _ => 2,
            };
            out.scheduler.wakeup[index] = Some(v);
        }
        // Port of erts/emulator/beam/erl_init.c:2087-2094 and erl_process.c:5892-5904,
        // OTP-29.1.1.
        "+sfwi" => {
            let v = value(true, &mut consumed)?.unwrap();
            let parsed = v
                .parse::<i64>()
                .ok()
                .filter(|value| *value >= 0)
                .ok_or_else(|| {
                    scheduler_diagnostic(format!("bad scheduler forced wakeup interval {v}"))
                })? as u64;
            out.scheduler.forced_wakeup_interval = Some(parsed);
        }
        // Port of erts/emulator/beam/erl_init.c:1914-1944, OTP-29.1.1.
        "+sbt" => {
            let v = value(true, &mut consumed)?.unwrap();
            if !matches!(
                v.as_str(),
                "u" | "db" | "s" | "ps" | "ts" | "tnnps" | "nnps" | "nnts" | "ns"
            ) {
                return Err(scheduler_diagnostic(format!(
                    "setting scheduler bind type '{v}' failed: invalid type"
                )));
            }
            out.scheduler.bind_type = Some(v);
        }
        // Port of erts/emulator/beam/erl_init.c:1648-1667, OTP-29.1.1.
        "+D" => {
            if let Some(value) = inline {
                return Err(invalid(token, value));
            }
            out.debugger_support = true;
        }
        "+Dibpl" => {
            let v = value(true, &mut consumed)?.unwrap();
            out.debugger_line_breakpoints = Some(match v.as_str() {
                "true" => true,
                "false" => false,
                _ => return Err(invalid(token, &v)),
            });
        }
        "+S" | "+SDPcpu" => {
            let v = value(true, &mut consumed)?.unwrap();
            let count = scheduler_count(token, &v)?;
            if name == "+S" {
                out.schedulers = Some(count);
            } else {
                out.dirty_cpu_schedulers = Some(count);
            }
        }
        "+SDcpu" => {
            // Port of erts/emulator/beam/erl_init.c:1031 (erl_start -SDcpu), OTP-29.1.1.
            // The count is recorded and not applied: Arinsal does not run dirty CPU schedulers.
            let v = require_plus_value(args, i, token, &mut consumed)?;
            out.dirty_cpu_schedulers = Some(dirty_cpu_schedulers(token, &v)?);
        }
        "+IOs" => {
            // Port of erts/emulator/sys/common/erl_check_io.c (parse_args +IOs), OTP-29.1.1.
            let v = value(true, &mut consumed)?.unwrap();
            out.scheduler_polling = Some(match v.as_str() {
                "true" => true,
                "false" => false,
                _ => {
                    return Err(scheduler_diagnostic(format!(
                        "bad +IOs boolean argument: {v}"
                    )));
                }
            });
        }
        "+SDio" => {
            let v = value(true, &mut consumed)?.unwrap();
            out.dirty_io_schedulers = Some(positive_u32(token, &v)?);
        }
        "+P" | "+Q" => {
            let v = value(true, &mut consumed)?.unwrap();
            let limit = if v == "legacy" {
                Limit::Legacy
            } else {
                let minimum = 1024;
                let maximum = (1_u64 << 27) - 1;
                let number = positive_u64(token, &v)?;
                if !(minimum..=maximum).contains(&number) {
                    return Err(invalid(token, &v));
                }
                Limit::Value(number)
            };
            if name == "+P" {
                out.process_limit = Some(limit);
            } else {
                out.port_limit = Some(limit);
            }
        }
        "+t" => {
            let v = value(true, &mut consumed)?.unwrap();
            let number = positive_u64(token, &v)?;
            if !(8192..=i32::MAX as u64).contains(&number) {
                return Err(invalid(token, &v));
            }
            out.atom_limit = Some(number);
        }
        "+hms" | "+hmbs" => {
            let v = require_plus_value(args, i, token, &mut consumed)?;
            if name == "+hms" {
                // Port of erts/emulator/beam/erl_init.c:1556 (erl_start -hms), OTP-29.1.1.
                // The VM applies this through erts_next_heap_size at startup.
                let words = c_atoi(&v);
                if words <= 0 {
                    return Err(ArgsError::ErlDiagnostic(format!("bad heap size {v}")));
                }
                out.min_heap_size = Some(u64::try_from(words).unwrap_or(u64::MAX));
            } else {
                // Port of erts/emulator/beam/erl_init.c:1548 (erl_start -hmbs), OTP-29.1.1.
                let words = c_atoi(&v);
                if words <= 0 {
                    return Err(ArgsError::ErlDiagnostic(format!("bad heap size {v}")));
                }
                out.min_binary_heap_size = Some(words as u64);
            }
        }
        "+zdbbl" => {
            let v = value(true, &mut consumed)?.unwrap();
            // Port of erts/emulator/beam/erl_init.c:2376 (erl_start -zdbbl), OTP-29.1.1.
            let limit = c_atoi(&v);
            if !(1..=2_097_151).contains(&limit) {
                return Err(ArgsError::ErlDiagnostic(format!(
                    "Invalid dbbl limit: {limit}"
                )));
            }
            out.distribution_buffer_busy_limit = Some(limit as u64);
        }
        "+C" => {
            let v = value(true, &mut consumed)?.unwrap();
            out.time_warp = Some(match v.as_str() {
                "no_time_warp" => TimeWarp::None,
                "single_time_warp" => TimeWarp::Single,
                "multi_time_warp" => TimeWarp::Multi,
                _ => return Err(invalid(token, &v)),
            });
        }
        "+c" => {
            // erlexec consumes a separate value only when it is a boolean.
            let v = if inline.is_some() {
                value(false, &mut consumed)?
            } else if matches!(args.get(i + 1).map(String::as_str), Some("true" | "false")) {
                consumed = 2;
                args.get(i + 1).cloned()
            } else {
                None
            };
            out.time_correction = Some(match v.as_deref() {
                None | Some("false") => false,
                Some("true") => true,
                Some(other) => return Err(invalid(token, other)),
            });
        }
        "+B" => {
            let v = if matches!(args.get(i + 1).map(String::as_str), Some("i" | "c" | "d")) {
                consumed = 2;
                args.get(i + 1).cloned()
            } else {
                None
            };
            out.ignored.push(IgnoredFlag {
                name: name.into(),
                value: v,
            });
        }
        "+Zsim" => {
            let v = value(true, &mut consumed)?.unwrap();
            out.simulation_seed = Some(v.parse().map_err(|_| invalid(token, &v))?);
        }
        "+Spool" => {
            let v = value(true, &mut consumed)?.unwrap();
            let (name, cpus) = v.split_once(':').ok_or_else(|| invalid(token, &v))?;
            if name.is_empty() {
                return Err(invalid(token, &v));
            }
            let cpus: Result<Vec<_>, _> = cpus.split(',').map(|s| s.parse::<u32>()).collect();
            let cpus = cpus.map_err(|_| invalid(token, &v))?;
            if cpus.is_empty() {
                return Err(invalid(token, &v));
            }
            out.core_pools.push(CorePool {
                name: name.into(),
                cpus,
            });
        }
        _ => {
            let kind =
                ignored_kind(name).ok_or_else(|| ArgsError::UnknownEmulatorFlag(token.clone()))?;
            let v = if kind {
                Some(require_plus_value(args, i, token, &mut consumed)?)
            } else {
                None
            };
            if name == "+A" {
                // Port of erts/emulator/beam/erl_init.c:925 (erl_start -A), OTP-29.1.1.
                let arg = v.as_deref().unwrap_or("");
                let threads = c_atoi(arg);
                if !(0..=1024).contains(&threads) {
                    return Err(ArgsError::ErlDiagnostic(format!(
                        "bad number of async threads {arg}"
                    )));
                }
                out.async_threads = Some(threads as u32);
            } else if name == "+sbwt" {
                // Port of erts/emulator/beam/erl_process.c:5852
                // (erts_sched_set_busy_wait_threshold), OTP-29.1.1.
                let arg = v.as_deref().unwrap_or("");
                if !matches!(
                    arg,
                    "none" | "very_short" | "short" | "medium" | "long" | "very_long"
                ) {
                    return Err(ArgsError::ErlDiagnostic(format!(
                        "bad scheduler busy wait threshold: {arg}"
                    )));
                }
            } else if name == "+hmqd" {
                // Port of erts/emulator/beam/erl_init.c:1583 (erl_start -hmqd), OTP-29.1.1.
                let arg = v.as_deref().unwrap_or("");
                if !matches!(arg, "on_heap" | "off_heap") {
                    return Err(ArgsError::ErlDiagnostic(format!(
                        "Invalid message_queue_data flag: {arg}"
                    )));
                }
            } else if name == "+hmax" {
                // Port of erts/emulator/beam/erl_init.c:1619 (erl_start -hmax), OTP-29.1.1.
                let arg = v.as_deref().unwrap_or("");
                let size = arg.parse::<i64>().unwrap_or(0);
                if !(0..=(1_i64 << 59) - 1).contains(&size) {
                    return Err(ArgsError::ErlDiagnostic(format!("bad max heap size {arg}")));
                }
            } else if matches!(name, "+hmaxk" | "+hmaxel" | "+hmaxib") {
                // Port of erts/emulator/beam/erl_init.c:1593 (erl_start -hmax*), OTP-29.1.1.
                let arg = v.as_deref().unwrap_or("");
                if !matches!(arg, "true" | "false") {
                    let label = match name {
                        "+hmaxk" => "kill",
                        "+hmaxel" => "error logger",
                        _ => "include bins",
                    };
                    return Err(ArgsError::ErlDiagnostic(format!(
                        "bad max heap {label} {arg}"
                    )));
                }
            } else if name == "+MBas" {
                // Port of erts/emulator/beam/erl_alloc.c:1324 (handle_au_arg) and
                // :1100 (bad_value), OTP-29.1.1.
                let arg = v.as_deref().unwrap_or("");
                if !MBAS_ALGS.contains(&arg) {
                    return Err(allocator_diagnostic(format!("bad \"MBa\" value: {arg}")));
                }
            }
            if name.starts_with("+M") {
                validate_allocator_flag(name, v.as_deref().unwrap_or(""))?;
                out.allocator_options.push(IgnoredFlag {
                    name: name.to_owned(),
                    value: v.clone(),
                });
            }
            if name != "+A" {
                out.ignored.push(IgnoredFlag {
                    name: name.into(),
                    value: v,
                });
            }
        }
    }
    Ok(consumed)
}

fn split_emulator_flag(token: &str) -> (&str, Option<&str>) {
    const SCHEDULER_FLAGS: &[&str] = &[
        "+sbwtdcpu",
        "+sbwtdio",
        "+swtdcpu",
        "+swtdio",
        "+scl",
        "+sub",
        "+sbwt",
        "+swt",
        "+sfwi",
        "+spp",
        "+sbt",
    ];
    for prefix in SCHEDULER_FLAGS {
        if let Some(rest) = token.strip_prefix(prefix) {
            return (*prefix, (!rest.is_empty()).then_some(rest));
        }
    }
    const PREFIXES: &[&str] = &[
        "+SDPcpu", "+SDcpu", "+SDio", "+Spool", "+Zsim", "+zdbbl", "+hmbs", "+hms", "+Dibpl", "+D",
        "+s", "+h", "+M", "+JP", "+fn", "+pc", "+pa", "+SP", "+S", "+P", "+Q", "+t", "+C", "+c",
    ];
    for prefix in PREFIXES {
        if let Some(rest) = token.strip_prefix(prefix) {
            if *prefix == "+s"
                || *prefix == "+h"
                || *prefix == "+M"
                || *prefix == "+JP"
                || *prefix == "+fn"
                || *prefix == "+pc"
                || *prefix == "+pa"
            {
                return (token, None);
            }
            return (prefix, (!rest.is_empty()).then_some(rest));
        }
    }
    (token, None)
}

fn ignored_kind(name: &str) -> Option<bool> {
    // The accepted spellings follow erlexec.c's plus-option tables. Options
    // whose value is embedded in the spelling are returned with `false`.
    const VALUE: &[&str] = &[
        "+a",
        "+A",
        "+e",
        "+i",
        "+n",
        "+T",
        "+R",
        "+W",
        "+K",
        "+IOt",
        "+IOp",
        "+IOPt",
        "+IOPp",
        "+pc",
        "+pad",
        "+rg",
        "+zdbbl",
        "+zdntgc",
        "+zebwt",
        "+zosrl",
        "+zhft",
        "+h",
        "+hpds",
        "+hmax",
        "+hmaxk",
        "+hmaxel",
        "+hmaxib",
        "+hmqd",
        "+sbt",
        "+sbwt",
        "+sbwtdcpu",
        "+sbwtdio",
        "+scl",
        "+sct",
        "+secio",
        "+sfwi",
        "+stbt",
        "+swct",
        "+swtdcpu",
        "+swtdio",
        "+swt",
        "+sws",
        "+sss",
        "+sssdcpu",
        "+sssdio",
        "+spp",
        "+sub",
        "+SP",
    ];
    if VALUE.contains(&name) {
        return Some(true);
    }
    if let Some(rest) = name.strip_prefix("+M") {
        const ALLOCATORS: &str = "uBIDEFHLRSTZ";
        const ALLOC_SWITCHES: &[&str] = &[
            "as", "asbcst", "atags", "acul", "acnl", "acfml", "acful", "cp", "e", "t", "lmbcs",
            "mbcgs", "mbsd", "mmbcs", "mmmbc", "mmsbc", "msbclt", "ramv", "rmbcmt", "rsbcmt",
            "rsbcst", "sbct", "smbcs",
        ];
        const OTHER: &[&str] = &[
            "ea", "umadtn", "ummc", "uycs", "usac", "im", "is", "lpm", "Mamcbf", "Mrmcbf", "Mmcs",
            "Mscs", "Mscrfsd", "Msco", "Mscrpm", "Mlp", "Ye", "Ym", "Ytp", "Ytt", "Iscs", "Xscs",
            "dai",
        ];
        if OTHER.contains(&rest)
            || rest.chars().next().is_some_and(|c| ALLOCATORS.contains(c))
                && ALLOC_SWITCHES.contains(&&rest[1..])
        {
            return Some(true);
        }
        if rest.chars().next().is_some_and(|c| ALLOCATORS.contains(c)) {
            return Some(true);
        }
        return None;
    }
    if matches!(
        name,
        "+JPperf" | "+JPperfdirectory" | "+JPcover" | "+JMsingle" | "+JDdump"
    ) {
        return Some(true);
    }
    if name == "+B"
        || matches!(
            name,
            "+Bi" | "+Bc" | "+Bd" | "+d" | "+L" | "+v" | "+V" | "+r" | "+H" | "+ec"
        )
    {
        return Some(false);
    }
    if name.starts_with("+fn")
        && matches!(
            &name[3..],
            "u" | "l" | "a" | "uw" | "ui" | "ue" | "aw" | "ai" | "ae"
        )
    {
        return Some(false);
    }
    None
}

// Port of erts/etc/common/erlexec.c:412 (NEXT_ARG_CHECK), OTP-29.1.1.
fn require_erl_value(args: &[String], i: usize, flag: &str) -> Result<String, ArgsError> {
    match args.get(i + 1) {
        Some(value) if value != "--" => Ok(value.clone()),
        _ => Err(missing_erl_argument(flag)),
    }
}

fn require_plus_value(
    args: &[String],
    i: usize,
    token: &str,
    consumed: &mut usize,
) -> Result<String, ArgsError> {
    let (name, inline) = split_emulator_flag(token);
    if let Some(value) = inline {
        return Ok(value.to_owned());
    }
    match args.get(i + 1) {
        Some(value) if value != "--" => {
            *consumed = 2;
            Ok(value.clone())
        }
        _ => Err(missing_erl_argument(name)),
    }
}

fn missing_erl_argument(flag: &str) -> ArgsError {
    ArgsError::ErlDiagnostic(format!("Missing argument(s) for '{flag}'.\n{ERL_USAGE}\n"))
}

// Port of erts/etc/common/erlexec.c:350 (add_extra_suffixes) and
// :1240 (the ENOENT type/flavor report), OTP-29.1.1.
fn validate_emulator(bindir: &str, emu_type: Option<&str>, flavor: &str) -> Result<(), ArgsError> {
    let file = match emu_type {
        Some(kind) if kind != "opt" => format!("beam.{kind}.{flavor}"),
        _ => format!("beam.{flavor}"),
    };
    if Path::new(bindir).join(file).is_file() {
        return Ok(());
    }
    let combos = emulator_combinations(bindir);
    Err(ArgsError::ErlDiagnostic(format!(
        "erlexec: Invalid emulator type or flavor. Available combinations are: {combos}\n\n"
    )))
}

fn emulator_combinations(bindir: &str) -> String {
    let mut out = String::new();
    let Ok(entries) = fs::read_dir(bindir) else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some((_, after)) = name.split_once('.') else {
            continue;
        };
        if !name.starts_with("beam") {
            continue;
        }
        out.push_str("\n  ");
        if let Some((emu_type, flavor)) = after.split_once('.') {
            out.push_str("-emu_type ");
            out.push_str(emu_type);
            out.push(' ');
            out.push_str("-emu_flavor ");
            out.push_str(flavor);
        } else {
            out.push_str("-emu_flavor ");
            out.push_str(after);
        }
    }
    out
}

// Port of erts/emulator/beam/erl_init.c:1031 (erl_start, -SDcpu), OTP-29.1.1.
fn dirty_cpu_schedulers(_flag: &str, value: &str) -> Result<SchedulerCount, ArgsError> {
    let cpus = i32::try_from(
        std::thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(1),
    )
    .unwrap_or(i32::MAX);
    let parsed = parse_dirty_cpu(value).ok_or_else(|| {
        ArgsError::ErlDiagnostic(format!("bad amount of dirty CPU schedulers {value}"))
    })?;
    let (check_total, check_online) = match parsed {
        DirtyCpu::Both(total, online) => (total, online),
        DirtyCpu::Total(total) => (total, if total < cpus { total } else { cpus }),
        DirtyCpu::Online(online) => (cpus, online),
    };
    let dirty = if check_total > 0 {
        check_total
    } else {
        cpus.saturating_add(check_total)
    };
    let online_resolved = if check_online > 0 {
        check_online
    } else {
        cpus.saturating_add(check_online)
    };
    if !(1..=1024).contains(&dirty) {
        return Err(ArgsError::ErlDiagnostic(format!(
            "bad amount of dirty CPU schedulers {check_total}"
        )));
    }
    if online_resolved < 1 || dirty < online_resolved {
        return Err(ArgsError::ErlDiagnostic(format!(
            "bad amount of dirty CPU schedulers online {online_resolved} (total amount of dirty CPU schedulers {dirty})"
        )));
    }
    Ok(match parsed {
        DirtyCpu::Both(total, online) => SchedulerCount {
            total,
            online: Some(online),
        },
        DirtyCpu::Total(total) => SchedulerCount {
            total,
            online: None,
        },
        DirtyCpu::Online(online) => SchedulerCount {
            total: 0,
            online: Some(online),
        },
    })
}

#[derive(Clone, Copy)]
enum DirtyCpu {
    Both(i32, i32),
    Total(i32),
    Online(i32),
}

fn parse_dirty_cpu(value: &str) -> Option<DirtyCpu> {
    if let Some((total, rest)) = scan_i32(value) {
        if let Some(rest) = rest.strip_prefix(':')
            && let Some((online, _)) = scan_i32(rest)
        {
            return Some(DirtyCpu::Both(total, online));
        }
        return Some(DirtyCpu::Total(total));
    }
    sscanf_colon(value).map(DirtyCpu::Online)
}

fn sscanf_colon(value: &str) -> Option<i32> {
    let rest = value.trim_start().strip_prefix(':')?;
    scan_i32(rest).map(|(n, _)| n)
}

// C `atoi`: optional sign and digits, with a zero result when none are present.
fn c_atoi(value: &str) -> i32 {
    scan_i32(value).map(|(n, _)| n).unwrap_or(0)
}

fn scan_i32(value: &str) -> Option<(i32, &str)> {
    let value = value.trim_start();
    let (sign, rest) = if let Some(rest) = value.strip_prefix('+') {
        (1, rest)
    } else if let Some(rest) = value.strip_prefix('-') {
        (-1, rest)
    } else {
        (1, value)
    };
    let bytes = rest.as_bytes();
    if bytes.first().is_none_or(|byte| !byte.is_ascii_digit()) {
        return None;
    }
    let mut number: i32 = 0;
    let mut index = 0;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        number = number
            .saturating_mul(10)
            .saturating_add(i32::from(bytes[index] - b'0'));
        index += 1;
    }
    Some((number.saturating_mul(sign), &rest[index..]))
}

fn scheduler_count(flag: &str, value: &str) -> Result<SchedulerCount, ArgsError> {
    let (total, online) = match value.split_once(':') {
        Some(("", online)) => (
            0,
            Some(online.parse::<i32>().map_err(|_| invalid(flag, value))?),
        ),
        Some((total, online)) => (
            total.parse::<i32>().map_err(|_| invalid(flag, value))?,
            Some(online.parse::<i32>().map_err(|_| invalid(flag, value))?),
        ),
        None => (
            value.parse::<i32>().map_err(|_| invalid(flag, value))?,
            None,
        ),
    };
    if total == 0 && online.is_none() || online == Some(0) {
        return Err(invalid(flag, value));
    }
    Ok(SchedulerCount { total, online })
}

fn positive_u32(flag: &str, value: &str) -> Result<u32, ArgsError> {
    value
        .parse::<u32>()
        .ok()
        .filter(|v| *v > 0)
        .ok_or_else(|| invalid(flag, value))
}

fn positive_u64(flag: &str, value: &str) -> Result<u64, ArgsError> {
    value
        .parse::<u64>()
        .ok()
        .filter(|v| *v > 0)
        .ok_or_else(|| invalid(flag, value))
}

fn invalid(flag: &str, value: &str) -> ArgsError {
    ArgsError::InvalidValue {
        flag: flag.into(),
        value: value.into(),
    }
}

fn scheduler_diagnostic(message: String) -> ArgsError {
    ArgsError::ErlDiagnostic(format!("{message}\r\n{OTP_29_USAGE}"))
}
