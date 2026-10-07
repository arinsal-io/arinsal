use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const SCENARIOS: [&str; 6] = ["bench", "boot", "hello", "elixir", "iex", "mix"];

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Call {
    module: String,
    function: String,
    arity: u8,
}

#[derive(Clone, Debug)]
struct Entry {
    call: Call,
    calls: u64,
    kind: String,
    implemented: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("gap-report: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let root = workspace_root()?;
    if std::env::args().any(|arg| arg == "--bif-tab") {
        return bif_tab_missing(&root);
    }
    let mut scenarios = BTreeMap::new();
    for scenario in SCENARIOS {
        let path = root
            .join("docs/census")
            .join(format!("dynamic-{scenario}.csv"));
        scenarios.insert(scenario, read_scenario(&path)?);
    }
    let opcodes = unsupported_opcodes(&root)?;
    let report = render(&scenarios, &opcodes);
    let output = root.join("docs/status/gap.md");
    std::fs::create_dir_all(output.parent().expect("report has parent"))?;
    std::fs::write(&output, &report)?;
    let erts = erts_index();
    let missing = render_missing(&scenarios, &erts);
    let missing_path = root.join("docs/status/missing.md");
    std::fs::write(&missing_path, &missing)?;
    print_summary(&scenarios);
    println!("wrote docs/status/gap.md");
    println!("wrote docs/status/missing.md");
    Ok(())
}

fn print_summary(scenarios: &BTreeMap<&str, Vec<Entry>>) {
    println!("| Scenario | Implemented | Total distinct BIFs + NIFs | Coverage |");
    println!("|---|---:|---:|---:|");
    for scenario in SCENARIOS {
        let entries = &scenarios[scenario];
        let total = entries.len();
        let implemented = entries.iter().filter(|entry| entry.implemented).count();
        let percent = if total == 0 {
            0.0
        } else {
            implemented as f64 * 100.0 / total as f64
        };
        println!("| {scenario} | {implemented} | {total} | {percent:.1}% |");
    }
}

fn workspace_root() -> Result<PathBuf> {
    let cwd = std::env::current_dir()?;
    for path in cwd.ancestors() {
        if path.join("Cargo.toml").is_file() && path.join("docs/census").is_dir() {
            return Ok(path.to_path_buf());
        }
    }
    Err("run from inside the Arinsal workspace".into())
}

fn read_scenario(path: &Path) -> Result<Vec<Entry>> {
    let input = std::fs::read_to_string(path)?;
    let mut lines = input.lines();
    let header = lines.next().ok_or("empty census CSV")?;
    if header != "module,function,arity,calls,kind" {
        return Err(format!("unexpected header in {}", path.display()).into());
    }

    let mut entries = BTreeMap::<(Call, String), u64>::new();
    for (line_index, line) in lines.enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let fields = parse_csv_line(line)?;
        if fields.len() != 5 {
            return Err(format!(
                "{}:{}: expected five columns",
                path.display(),
                line_index + 2
            )
            .into());
        }
        if fields[4] != "bif" && fields[4] != "nif" {
            continue;
        }
        let arity: u8 = fields[2].parse()?;
        let calls: u64 = fields[3].parse()?;
        let call = Call {
            module: fields[0].clone(),
            function: fields[1].clone(),
            arity,
        };
        *entries.entry((call, fields[4].clone())).or_default() += calls;
    }

    Ok(entries
        .into_iter()
        .map(|((call, kind), calls)| Entry {
            implemented: is_implemented(&call, &kind),
            call,
            calls,
            kind,
        })
        .collect())
}

fn parse_csv_line(line: &str) -> Result<Vec<String>> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' if quoted && chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => fields.push(std::mem::take(&mut field)),
            _ => field.push(ch),
        }
    }
    if quoted {
        return Err("unterminated quoted CSV field".into());
    }
    fields.push(field);
    Ok(fields)
}

/// Interpreter instruction path, not a BIF table entry.
/// `Vm::intercept_fun_import` in `crates/vm/src/funs.rs`.
const OPCODE_BIFS: &[(&str, &str, u8)] = &[
    ("erlang", "apply", 2),
    ("erlang", "apply", 3),
    ("erlang", "make_fun", 3),
    ("erlang", "fun_info", 1),
    ("erlang", "fun_info", 2),
];

fn is_implemented(call: &Call, _kind: &str) -> bool {
    let module = call.module.as_str();
    let name = call.function.as_str();
    let arity = call.arity;
    static_nif(module, name, arity)
        || arinsal_bifs::lookup(module, name, arity).is_some()
        || arinsal_vm::implemented_natives().iter().any(
            |&(item_module, item_function, item_arity)| {
                item_module == module && item_function == name && item_arity == arity
            },
        )
        || OPCODE_BIFS
            .iter()
            .any(|&(item_module, item_function, item_arity)| {
                item_module == module && item_function == name && item_arity == arity
            })
}

/// Every `bif.tab` entry (not only the ones the scenarios call) that no Arinsal table implements.
fn bif_tab_missing(root: &Path) -> Result<()> {
    let Some(source) = std::env::var_os("ARINSAL_OTP_SRC").map(PathBuf::from) else {
        eprintln!("Skipping bif.tab lookup: set ARINSAL_OTP_SRC to the OTP source tree");
        return Ok(());
    };
    let text = std::fs::read_to_string(source.join("erts/emulator/beam/bif.tab"))?;
    let mut missing = Vec::new();
    for line in text.lines().map(str::trim) {
        let mut parts = line.split_whitespace();
        let (Some(kind), Some(mfa)) = (parts.next(), parts.next()) else {
            continue;
        };
        if !matches!(kind, "bif" | "ubif" | "hbif") {
            continue;
        }
        let Some((module, rest)) = mfa.split_once(':') else {
            continue;
        };
        let Some((name, arity)) = rest.rsplit_once('/') else {
            continue;
        };
        let Ok(arity) = arity.parse::<u8>() else {
            continue;
        };
        let call = Call {
            module: module.trim_matches('\'').to_string(),
            function: name.trim_matches('\'').to_string(),
            arity,
        };
        if !is_implemented(&call, kind) {
            missing.push(format!("{}:{}/{}", call.module, call.function, call.arity));
        }
    }
    missing.sort();
    missing.dedup();
    let out = root.join("docs/status/bif_tab_missing.md");
    let body = format!(
        "# bif.tab entries not implemented\n\nGenerated by `cargo run -p gap-report -- --bif-tab`.\n\n{} missing.\n\n{}\n",
        missing.len(),
        missing
            .iter()
            .map(|m| format!("- `{m}`"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    std::fs::write(&out, body)?;
    println!(
        "{} bif.tab entries missing; wrote docs/status/bif_tab_missing.md",
        missing.len()
    );
    Ok(())
}

fn static_nif(module: &str, name: &str, arity: u8) -> bool {
    arinsal_nif_file::lookup(module, name, arity).is_some()
        || arinsal_nif_tty::lookup(module, name, arity).is_some()
        || arinsal_nif_buffer::lookup(module, name, arity).is_some()
        || arinsal_nif_zlib::lookup(module, name, arity).is_some()
        || arinsal_nif_socket::lookup(module, name, arity).is_some()
        || arinsal_re::lookup(module, name, arity).is_some()
}

fn subsystem(call: &Call, kind: &str) -> &'static str {
    if kind == "nif" {
        return "NIF-resource";
    }
    let module = call.module.as_str();
    let name = call.function.as_str();
    if module == "ets" {
        "ETS"
    } else if module == "persistent_term" {
        "persistent_term"
    } else if module == "erts_literal_area_collector" || name.starts_with("dt_") || name == "trace"
    {
        "tracing"
    } else if matches!(
        name,
        "open_port"
            | "port_close"
            | "port_control"
            | "port_command"
            | "port_set_data"
            | "port_get_data"
    ) {
        "ports"
    } else if matches!(
        name,
        "nodes" | "monitor_node" | "dist_get_stat" | "setnode" | "is_alive"
    ) {
        "distribution"
    } else if matches!(
        name,
        "system_info" | "system_flag" | "scheduler_wall_time" | "time_unit"
    ) {
        "system_info"
    } else if matches!(
        name,
        "module_loaded"
            | "finish_loading"
            | "prepare_loading"
            | "function_exported"
            | "get_module_info"
            | "make_fun"
            | "pre_loaded"
            | "purge_module"
            | "delete_module"
            | "finish_after_on_load"
    ) {
        "code loading"
    } else if is_process_call(module, name) {
        "process"
    } else {
        "other"
    }
}

fn is_process_call(module: &str, name: &str) -> bool {
    matches!(
        (module, name),
        (
            "erlang",
            "spawn"
                | "spawn_link"
                | "spawn_monitor"
                | "spawn_opt"
                | "send"
                | "link"
                | "unlink"
                | "monitor"
                | "demonitor"
                | "register"
                | "unregister"
                | "whereis"
                | "process_info"
                | "processes"
                | "is_process_alive"
                | "process_flag"
                | "group_leader"
                | "put"
                | "get"
                | "erase"
                | "exit"
                | "send_after"
                | "start_timer"
                | "cancel_timer"
                | "make_ref"
                | "yield"
        ) | (
            "erts_internal",
            "group_leader"
                | "dirty_process_handle_signals"
                | "processes_next"
                | "request_system_task"
        )
    )
}

fn render(scenarios: &BTreeMap<&str, Vec<Entry>>, opcodes: &BTreeMap<String, usize>) -> String {
    let mut out = String::from(
        "# OTP, Elixir, IEx, and Mix implementation gaps\n\nGenerated by `cargo run -p gap-report`. Counts are observed calls from the census runs; this report measures distinct called BIF/NIF entries.\n\n",
    );
    out.push_str("## Summary\n\n| Scenario | Implemented | Total distinct BIFs + NIFs | Coverage |\n|---|---:|---:|---:|\n");
    for scenario in SCENARIOS {
        let entries = &scenarios[scenario];
        let total = entries.len();
        let implemented = entries.iter().filter(|entry| entry.implemented).count();
        let percent = if total == 0 {
            0.0
        } else {
            implemented as f64 * 100.0 / total as f64
        };
        let _ = writeln!(
            out,
            "| {scenario} | {implemented} | {total} | {percent:.1}% |"
        );
    }
    out.push_str("\n## Missing BIFs and NIFs\n\nCalls are ordered by descending observed call count within each owning subsystem, then module. `internal` wrapper rows in the source CSV are excluded. An entry counts as implemented when `arinsal_bifs::lookup`, `arinsal_vm::implemented_natives`, a static NIF lookup, or an opcode-level BIF covers it. See `docs/status/missing.md` for the same holes grouped by module with the erts C function.\n");
    for scenario in SCENARIOS {
        let missing: Vec<_> = scenarios[scenario]
            .iter()
            .filter(|entry| !entry.implemented)
            .collect();
        let missing_calls: u64 = missing.iter().map(|entry| entry.calls).sum();
        let _ = write!(
            out,
            "\n### {scenario}: {} missing distinct entries, {missing_calls} observed calls\n",
            missing.len()
        );
        if missing.is_empty() {
            out.push_str("\nNone.\n");
            continue;
        }
        let mut groups = BTreeMap::<(&str, &str), Vec<&Entry>>::new();
        for entry in missing {
            groups
                .entry((
                    subsystem(&entry.call, &entry.kind),
                    entry.call.module.as_str(),
                ))
                .or_default()
                .push(entry);
        }
        let mut ordered: Vec<_> = groups.into_iter().collect();
        ordered.sort_by(|((sub_a, mod_a), rows_a), ((sub_b, mod_b), rows_b)| {
            let count_a: u64 = rows_a.iter().map(|row| row.calls).sum();
            let count_b: u64 = rows_b.iter().map(|row| row.calls).sum();
            count_b
                .cmp(&count_a)
                .then_with(|| sub_a.cmp(sub_b))
                .then_with(|| mod_a.cmp(mod_b))
        });
        for ((owner, module), mut rows) in ordered {
            rows.sort_by(|a, b| b.calls.cmp(&a.calls).then_with(|| a.call.cmp(&b.call)));
            let _ = writeln!(out, "\n#### {owner} — `{module}`");
            for row in rows {
                let _ = writeln!(
                    out,
                    "- `{}:{}/{}` — {} calls",
                    module, row.call.function, row.call.arity, row.calls
                );
            }
        }
    }
    out.push_str("\n## Unsupported opcodes\n\nAggregated from `cargo test -p arinsal-loader --test corpus -- --nocapture`:\n\n");
    if opcodes.is_empty() {
        out.push_str("No unsupported opcodes reported.\n");
    } else {
        out.push_str("| Opcode | Count |\n|---|---:|\n");
        let mut rows: Vec<_> = opcodes.iter().collect();
        rows.sort_by(|(name_a, count_a), (name_b, count_b)| {
            count_b.cmp(count_a).then_with(|| name_a.cmp(name_b))
        });
        for (name, count) in rows {
            let _ = writeln!(out, "| `{name}` | {count} |");
        }
    }
    out
}

fn unsupported_opcodes(root: &Path) -> Result<BTreeMap<String, usize>> {
    let output = Command::new("cargo")
        .args([
            "test",
            "-p",
            "arinsal-loader",
            "--test",
            "corpus",
            "--",
            "--nocapture",
        ])
        .current_dir(root)
        .output()?;
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !output.status.success() {
        return Err(format!("corpus test failed:\n{combined}").into());
    }
    let marker = "unsupported ";
    let start = combined
        .rfind(marker)
        .ok_or("corpus output did not include unsupported opcode counts")?
        + marker.len();
    let rest = &combined[start..];
    let end = rest
        .find('}')
        .ok_or("unterminated unsupported opcode map")?;
    let body = rest[..end]
        .trim()
        .strip_prefix('{')
        .unwrap_or(rest[..end].trim());
    let mut counts = BTreeMap::new();
    if body.trim().is_empty() {
        return Ok(counts);
    }
    for item in body.split(',') {
        let (name, value) = item
            .split_once(':')
            .ok_or("invalid unsupported opcode entry")?;
        counts.insert(
            name.trim().trim_matches('"').to_owned(),
            value.trim().parse()?,
        );
    }
    Ok(counts)
}

struct CLoc {
    /// Path relative to `erts/emulator`.
    path: String,
    line: usize,
    symbol: String,
}

struct ErtsIndex {
    /// C function name → definition.
    functions: HashMap<String, CLoc>,
    /// `(erlang name, arity, file text index)` NIF table rows: name, arity, C symbol, path.
    nifs: Vec<(String, u8, String, String)>,
    available: bool,
}

fn erts_root() -> Option<PathBuf> {
    std::env::var_os("ARINSAL_OTP_SRC")
        .map(PathBuf::from)
        .map(|root| root.join("erts/emulator"))
}

fn erts_index() -> ErtsIndex {
    let Some(root) = erts_root().filter(|root| root.is_dir()) else {
        eprintln!("Skipping erts source lookup: set ARINSAL_OTP_SRC to the OTP source tree");
        return ErtsIndex {
            functions: HashMap::new(),
            nifs: Vec::new(),
            available: false,
        };
    };
    let beam = root.join("beam");
    let nifs = root.join("nifs");
    let mut files = Vec::new();
    collect_c_files(&beam, &mut files);
    collect_c_files(&nifs, &mut files);
    let mut functions = HashMap::new();
    let mut nif_rows = Vec::new();
    for path in files {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let relative = path
            .strip_prefix(&root)
            .unwrap_or(path.as_path())
            .display()
            .to_string();
        for (symbol, line) in c_definitions(&text) {
            functions.entry(symbol.clone()).or_insert(CLoc {
                path: relative.clone(),
                line,
                symbol,
            });
        }
        for (name, arity, symbol) in nif_table_rows(&text) {
            nif_rows.push((name, arity, symbol, relative.clone()));
        }
    }
    ErtsIndex {
        available: beam.is_dir(),
        functions,
        nifs: nif_rows,
    }
}

fn collect_c_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<_> = entries.flatten().map(|entry| entry.path()).collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            collect_c_files(&path, out);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("c") {
            out.push(path);
        }
    }
}

fn c_definitions(text: &str) -> Vec<(String, usize)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut found = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if let Some(name) = definition_name(line) {
            found.push((name, index + 1));
            continue;
        }
        let trimmed = line.trim();
        if matches!(
            trimmed,
            "BIF_RETTYPE" | "static BIF_RETTYPE" | "ERL_NIF_TERM" | "static ERL_NIF_TERM"
        ) && let Some(next) = lines.get(index + 1)
            && let Some(name) = ident_before_paren(next.trim())
        {
            found.push((name, index + 2));
        }
    }
    found
}

fn definition_name(line: &str) -> Option<String> {
    let mut rest = line.trim();
    let mut stripped = false;
    loop {
        let next = [
            "static ",
            "ERTS_GLB_INLINE ",
            "BIF_RETTYPE ",
            "ERL_NIF_TERM ",
            "Eterm ",
        ]
        .iter()
        .find_map(|prefix| rest.strip_prefix(prefix));
        match next {
            Some(tail) => {
                stripped = true;
                rest = tail.trim_start();
            }
            None => break,
        }
    }
    if !stripped {
        return None;
    }
    ident_before_paren(rest)
}

fn ident_before_paren(rest: &str) -> Option<String> {
    let rest = rest.trim_start();
    let end = rest
        .find(|ch: char| !(ch == '_' || ch.is_ascii_alphanumeric()))
        .unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    let name = &rest[..end];
    rest[end..]
        .trim_start()
        .starts_with('(')
        .then(|| name.to_string())
}

fn nif_table_rows(text: &str) -> Vec<(String, u8, String)> {
    let mut rows = Vec::new();
    for line in text.lines() {
        let Some(start) = line.find("{\"") else {
            continue;
        };
        let rest = &line[start + 2..];
        let Some(quote) = rest.find('"') else {
            continue;
        };
        let name = &rest[..quote];
        let after = rest[quote + 1..].trim_start();
        let Some(after) = after.strip_prefix(',') else {
            continue;
        };
        let after = after.trim_start();
        let Some(comma) = after.find(',') else {
            continue;
        };
        let Ok(arity) = after[..comma].trim().parse::<u8>() else {
            continue;
        };
        let func = after[comma + 1..].trim_start();
        let func_end = func
            .find(|ch: char| !(ch == '_' || ch.is_ascii_alphanumeric()))
            .unwrap_or(func.len());
        if func_end == 0 {
            continue;
        }
        rows.push((name.to_string(), arity, func[..func_end].to_string()));
    }
    rows
}

// Port of erts/emulator/utils/make_tables:103-107 (default BIF C name), OTP-29.1.1.
fn default_c_name(module: &str, name: &str, arity: u8) -> String {
    if module == "erlang" {
        format!("{name}_{arity}")
    } else {
        format!("{module}_{name}_{arity}")
    }
}

fn bif_alias(module: &str, name: &str, arity: u8) -> Option<String> {
    let tab = erts_root()?.join("beam/bif.tab");
    let text = std::fs::read_to_string(tab).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let kind = parts.next()?;
        if kind != "bif" && kind != "ubif" && kind != "hbif" {
            continue;
        }
        let mfa = parts.next()?;
        let (decl_module, rest) = mfa.split_once(':')?;
        let (decl_name, decl_arity) = rest.rsplit_once('/')?;
        let decl_name = decl_name.trim_matches('\'');
        let Ok(decl_arity) = decl_arity.parse::<u8>() else {
            continue;
        };
        if decl_module == module && decl_name == name && decl_arity == arity {
            return parts
                .next()
                .map(str::to_string)
                .or_else(|| Some(default_c_name(module, name, arity)));
        }
    }
    None
}

fn c_function(index: &ErtsIndex, module: &str, name: &str, arity: u8) -> String {
    if !index.available {
        return "erts sources not found".to_string();
    }
    let symbol =
        bif_alias(module, name, arity).unwrap_or_else(|| default_c_name(module, name, arity));
    if let Some(loc) = index.functions.get(&symbol) {
        return format!("`{}:{}` `{}`", loc.path, loc.line, loc.symbol);
    }
    let nif = index.nifs.iter().find(|(nif_name, nif_arity, _, path)| {
        *nif_name == name && *nif_arity == arity && path.contains(module)
    });
    let nif = nif.or_else(|| {
        index
            .nifs
            .iter()
            .find(|(nif_name, nif_arity, _, _)| *nif_name == name && *nif_arity == arity)
    });
    if let Some((_, _, nif_symbol, path)) = nif {
        if let Some(loc) = index.functions.get(nif_symbol) {
            return format!("`{}:{}` `{}`", loc.path, loc.line, loc.symbol);
        }
        return format!("`{path}` `{nif_symbol}`");
    }
    format!("`{symbol}` (definition not found under `erts/emulator`)")
}

struct MissingRow {
    call: Call,
    calls: u64,
    kind: String,
}

fn render_missing(scenarios: &BTreeMap<&str, Vec<Entry>>, erts: &ErtsIndex) -> String {
    let mut best: BTreeMap<(String, String, u8, String), u64> = BTreeMap::new();
    for entries in scenarios.values() {
        for entry in entries.iter().filter(|entry| !entry.implemented) {
            let key = (
                entry.call.module.clone(),
                entry.call.function.clone(),
                entry.call.arity,
                entry.kind.clone(),
            );
            let count = best.entry(key).or_default();
            *count = (*count).max(entry.calls);
        }
    }
    let mut rows: Vec<MissingRow> = best
        .into_iter()
        .map(|((module, function, arity, kind), calls)| MissingRow {
            call: Call {
                module,
                function,
                arity,
            },
            calls,
            kind,
        })
        .collect();
    let mut out = String::from(
        "# Missing BIFs and NIFs\n\nGenerated by `cargo run -p gap-report`. These census entries are not covered by `arinsal_bifs::lookup`, `arinsal_vm::implemented_natives`, static NIF lookups (`prim_file`, `prim_buffer`, `prim_tty`, `prim_socket`, `prim_net`, `zlib`, `re`), or the opcode-level BIFs `erlang:apply/2`, `erlang:apply/3`, `erlang:make_fun/3`, and `erlang:fun_info/1`, `erlang:fun_info/2`. Call counts are the maximum observed in any one of bench, boot, hello, elixir, iex, and mix. C functions follow explicit `bif.tab` aliases or the `make_tables` default `{module_}{name}_{arity}`, then the `BIF_RETTYPE` / `ERL_NIF_TERM` definition under `erts/emulator`.\n\n",
    );
    let _ = writeln!(out, "{} missing distinct entries.\n", rows.len());
    let mut groups: BTreeMap<String, Vec<MissingRow>> = BTreeMap::new();
    for row in rows.drain(..) {
        groups.entry(row.call.module.clone()).or_default().push(row);
    }
    let mut ordered: Vec<_> = groups.into_iter().collect();
    ordered.sort_by(|(_, left), (_, right)| {
        let left_calls: u64 = left.iter().map(|row| row.calls).sum();
        let right_calls: u64 = right.iter().map(|row| row.calls).sum();
        right_calls
            .cmp(&left_calls)
            .then_with(|| left[0].call.module.cmp(&right[0].call.module))
    });
    for (module, mut group) in ordered {
        group.sort_by(|left, right| {
            right
                .calls
                .cmp(&left.calls)
                .then_with(|| left.call.function.cmp(&right.call.function))
                .then_with(|| left.call.arity.cmp(&right.call.arity))
                .then_with(|| left.kind.cmp(&right.kind))
        });
        let total: u64 = group.iter().map(|row| row.calls).sum();
        let _ = writeln!(out, "## `{module}`\n\n{total} observed calls.\n");
        for row in group {
            let c_fn = c_function(erts, &row.call.module, &row.call.function, row.call.arity);
            let _ = writeln!(
                out,
                "- `{}:{}/{}` ({}) — {} calls — {c_fn}",
                row.call.module, row.call.function, row.call.arity, row.kind, row.calls
            );
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_reader_handles_quoted_fields_and_escaped_quotes() {
        assert_eq!(
            parse_csv_line("module,\"function,name\",2,4,bif").unwrap(),
            ["module", "function,name", "2", "4", "bif"]
        );
        assert_eq!(
            parse_csv_line("module,\"say \"\"hello\"\"\",1,1,nif").unwrap()[1],
            "say \"hello\""
        );
    }

    #[test]
    fn process_operations_have_a_distinct_owner() {
        let send = Call {
            module: "erlang".into(),
            function: "send".into(),
            arity: 2,
        };
        assert_eq!(subsystem(&send, "bif"), "process");
        assert!(is_implemented(&send, "bif"));
    }

    #[test]
    fn default_bif_c_name_follows_make_tables() {
        assert_eq!(default_c_name("erlang", "spawn", 3), "spawn_3");
        assert_eq!(
            default_c_name("erts_internal", "garbage_collect", 1),
            "erts_internal_garbage_collect_1"
        );
    }
}
