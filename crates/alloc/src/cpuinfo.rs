//! Logical processor counts and cgroup CPU quota.
//!
//! Port of erts/lib_src/common/erl_misc_utils.c (erts_cpu_info_update, read_cpu_quota,
//! get_cgroup_path), OTP-29.1.1. `std::thread::available_parallelism` is not used because it
//! folds the quota into the affinity count, while erts keeps the four numbers apart.

use std::sync::OnceLock;

/// One row from `erts_cpu_topology_t`, in the order used by ERTS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuTopologyEntry {
    /// NUMA node id, or -1 when the operating system does not expose one.
    pub node: i32,
    /// Processor package id.
    pub processor: i32,
    /// NUMA node local to a package, or -1 when it is not needed.
    pub processor_node: i32,
    /// Core id within the package.
    pub core: i32,
    /// Hardware thread id within the core.
    pub thread: i32,
    /// Logical processor id used by the OS affinity API.
    pub logical: i32,
}

/// Detected hardware topology, sorted like `erts_get_cpu_topology` returns it.
// Port of erts/lib_src/common/erl_misc_utils.c (erts_get_cpu_topology), OTP-29.1.1.
pub fn cpu_topology() -> &'static [CpuTopologyEntry] {
    static TOPOLOGY: OnceLock<Vec<CpuTopologyEntry>> = OnceLock::new();
    TOPOLOGY.get_or_init(read_cpu_topology)
}

// Port of erts/lib_src/common/erl_misc_utils.c (erts_cpu_info_update), OTP-29.1.1.
fn read_cpu_topology() -> Vec<CpuTopologyEntry> {
    #[cfg(target_os = "linux")]
    {
        read_linux_cpu_topology()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

// Port of erts/lib_src/common/erl_misc_utils.c (read_topology), OTP-29.1.1.
#[cfg(target_os = "linux")]
fn read_linux_cpu_topology() -> Vec<CpuTopologyEntry> {
    let info = cpu_info();
    if info.configured == 0 {
        return Vec::new();
    }
    let node_root = std::fs::canonicalize("/sys/devices/system/node").ok();
    let node_dirs = node_root.as_ref().and_then(|root| {
        let mut dirs = std::fs::read_dir(root)
            .ok()?
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let name = entry.file_name().into_string().ok()?;
                Some((
                    name.strip_prefix("node")?.parse::<i32>().ok()?,
                    entry.path(),
                ))
            })
            .collect::<Vec<_>>();
        dirs.sort_by_key(|(id, _)| *id);
        Some(dirs)
    });
    let nodes_available = node_dirs.as_ref().is_some_and(|dirs| !dirs.is_empty());
    let sources = if nodes_available {
        node_dirs.unwrap_or_default()
    } else {
        vec![(-1, std::path::PathBuf::from("/sys/devices/system/cpu"))]
    };
    let mut entries = Vec::new();
    for (node, source) in sources {
        let Ok(cpus) = std::fs::read_dir(source) else {
            return Vec::new();
        };
        for entry in cpus.filter_map(Result::ok) {
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            let Some(logical) = name
                .strip_prefix("cpu")
                .filter(|number| !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|number| number.parse::<i32>().ok())
            else {
                continue;
            };
            let topology = entry.path().join("topology");
            let Some(processor) = read_i32(topology.join("physical_package_id")) else {
                continue;
            };
            let Some(core) = read_i32(topology.join("core_id")) else {
                continue;
            };
            entries.push(CpuTopologyEntry {
                node,
                processor,
                processor_node: -1,
                core,
                thread: 0,
                logical,
            });
            if entries.len() > info.configured {
                return Vec::new();
            }
        }
    }
    if entries.len() < info.online || entries.is_empty() {
        return Vec::new();
    }

    // Port of adjust_processor_nodes: move NUMA ids into processor_node when a package
    // spans multiple NUMA nodes.
    if nodes_available {
        let mut package_nodes =
            std::collections::BTreeMap::<i32, std::collections::BTreeSet<i32>>::new();
        for entry in &entries {
            package_nodes
                .entry(entry.processor)
                .or_default()
                .insert(entry.node);
        }
        for entry in &mut entries {
            if package_nodes[&entry.processor].len() > 1 {
                entry.processor_node = entry.node;
                entry.node = -1;
            }
        }
    }
    entries.sort_by_key(topology_cpu_key);
    let mut prior: Option<CpuTopologyEntry> = None;
    let mut thread = 0;
    for entry in &mut entries {
        let same_core = prior.is_some_and(|last| {
            (last.node, last.processor, last.processor_node, last.core)
                == (
                    entry.node,
                    entry.processor,
                    entry.processor_node,
                    entry.core,
                )
        });
        thread = if same_core { thread + 1 } else { 0 };
        entry.thread = thread;
        prior = Some(*entry);
    }
    entries
}

#[cfg(target_os = "linux")]
fn read_i32(path: std::path::PathBuf) -> Option<i32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// `cpu_cmp` in `erl_misc_utils.c`.
pub fn topology_cpu_key(entry: &CpuTopologyEntry) -> (i32, i32, i32, i32, i32, i32) {
    (
        entry.node,
        entry.processor,
        entry.processor_node,
        entry.core,
        entry.thread,
        entry.logical,
    )
}

/// Sort topology records using OTP's scheduler bind order.
// Port of erts/emulator/beam/erl_cpu_topology.c (cpu_bind_order_sort,
// make_cpudata_id_seq), OTP-29.1.1.
pub fn cpu_bind_ordered_topology(order: &str) -> Option<Vec<CpuTopologyEntry>> {
    cpu_bind_ordered_entries(cpu_topology(), order)
}

/// Sort a defined topology using OTP's scheduler bind order.
// Port of erts/emulator/beam/erl_cpu_topology.c (cpu_bind_order_sort,
// make_cpudata_id_seq), OTP-29.1.1.
pub fn cpu_bind_ordered_entries(
    topology: &[CpuTopologyEntry],
    order: &str,
) -> Option<Vec<CpuTopologyEntry>> {
    let mut entries = topology.to_vec();
    let no_node = matches!(
        order,
        "default_bind"
            | "thread_no_node_processor_spread"
            | "no_node_processor_spread"
            | "no_node_thread_spread"
    );
    if !matches!(
        order,
        "default_bind"
            | "spread"
            | "processor_spread"
            | "thread_spread"
            | "thread_no_node_processor_spread"
            | "no_node_processor_spread"
            | "no_node_thread_spread"
            | "no_spread"
    ) {
        return None;
    }
    if entries.len() > 1 {
        make_topology_id_seq(&mut entries, no_node);
        entries.sort_by_key(|entry| match order {
            "spread" => (
                entry.thread,
                entry.core,
                entry.processor_node,
                entry.processor,
                entry.node,
                0,
            ),
            "processor_spread" => (
                entry.thread,
                entry.processor_node,
                entry.core,
                entry.node,
                entry.processor,
                0,
            ),
            "thread_spread" => (
                entry.thread,
                entry.node,
                entry.processor,
                entry.processor_node,
                entry.core,
                0,
            ),
            "default_bind" | "thread_no_node_processor_spread" => {
                (entry.thread, entry.node, entry.core, entry.processor, 0, 0)
            }
            "no_node_processor_spread" => {
                (entry.node, entry.thread, entry.core, entry.processor, 0, 0)
            }
            "no_node_thread_spread" => {
                (entry.node, entry.thread, entry.processor, entry.core, 0, 0)
            }
            _ => (
                entry.node,
                entry.processor,
                entry.processor_node,
                entry.core,
                entry.thread,
                0,
            ),
        });
    }
    Some(entries)
}

// Port of erts/emulator/beam/erl_cpu_topology.c (make_cpudata_id_seq), OTP-29.1.1.
fn make_topology_id_seq(entries: &mut [CpuTopologyEntry], no_node: bool) {
    let mut node = -1;
    let mut processor = -1;
    let mut processor_node = -1;
    let mut processor_node_node = -1;
    let mut core = -1;
    let mut thread = -1;
    let mut old_node = -1;
    let mut old_processor = -1;
    let mut old_processor_node = -1;
    let mut old_core = -1;
    let mut old_thread = -1;
    for entry in entries {
        if !no_node || entry.node >= 0 {
            if old_node == entry.node {
                entry.node = node;
            } else {
                old_node = entry.node;
                old_processor = -1;
                processor = -1;
                if !no_node {
                    old_processor_node = -1;
                    processor_node = -1;
                }
                old_core = -1;
                core = -1;
                old_thread = -1;
                thread = -1;
                if no_node || entry.node >= 0 {
                    node += 1;
                    entry.node = node;
                }
            }
        }
        if old_processor == entry.processor {
            entry.processor = processor;
        } else {
            old_processor = entry.processor;
            processor = processor.saturating_add(1);
            if !no_node {
                processor_node_node = -1;
                old_processor_node = -1;
                processor_node = -1;
            }
            old_core = -1;
            core = -1;
            old_thread = -1;
            thread = -1;
            entry.processor = processor;
        }
        if no_node && entry.processor_node < 0 {
            old_processor_node = -1;
        } else if old_processor_node == entry.processor_node {
            if no_node {
                entry.node = node;
                entry.processor_node = node;
            } else {
                if processor_node_node >= 0 {
                    entry.node = processor_node_node;
                }
                entry.processor_node = processor_node;
            }
        } else {
            old_processor_node = entry.processor_node;
            old_core = -1;
            core = -1;
            old_thread = -1;
            thread = -1;
            if no_node {
                node += 1;
                entry.node = node;
                entry.processor_node = node;
            } else {
                node += 1;
                processor_node += 1;
                processor_node_node = node;
                entry.node = node;
                entry.processor_node = processor_node;
            }
        }
        if !no_node && entry.processor_node < 0 {
            entry.processor_node = 0;
        }
        if old_core == entry.core {
            entry.core = core;
        } else {
            old_core = entry.core;
            old_thread = -1;
            thread = -1;
            core += 1;
            entry.core = core;
        }
        if old_thread == entry.thread {
            entry.thread = thread;
        } else {
            old_thread = entry.thread;
            thread += 1;
            entry.thread = thread;
        }
    }
}

/// Processor counts as erts reports them through `erts_get_logical_processors`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuInfo {
    /// Configured logical processors (`_SC_NPROCESSORS_CONF`); 0 when unknown.
    pub configured: usize,
    /// Online logical processors (`_SC_NPROCESSORS_ONLN`, capped by `configured`).
    pub online: usize,
    /// Processors in the process affinity mask, capped by `online`.
    pub available: usize,
    /// CPU quota of the cgroup, in whole processors (never above `online`); 0 when unknown.
    pub quota: usize,
}

/// The processor counts, read once at first use like `erts_pre_early_init_cpu_topology`.
pub fn cpu_info() -> CpuInfo {
    static INFO: OnceLock<CpuInfo> = OnceLock::new();
    *INFO.get_or_init(read_cpu_info)
}

/// Highest file descriptor count the poller supports.
// Port of erts/emulator/sys/common/erl_poll.c (erts_poll_init, max_fds), OTP-29.1.1:
// `sysconf(_SC_OPEN_MAX)` is the soft `RLIMIT_NOFILE`.
pub fn poll_max_fds() -> usize {
    use rustix::process::{Resource, getrlimit};
    // macOS 11+ can report "unlimited"; erts then assumes the kernel's per-process cap.
    getrlimit(Resource::Nofile)
        .current
        .and_then(|limit| usize::try_from(limit).ok())
        .unwrap_or(24_576)
}

/// Default `(schedulers, schedulers_online)` before any `+S` flag.
// Port of erts/emulator/beam/erl_init.c (erl_start: no_schedulers, no_schedulers_online),
// OTP-29.1.1.
pub fn default_schedulers() -> (usize, usize) {
    let info = cpu_info();
    let total = info.configured.max(1);
    let online = if info.available > 0 {
        if info.quota > 0 {
            info.quota.min(info.available)
        } else {
            info.available
        }
    } else if info.online > 0 {
        info.online
    } else {
        total
    };
    (total, online)
}

fn read_cpu_info() -> CpuInfo {
    let (configured, online) = configured_and_online();
    let mut available = affinity_count();
    // Capped by the online count; zero ("shouldn't happen") also falls back to it.
    if available > online || available == 0 {
        available = online;
    }
    let quota = read_cpu_quota(online);
    CpuInfo {
        configured,
        online,
        available,
        quota,
    }
}

/// `(_SC_NPROCESSORS_CONF, _SC_NPROCESSORS_ONLN)`; glibc reads the same sysfs data.
#[cfg(target_os = "linux")]
fn configured_and_online() -> (usize, usize) {
    let configured = std::fs::read_dir("/sys/devices/system/cpu")
        .map(|dir| {
            dir.filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .and_then(|name| name.strip_prefix("cpu"))
                        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
                })
                .count()
        })
        .unwrap_or(0);
    let fallback = std::thread::available_parallelism().map_or(1, usize::from);
    let configured = if configured == 0 {
        fallback
    } else {
        configured
    };
    let online = std::fs::read_to_string("/sys/devices/system/cpu/online")
        .ok()
        .and_then(|text| count_cpu_list(text.trim()))
        .unwrap_or(configured);
    (configured, online.min(configured))
}

/// Number of CPUs in a sysfs list such as `0-3,5,7-8`.
#[cfg(target_os = "linux")]
fn count_cpu_list(list: &str) -> Option<usize> {
    let mut count = 0;
    for part in list.split(',').filter(|part| !part.is_empty()) {
        count += match part.split_once('-') {
            Some((from, to)) => to.parse::<usize>().ok()? + 1 - from.parse::<usize>().ok()?,
            None => {
                part.parse::<usize>().ok()?;
                1
            }
        };
    }
    (count > 0).then_some(count)
}

/// Port of erts/lib_src/common/erl_misc_utils.c (erts_cpu_info_update): sysctl HW_NCPU
/// and HW_AVAILCPU are the configured and online counts on macOS.
#[cfg(target_os = "macos")]
fn configured_and_online() -> (usize, usize) {
    fn sysctl(name: &str) -> Option<usize> {
        use sysctl::Sysctl;

        if !matches!(name, "hw.ncpu" | "hw.availcpu") {
            return None;
        }
        sysctl::Ctl::Name(name.to_owned(), sysctl::CtlType::Int, "I".to_owned())
            .value()
            .ok()?
            .as_int()
            .and_then(|value| usize::try_from(*value).ok())
    }
    let configured = sysctl("hw.ncpu").unwrap_or(0);
    let online = sysctl("hw.availcpu").unwrap_or(configured);
    (configured, online.min(configured))
}

/// Fallback for operating systems without an ERTS CPU count implementation.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn configured_and_online() -> (usize, usize) {
    let count = std::thread::available_parallelism().map_or(1, usize::from);
    (count, count)
}

/// Processors in the affinity mask of this process; 0 where the platform has none (macOS).
#[cfg(target_os = "linux")]
fn affinity_count() -> usize {
    available_cpu_ids().len()
}

#[cfg(not(target_os = "linux"))]
fn affinity_count() -> usize {
    0
}

/// CPU ids in the process affinity mask captured during CPU info initialization.
#[cfg(target_os = "linux")]
pub fn available_cpu_ids() -> &'static [usize] {
    static IDS: OnceLock<Vec<usize>> = OnceLock::new();
    IDS.get_or_init(|| {
        rustix::thread::sched_getaffinity(None)
            .map(|set| {
                (0..rustix::thread::CpuSet::MAX_CPU)
                    .filter(|cpu| set.is_set(*cpu))
                    .collect()
            })
            .unwrap_or_default()
    })
}

/// CPU ids are unavailable on platforms without a process affinity mask.
#[cfg(not(target_os = "linux"))]
pub fn available_cpu_ids() -> &'static [usize] {
    &[]
}

#[cfg(not(target_os = "linux"))]
fn read_cpu_quota(_limit: usize) -> usize {
    0
}

#[cfg(target_os = "linux")]
fn read_cpu_quota(limit: usize) -> usize {
    use std::fs;
    let read = |path: &str| fs::read_to_string(path).unwrap_or_default();
    let (version, group) = match cgroup_path("cpu", &read) {
        Some(found) => found,
        None => return 0,
    };
    match version {
        CgroupVersion::V1 => {
            let field = |name: &str| {
                read(&format!("{group}/{name}"))
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse::<i64>().ok())
            };
            match (field("cpu.cfs_quota_us"), field("cpu.cfs_period_us")) {
                (Some(quota), Some(period)) => calculate_cpu_quota(limit, quota, period),
                _ => 0,
            }
        }
        CgroupVersion::V2 => {
            let text = read(&format!("{group}/cpu.max"));
            let mut words = text.split_whitespace();
            match (words.next(), words.next()) {
                // "max <period>": no quota, the upper limit applies.
                (Some("max"), Some(period)) if period.parse::<i64>().is_ok() => limit,
                (Some(quota), Some(period)) => {
                    match (quota.parse::<i64>(), period.parse::<i64>()) {
                        (Ok(quota), Ok(period)) => calculate_cpu_quota(limit, quota, period),
                        _ => 0,
                    }
                }
                _ => 0,
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn calculate_cpu_quota(limit: usize, quota_us: i64, period_us: i64) -> usize {
    if period_us > 0 && quota_us > 0 {
        let quota = usize::try_from(quota_us / period_us).unwrap_or(0).max(1);
        if quota <= limit {
            return quota;
        }
    }
    limit
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum CgroupVersion {
    V1,
    V2,
}

/// Directory of the cgroup holding `controller` for this process.
// Port of erl_misc_utils.c (get_cgroup_child_path, get_cgroup_path).
#[cfg(target_os = "linux")]
fn cgroup_path(controller: &str, read: &dyn Fn(&str) -> String) -> Option<(CgroupVersion, String)> {
    let mount_info = read("/proc/self/mountinfo");
    if mount_info.is_empty() {
        return None;
    }
    // /proc/self/cgroup lines: "id:controllers:path"; an empty controller list is the v2 tree.
    let mut version = None;
    let mut child = String::new();
    for line in read("/proc/self/cgroup").lines() {
        let mut parts = line.splitn(3, ':');
        let (_, Some(controllers), Some(path)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        if controllers.is_empty() {
            version = Some(CgroupVersion::V2);
            child = path.to_owned();
        } else if controllers.split(',').any(|c| c == controller) {
            version = Some(CgroupVersion::V1);
            child = path.to_owned();
            break;
        }
    }
    let version = version?;
    for line in mount_info.lines() {
        // [id] [parent] [maj:min] [root] [mount point] [opts...] - [fstype] [source] [flags]
        let Some((head, tail)) = line.split_once(" - ") else {
            continue;
        };
        let fields: Vec<&str> = head.split_whitespace().collect();
        let tail: Vec<&str> = tail.split_whitespace().collect();
        if fields.len() < 5 || tail.len() < 3 {
            continue;
        }
        let (root, mount) = (fields[3], fields[4]);
        match version {
            CgroupVersion::V2 if tail[0] == "cgroup2" => {
                let dir = format!("{mount}{child}");
                let controllers = read(&format!("{dir}/cgroup.controllers"));
                if controllers.split_whitespace().any(|c| c == controller) {
                    return Some((version, dir));
                }
            }
            CgroupVersion::V1
                if tail[0] == "cgroup" && tail[2].split(',').any(|c| c == controller) =>
            {
                let dir = if root == child {
                    mount.to_owned()
                } else {
                    format!("{mount}{child}")
                };
                return Some((version, dir));
            }
            _ => {}
        }
    }
    None
}
