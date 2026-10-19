//! Logical processor counts and cgroup CPU quota.
//!
//! Port of erts/lib_src/common/erl_misc_utils.c (erts_cpu_info_update, read_cpu_quota,
//! get_cgroup_path), OTP-29.1.1. `std::thread::available_parallelism` is not used because it
//! folds the quota into the affinity count, while erts keeps the four numbers apart.

use std::sync::OnceLock;

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
// Port of erts/emulator/sys/common/erl_poll.c (erts_poll_init, max_fds), OTP-29.1.1.
#[allow(unsafe_code)]
pub fn poll_max_fds() -> usize {
    // SAFETY: sysconf only reads a system limit.
    let max = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    match usize::try_from(max) {
        Ok(max) => max,
        // macOS 11+ can report "unlimited"; erts then assumes the kernel's per-process cap.
        Err(_) => 24_576,
    }
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

#[allow(unsafe_code)]
fn read_cpu_info() -> CpuInfo {
    // SAFETY: sysconf only reads a system limit.
    let (configured, online) = unsafe {
        (
            libc::sysconf(libc::_SC_NPROCESSORS_CONF),
            libc::sysconf(libc::_SC_NPROCESSORS_ONLN),
        )
    };
    let configured = usize::try_from(configured).unwrap_or(0);
    let online = usize::try_from(online).unwrap_or(0).min(configured);
    let mut available = affinity_count();
    if available > online {
        available = online;
    } else if available == 0 {
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

/// Processors in the affinity mask of this process; 0 where the platform has none (macOS).
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn affinity_count() -> usize {
    // SAFETY: cpu_set_t is plain bytes, so all-zero is valid; sched_getaffinity fills it
    // for the size passed.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        if libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) != 0 {
            return 0;
        }
        usize::try_from(libc::CPU_COUNT(&set)).unwrap_or(0)
    }
}

#[cfg(not(target_os = "linux"))]
fn affinity_count() -> usize {
    0
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
            CgroupVersion::V1 if tail[0] == "cgroup" => {
                if tail[2].split(',').any(|c| c == controller) {
                    let dir = if root == child {
                        mount.to_owned()
                    } else {
                        format!("{mount}{child}")
                    };
                    return Some((version, dir));
                }
            }
            _ => {}
        }
    }
    None
}
