// Port of erts/emulator/beam/erl_process.c (erts_sched_stat, erts_sched_stat_modify,
// erts_sched_stat_term), OTP-29.1.1.
mod raw;

use std::sync::atomic::{AtomicBool, Ordering};

const PRIORITY_COUNT: usize = 5;
const PORT_PRIORITY: usize = PRIORITY_COUNT - 1;

#[derive(Default)]
struct PriorityStat {
    total_executed: u64,
    executed: u64,
    total_migrated: u64,
    migrated: u64,
}

struct SchedStat {
    enabled: AtomicBool,
    lock: raw::LockedValue<[PriorityStat; PRIORITY_COUNT]>,
}

static SCHED_STAT: SchedStat = SchedStat {
    enabled: AtomicBool::new(false),
    lock: raw::LockedValue::new([
        PriorityStat {
            total_executed: 0,
            executed: 0,
            total_migrated: 0,
            migrated: 0,
        },
        PriorityStat {
            total_executed: 0,
            executed: 0,
            total_migrated: 0,
            migrated: 0,
        },
        PriorityStat {
            total_executed: 0,
            executed: 0,
            total_migrated: 0,
            migrated: 0,
        },
        PriorityStat {
            total_executed: 0,
            executed: 0,
            total_migrated: 0,
            migrated: 0,
        },
        PriorityStat {
            total_executed: 0,
            executed: 0,
            total_migrated: 0,
            migrated: 0,
        },
    ]),
};

/// Whether scheduler statistics are enabled.
// Port of erts/emulator/beam/erl_process.c:10208 (schedule), OTP-29.1.1.
pub fn enabled() -> bool {
    SCHED_STAT.enabled.load(Ordering::Relaxed)
}

/// Record one process selection after `schedule()` observes enabled statistics.
// Port of erts/emulator/beam/erl_process.c:10208-10224 (schedule), OTP-29.1.1.
pub(crate) fn record_execution(priority: usize, migrated: bool) {
    let mut stats = SCHED_STAT.lock.lock();
    let stat = &mut stats[priority];
    stat.total_executed = stat.total_executed.wrapping_add(1);
    stat.executed = stat.executed.wrapping_add(1);
    if migrated {
        stat.total_migrated = stat.total_migrated.wrapping_add(1);
        stat.migrated = stat.migrated.wrapping_add(1);
    }
}

/// Record one port selection on a normal scheduler.
// Port of erts/emulator/beam/erl_port_task.c:1707-1716 (erts_port_task_execute), OTP-29.1.1.
pub fn record_port_execution(migrated: bool) {
    let mut stats = SCHED_STAT.lock.lock();
    let stat = &mut stats[PORT_PRIORITY];
    stat.total_executed = stat.total_executed.wrapping_add(1);
    stat.executed = stat.executed.wrapping_add(1);
    if migrated {
        stat.total_migrated = stat.total_migrated.wrapping_add(1);
        stat.migrated = stat.migrated.wrapping_add(1);
    }
}

/// Enable, disable, or clear the global scheduling counters.
// Port of erts/emulator/beam/erl_process.c:11949-11972 (erts_sched_stat_modify), OTP-29.1.1.
pub fn modify(action: &str) {
    match action {
        "enable" | "disable" => {
            SCHED_STAT
                .enabled
                .store(action == "enable", Ordering::SeqCst);
        }
        "clear" => {
            let mut stats = SCHED_STAT.lock.lock();
            for stat in stats.iter_mut() {
                *stat = PriorityStat::default();
            }
        }
        _ => unreachable!("caller validates scheduling statistics action"),
    }
}

/// Read cumulative counters or return and clear the counters since the last interval read.
// Port of erts/emulator/beam/erl_process.c:11977-12008 (erts_sched_stat_term), OTP-29.1.1.
pub fn snapshot(total: bool) -> [(u64, u64); PRIORITY_COUNT] {
    let mut stats = SCHED_STAT.lock.lock();
    std::array::from_fn(|index| {
        let stat = &mut stats[index];
        if total {
            (stat.total_executed, stat.total_migrated)
        } else {
            let values = (stat.executed, stat.migrated);
            stat.executed = 0;
            stat.migrated = 0;
            values
        }
    })
}
