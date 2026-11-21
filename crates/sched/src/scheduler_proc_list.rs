//! Scheduler suspend lists corresponding to `ErtsProcList`.
// Port of erts/emulator/beam/erl_process.c (`proclist_create`, `erts_proclist_store_last`,
// `erts_proclist_remove`), OTP-29.1.1.

mod raw;

use crate::Pid;

#[derive(Clone, Copy)]
pub(super) struct SchedulerProcListEntry {
    pub(super) pid: Pid,
}

#[derive(Default)]
pub(super) struct SchedulerProcList(raw::ErtsProcList);

impl SchedulerProcList {
    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(super) fn len(&self) -> usize {
        self.0.len()
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = SchedulerProcListEntry> + '_ {
        self.0.iter()
    }

    pub(super) fn push_last(&mut self, entry: SchedulerProcListEntry) {
        self.0.push_last(entry);
    }

    pub(super) fn remove(&mut self, pid: Pid, all: bool) {
        self.0.remove(pid, all);
    }

    pub(super) fn pop_first(&mut self) -> Option<SchedulerProcListEntry> {
        self.0.pop_first()
    }

    pub(super) fn append(&mut self, other: &mut Self) {
        self.0.append(&mut other.0);
    }
}
