use super::TaskCell;
use crate::Task;
use std::mem::MaybeUninit;

impl<T: Task> TaskCell<T> {
    // Port of erts/emulator/beam/erl_process.c (alloc_process), OTP-29.1.1.
    /// Let a raw constructor initialize the task in the cell's final process block.
    ///
    /// The returned reference must identify this cell's storage. The address check keeps a
    /// safe callback from marking some separate value initialized here.
    #[inline(always)]
    pub(crate) fn init_in_place(
        &mut self,
        init: impl for<'a> FnOnce(&'a mut MaybeUninit<T>) -> &'a mut T,
    ) {
        assert!(!self.initialized, "a task is written once");
        let slot = self.task.as_mut_ptr();
        let task = init(&mut self.task);
        assert!(std::ptr::eq(slot, task));
        self.initialized = true;
    }
}
