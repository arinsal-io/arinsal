//! Safe scheduler-local allocator instances and delayed cross-instance frees.

use crate::alloc_util::{AllocError, AllocUtil, AllocUtilOptions, Allocation, Strategy};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::thread::{self, ThreadId};

struct Instance {
    allocator: AllocUtil,
    delayed: VecDeque<Allocation>,
}

/// A handle allocated by one scheduler-local allocator instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstanceAllocation {
    instance: usize,
    allocation: Allocation,
}

/// Owns allocator instances and queues cross-instance frees for the owning instance.
///
/// Port of the scheduler-specific allocator and alloc_util delayed-deallocation
/// queue behavior in `erl_alloc_util.c:1825-1848,2030-2077`, OTP-29.1.1.
pub struct ThreadSpecificAllocators {
    instances: Vec<Mutex<Instance>>,
    thread_instances: Mutex<HashMap<ThreadId, usize>>,
    thread_specific: bool,
}

impl ThreadSpecificAllocators {
    /// Creates `instance_count` scheduler-local instances.
    pub fn new(
        instance_count: usize,
        thread_specific: bool,
        strategy: Strategy,
        options: AllocUtilOptions,
    ) -> Self {
        let count = instance_count.max(1);
        Self {
            instances: (0..count)
                .map(|_| {
                    Mutex::new(Instance {
                        allocator: AllocUtil::new(strategy, options),
                        delayed: VecDeque::new(),
                    })
                })
                .collect(),
            thread_instances: Mutex::new(HashMap::new()),
            thread_specific,
        }
    }

    /// Allocates on the instance assigned to the current thread.
    pub fn alloc(&self, size: usize) -> Result<InstanceAllocation, AllocError> {
        let instance = self.current_instance();
        let mut state = self.instances[instance]
            .lock()
            .expect("allocator lock poisoned");
        Self::drain_locked(&mut state)?;
        let allocation = state.allocator.alloc(size)?;
        Ok(InstanceAllocation {
            instance,
            allocation,
        })
    }

    /// Resizes an allocation on its owning instance.
    pub fn realloc(
        &self,
        allocation: InstanceAllocation,
        size: usize,
    ) -> Result<InstanceAllocation, AllocError> {
        let instance = allocation.instance;
        let mut state = self.instances[allocation.instance]
            .lock()
            .expect("allocator lock poisoned");
        Self::drain_locked(&mut state)?;
        let allocation = state.allocator.realloc(allocation.allocation, size)?;
        Ok(InstanceAllocation {
            instance,
            allocation,
        })
    }

    /// Frees immediately on the current instance or queues the free for its owner.
    pub fn free(&self, allocation: InstanceAllocation) -> Result<(), AllocError> {
        let current = self.current_instance();
        let mut state = self.instances[allocation.instance]
            .lock()
            .expect("allocator lock poisoned");
        if current == allocation.instance {
            Self::drain_locked(&mut state)?;
            state.allocator.free(allocation.allocation)
        } else {
            state.delayed.push_back(allocation.allocation);
            Ok(())
        }
    }

    /// Writes bytes through the allocation's owning instance.
    pub fn write(
        &self,
        allocation: InstanceAllocation,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), AllocError> {
        self.instances[allocation.instance]
            .lock()
            .expect("allocator lock poisoned")
            .allocator
            .write(allocation.allocation, offset, bytes)
    }

    /// Reads bytes through the allocation's owning instance.
    pub fn read(
        &self,
        allocation: InstanceAllocation,
        offset: usize,
        out: &mut [u8],
    ) -> Result<(), AllocError> {
        self.instances[allocation.instance]
            .lock()
            .expect("allocator lock poisoned")
            .allocator
            .read(allocation.allocation, offset, out)
    }

    /// Processes the delayed-free queue for one instance.
    pub fn drain_deallocations(&self, instance: usize) -> Result<usize, AllocError> {
        let mut state = self.instances[instance]
            .lock()
            .expect("allocator lock poisoned");
        Self::drain_locked(&mut state)
    }

    /// Returns the number of frees waiting for the instance.
    pub fn pending_deallocations(&self, instance: usize) -> usize {
        self.instances[instance]
            .lock()
            .expect("allocator lock poisoned")
            .delayed
            .len()
    }

    /// Returns the allocator instance currently assigned to the calling thread.
    pub fn current_instance(&self) -> usize {
        if !self.thread_specific {
            return 0;
        }
        let id = thread::current().id();
        let mut assignments = self
            .thread_instances
            .lock()
            .expect("thread-instance lock poisoned");
        if let Some(instance) = assignments.get(&id) {
            return *instance;
        }
        let instance = assignments.len() % self.instances.len();
        assignments.insert(id, instance);
        instance
    }

    fn drain_locked(state: &mut Instance) -> Result<usize, AllocError> {
        let mut count = 0;
        while let Some(allocation) = state.delayed.pop_front() {
            if let Err(error) = state.allocator.free(allocation) {
                state.delayed.push_front(allocation);
                return Err(error);
            }
            count += 1;
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    #[test]
    fn cross_instance_free_is_delayed_until_owner_drains() {
        let allocators = Arc::new(ThreadSpecificAllocators::new(
            2,
            true,
            Strategy::AoffCbf,
            AllocUtilOptions::default(),
        ));
        let allocation = allocators.alloc(24).unwrap();
        let owner = allocation.instance;
        let barrier = Arc::new(Barrier::new(2));
        let worker_allocators = Arc::clone(&allocators);
        let worker_barrier = Arc::clone(&barrier);
        let worker = thread::spawn(move || {
            let _ = worker_allocators.current_instance();
            worker_barrier.wait();
            worker_barrier.wait();
            worker_allocators.free(allocation).unwrap();
            worker_allocators.pending_deallocations(owner)
        });
        barrier.wait();
        barrier.wait();
        assert_eq!(worker.join().unwrap(), 1);
        assert_eq!(allocators.drain_deallocations(owner).unwrap(), 1);
    }

    #[test]
    fn non_thread_specific_mode_uses_instance_zero() {
        let allocators =
            ThreadSpecificAllocators::new(4, false, Strategy::Afit, AllocUtilOptions::default());
        assert_eq!(allocators.current_instance(), 0);
        let allocation = allocators.alloc(32).unwrap();
        assert_eq!(allocation.instance, 0);
        allocators.free(allocation).unwrap();
    }
}
