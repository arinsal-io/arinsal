//! Scheduler-local allocator instances, delayed frees, and shared MBC carriers.

use crate::alloc_util::{
    AllocError, AllocUtil, AllocUtilOptions, Allocation, AllocatorInfo, CarrierPoolStats,
    CarrierTransfer, Strategy,
};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::thread::{self, ThreadId};

struct Instance {
    allocator: AllocUtil,
    delayed: VecDeque<(InstanceAllocation, Allocation)>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
/// A stable allocation handle that follows its block when a carrier migrates.
pub struct InstanceAllocation {
    instance: usize,
    allocation: Allocation,
}

#[derive(Clone, Copy)]
enum AllocationRoute {
    Current {
        instance: usize,
        allocation: Allocation,
    },
    Pooled {
        pool_id: u64,
        allocation: Allocation,
    },
    Homecoming {
        homecoming_id: u64,
        allocation: Allocation,
    },
}

struct PooledCarrier {
    id: u64,
    transfer: CarrierTransfer,
}

struct HomecomingCarrier {
    id: u64,
    transfer: CarrierTransfer,
}

/// Owns allocator instances and routes handles as carriers move between them.
///
/// Port of scheduler-specific allocator, delayed-free, and carrier-pool behavior
/// in `erl_alloc_util.c:2260-2299,3968-4030,4180-4200`, OTP-29.1.1.
pub struct ThreadSpecificAllocators {
    instances: Vec<Mutex<Instance>>,
    thread_instances: Mutex<HashMap<ThreadId, usize>>,
    routes: Mutex<HashMap<InstanceAllocation, AllocationRoute>>,
    carrier_pool: Mutex<Vec<PooledCarrier>>,
    homecomings: Mutex<Vec<HomecomingCarrier>>,
    next_pool_id: Mutex<u64>,
    pool_stats: Mutex<CarrierPoolStats>,
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
                .map(|instance| {
                    Mutex::new(Instance {
                        allocator: AllocUtil::new_for_instance(
                            strategy,
                            options,
                            "eheap_alloc",
                            instance,
                            true,
                        ),
                        delayed: VecDeque::new(),
                    })
                })
                .collect(),
            thread_instances: Mutex::new(HashMap::new()),
            routes: Mutex::new(HashMap::new()),
            carrier_pool: Mutex::new(Vec::new()),
            homecomings: Mutex::new(Vec::new()),
            next_pool_id: Mutex::new(1),
            pool_stats: Mutex::new(CarrierPoolStats::default()),
            thread_specific,
        }
    }

    /// Allocates on the instance assigned to the current thread.
    pub fn alloc(&self, size: usize) -> Result<InstanceAllocation, AllocError> {
        let instance = self.current_instance();
        let mut state = self.lock_instance(instance);
        let drained = Self::drain_locked(&mut state)?;
        self.clear_routes(drained);
        self.publish_transfers(instance, &mut state)?;
        if state.allocator.needs_carrier(size)? {
            self.fetch_for_size(instance, &mut state, size)?;
        }
        let allocation = state.allocator.alloc(size)?;
        let handle = InstanceAllocation {
            instance,
            allocation,
        };
        drop(state);
        self.routes
            .lock()
            .expect("allocation-route lock poisoned")
            .insert(
                handle,
                AllocationRoute::Current {
                    instance,
                    allocation,
                },
            );
        Ok(handle)
    }

    /// Resizes an allocation on its current carrier-owning instance.
    pub fn realloc(
        &self,
        handle: InstanceAllocation,
        size: usize,
    ) -> Result<InstanceAllocation, AllocError> {
        let route = self.ensure_current_route(handle)?;
        let AllocationRoute::Current {
            instance,
            allocation,
        } = route
        else {
            return Err(AllocError::Corrupt);
        };
        let mut state = self.lock_instance(instance);
        let drained = Self::drain_locked(&mut state)?;
        self.clear_routes(drained);
        let resized = state.allocator.realloc(allocation, size)?;
        self.publish_transfers(instance, &mut state)?;
        self.routes
            .lock()
            .expect("allocation-route lock poisoned")
            .insert(
                handle,
                AllocationRoute::Current {
                    instance,
                    allocation: resized,
                },
            );
        Ok(handle)
    }

    /// Frees immediately on the current instance or queues the free for its owner.
    pub fn free(&self, handle: InstanceAllocation) -> Result<(), AllocError> {
        let route = self.ensure_current_route(handle)?;
        let AllocationRoute::Current {
            instance,
            allocation,
        } = route
        else {
            return Err(AllocError::Corrupt);
        };
        let current = self.current_instance();
        let mut state = self.lock_instance(instance);
        if current == instance {
            let drained = Self::drain_locked(&mut state)?;
            self.clear_routes(drained);
            state.allocator.free(allocation)?;
            self.publish_transfers(instance, &mut state)?;
            self.routes
                .lock()
                .expect("allocation-route lock poisoned")
                .remove(&handle);
        } else {
            state.delayed.push_back((handle, allocation));
        }
        Ok(())
    }

    /// Writes bytes through the allocation's current carrier owner.
    pub fn write(
        &self,
        handle: InstanceAllocation,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), AllocError> {
        let AllocationRoute::Current {
            instance,
            allocation,
        } = self.ensure_current_route(handle)?
        else {
            return Err(AllocError::Corrupt);
        };
        self.lock_instance(instance)
            .allocator
            .write(allocation, offset, bytes)
    }

    /// Reads bytes through the allocation's current carrier owner.
    pub fn read(
        &self,
        handle: InstanceAllocation,
        offset: usize,
        out: &mut [u8],
    ) -> Result<(), AllocError> {
        let AllocationRoute::Current {
            instance,
            allocation,
        } = self.ensure_current_route(handle)?
        else {
            return Err(AllocError::Corrupt);
        };
        self.lock_instance(instance)
            .allocator
            .read(allocation, offset, out)
    }

    /// Processes the delayed-free queue for one instance.
    pub fn drain_deallocations(&self, instance: usize) -> Result<usize, AllocError> {
        let mut state = self.lock_instance(instance);
        let drained = Self::drain_locked(&mut state)?;
        let count = drained.len();
        self.clear_routes(drained);
        self.publish_transfers(instance, &mut state)?;
        Ok(count)
    }

    /// Returns the number of frees waiting for the instance.
    pub fn pending_deallocations(&self, instance: usize) -> usize {
        self.lock_instance(instance).delayed.len()
    }

    #[cfg(test)]
    fn pooled_carrier_count(&self) -> usize {
        self.carrier_pool
            .lock()
            .expect("carrier-pool lock poisoned")
            .len()
    }

    #[cfg(test)]
    fn homecoming_carrier_count(&self) -> usize {
        self.homecomings
            .lock()
            .expect("homecoming lock poisoned")
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

    /// Returns allocator information with the shared `{mbcs_pool, ...}` section.
    pub fn info(&self, instance: usize) -> AllocatorInfo {
        let mut info = self.lock_instance(instance).allocator.info();
        if info.options.acul != 0 && info.options.cpool.is_some() {
            info.mbcs_pool = Some(self.carrier_pool_stats());
        }
        info
    }

    /// Returns current shared-pool totals and its operation counters.
    pub fn carrier_pool_stats(&self) -> CarrierPoolStats {
        let mut stats = *self.pool_stats.lock().expect("pool-stats lock poisoned");
        let pool = self
            .carrier_pool
            .lock()
            .expect("carrier-pool lock poisoned");
        let homecomings = self.homecomings.lock().expect("homecoming lock poisoned");
        for transfer in pool
            .iter()
            .map(|entry| &entry.transfer)
            .chain(homecomings.iter().map(|entry| &entry.transfer))
        {
            let (carrier_size, blocks, blocks_size) = transfer.pool_summary();
            stats.carriers += 1;
            stats.carriers_size += carrier_size;
            stats.blocks += blocks;
            stats.blocks_size += blocks_size;
        }
        stats
    }

    fn lock_instance(&self, instance: usize) -> std::sync::MutexGuard<'_, Instance> {
        self.instances[instance]
            .lock()
            .expect("allocator lock poisoned")
    }

    fn clear_routes(&self, handles: Vec<InstanceAllocation>) {
        let mut routes = self.routes.lock().expect("allocation-route lock poisoned");
        for handle in handles {
            routes.remove(&handle);
        }
    }

    fn ensure_current_route(
        &self,
        handle: InstanceAllocation,
    ) -> Result<AllocationRoute, AllocError> {
        let route = self
            .routes
            .lock()
            .expect("allocation-route lock poisoned")
            .get(&handle)
            .copied()
            .ok_or(AllocError::InvalidAllocation)?;
        let (instance, id, homecoming) = match route {
            AllocationRoute::Current { .. } => return Ok(route),
            AllocationRoute::Pooled { pool_id, .. } => (self.current_instance(), pool_id, false),
            AllocationRoute::Homecoming { homecoming_id, .. } => {
                let homecomings = self.homecomings.lock().expect("homecoming lock poisoned");
                let entry = homecomings
                    .iter()
                    .find(|entry| entry.id == homecoming_id)
                    .ok_or(AllocError::InvalidAllocation)?;
                (entry.transfer.origin_instance(), homecoming_id, true)
            }
        };
        let mut state = self.lock_instance(instance);
        let transfer = if homecoming {
            let mut homecomings = self.homecomings.lock().expect("homecoming lock poisoned");
            let index = homecomings
                .iter()
                .position(|entry| entry.id == id)
                .ok_or(AllocError::InvalidAllocation)?;
            homecomings.swap_remove(index).transfer
        } else {
            let mut pool = self
                .carrier_pool
                .lock()
                .expect("carrier-pool lock poisoned");
            let index = pool
                .iter()
                .position(|entry| entry.id == id)
                .ok_or(AllocError::InvalidAllocation)?;
            pool.swap_remove(index).transfer
        };
        let remapped = state.allocator.import_carrier_transfer(transfer)?;
        if !homecoming {
            self.pool_stats
                .lock()
                .expect("pool-stats lock poisoned")
                .fetch
                .inc();
        }
        if homecoming {
            self.update_homecoming_routes(id, instance, remapped);
        } else {
            self.update_imported_routes(id, instance, remapped);
        }
        self.publish_transfers(instance, &mut state)?;
        self.routes
            .lock()
            .expect("allocation-route lock poisoned")
            .get(&handle)
            .copied()
            .ok_or(AllocError::InvalidAllocation)
    }

    fn fetch_for_size(
        &self,
        instance: usize,
        state: &mut Instance,
        size: usize,
    ) -> Result<(), AllocError> {
        let Some(need) = state.allocator.required_block_size(size)? else {
            return Ok(());
        };
        let mut pool = self
            .carrier_pool
            .lock()
            .expect("carrier-pool lock poisoned");
        let mut skipped_small = 0;
        let index = pool.iter().position(|entry| {
            let fits = state.allocator.transfer_largest_free(&entry.transfer) >= need;
            if !fits {
                skipped_small += 1;
            }
            fits
        });
        if skipped_small != 0 {
            let mut stats = self.pool_stats.lock().expect("pool-stats lock poisoned");
            for _ in 0..skipped_small {
                stats.skip_size.inc();
            }
        }
        let Some(index) = index else {
            return Ok(());
        };
        let entry = pool.swap_remove(index);
        let pool_id = entry.id;
        let remapped = state.allocator.import_carrier_transfer(entry.transfer)?;
        drop(pool);
        self.update_imported_routes(pool_id, instance, remapped);
        self.pool_stats
            .lock()
            .expect("pool-stats lock poisoned")
            .fetch
            .inc();
        Ok(())
    }

    fn update_imported_routes(
        &self,
        pool_id: u64,
        instance: usize,
        remapped: Vec<(Allocation, Allocation)>,
    ) {
        let mut routes = self.routes.lock().expect("allocation-route lock poisoned");
        for (old, new) in remapped {
            if let Some(route) = routes.values_mut().find(|route| {
            matches!(route, AllocationRoute::Pooled { pool_id: id, allocation } if *id == pool_id && allocation.id() == old.id())
            }) {
                *route = AllocationRoute::Current {
                    instance,
                    allocation: new,
                };
            }
        }
    }

    fn update_homecoming_routes(
        &self,
        homecoming_id: u64,
        instance: usize,
        remapped: Vec<(Allocation, Allocation)>,
    ) {
        let mut routes = self.routes.lock().expect("allocation-route lock poisoned");
        for (old, new) in remapped {
            if let Some(route) = routes.values_mut().find(|route| {
                matches!(route, AllocationRoute::Homecoming { homecoming_id: id, allocation } if *id == homecoming_id && allocation.id() == old.id())
            }) {
                *route = AllocationRoute::Current {
                    instance,
                    allocation: new,
                };
            }
        }
    }

    fn publish_transfers(&self, instance: usize, state: &mut Instance) -> Result<(), AllocError> {
        let transfers = state.allocator.take_pending_carriers();
        if transfers.is_empty() {
            return Ok(());
        }
        let mut pool = self
            .carrier_pool
            .lock()
            .expect("carrier-pool lock poisoned");
        let mut routes = self.routes.lock().expect("allocation-route lock poisoned");
        for transfer in transfers {
            if transfer.origin_instance() == instance
                && pool.len() >= state.allocator.carrier_pool_limit()
            {
                for (old, new) in state.allocator.import_carrier_transfer(transfer)? {
                    if let Some(route) = routes.values_mut().find(|route| {
                        matches!(route, AllocationRoute::Current { instance: owner, allocation } if *owner == instance && allocation.id() == old.id())
                    }) {
                        *route = AllocationRoute::Current {
                            instance,
                            allocation: new,
                        };
                    }
                }
                continue;
            }
            let id = {
                let mut next = self.next_pool_id.lock().expect("pool-id lock poisoned");
                let id = *next;
                *next += 1;
                id
            };
            if transfer.origin_instance() == instance {
                for (allocation, _) in transfer.allocations() {
                    if let Some(route) = routes.values_mut().find(|route| {
                        matches!(route, AllocationRoute::Current { instance: owner, allocation: live } if *owner == instance && live.id() == allocation.id())
                    }) {
                        *route = AllocationRoute::Pooled {
                            pool_id: id,
                            allocation: *allocation,
                        };
                    }
                }
                pool.push(PooledCarrier { id, transfer });
            } else {
                for (allocation, _) in transfer.allocations() {
                    if let Some(route) = routes.values_mut().find(|route| {
                        matches!(route, AllocationRoute::Current { instance: owner, allocation: live } if *owner == instance && live.id() == allocation.id())
                    }) {
                        *route = AllocationRoute::Homecoming {
                            homecoming_id: id,
                            allocation: *allocation,
                        };
                    }
                }
                self.homecomings
                    .lock()
                    .expect("homecoming lock poisoned")
                    .push(HomecomingCarrier { id, transfer });
            }
        }
        Ok(())
    }

    fn drain_locked(state: &mut Instance) -> Result<Vec<InstanceAllocation>, AllocError> {
        let mut drained = Vec::new();
        while let Some((handle, allocation)) = state.delayed.pop_front() {
            if let Err(error) = state.allocator.free(allocation) {
                state.delayed.push_front((handle, allocation));
                return Err(error);
            }
            drained.push(handle);
        }
        Ok(drained)
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

    #[test]
    fn abandoned_carrier_migrates_and_routes_live_allocations() {
        let options = AllocUtilOptions {
            sbct: 32 * 1024 * 1024,
            mmbcs: 4096,
            smbcs: 4096,
            lmbcs: 4096,
            mbcgs: 1,
            acul: 99,
            acful: 90,
            acnl: 8,
            acfml: 16,
            cpool: Some('H'),
            ..AllocUtilOptions::default()
        };
        let allocators = Arc::new(ThreadSpecificAllocators::new(
            2,
            true,
            Strategy::AoffCbf,
            options,
        ));
        let first = allocators.alloc(15_500_000).unwrap();
        let live = allocators.alloc(14_000_000).unwrap();
        allocators.write(live, 0, b"carrier migration").unwrap();
        let trigger = allocators.alloc(1_500_000).unwrap();
        allocators.free(trigger).unwrap();
        assert_eq!(allocators.pooled_carrier_count(), 1);
        let pool_info = allocators.info(0).mbcs_pool.unwrap();
        assert_eq!(pool_info.carriers, 1);
        assert_eq!(pool_info.blocks, 1);

        let worker_allocators = Arc::clone(&allocators);
        let worker = thread::spawn(move || {
            assert_eq!(worker_allocators.current_instance(), 1);
            let mut bytes = [0; 17];
            worker_allocators.read(live, 0, &mut bytes).unwrap();
            assert_eq!(&bytes, b"carrier migration");
            let next = worker_allocators.alloc(1_500_000).unwrap();
            worker_allocators.free(next).unwrap();
            assert_eq!(worker_allocators.homecoming_carrier_count(), 1);
            worker_allocators.read(live, 0, &mut bytes).unwrap();
            assert_eq!(&bytes, b"carrier migration");
        });
        worker.join().unwrap();
        assert_eq!(allocators.pooled_carrier_count(), 0);
        assert_eq!(allocators.homecoming_carrier_count(), 0);
        let pool_info = allocators.carrier_pool_stats();
        assert_eq!(pool_info.fetch.count, 1);
        assert_eq!(pool_info.fetch.giga, 0);
        allocators.free(live).unwrap();
        allocators.free(first).unwrap();
    }
}
