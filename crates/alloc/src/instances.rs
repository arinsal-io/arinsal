//! Scheduler-local allocator instances, delayed frees, and shared MBC carriers.

use crate::alloc_util::HashMap;
use crate::alloc_util::{
    AllocError, AllocUtil, AllocUtilOptions, Allocation, AllocatorInfo, CarrierPoolStats,
    CarrierTransfer, Strategy,
};
use crossbeam_queue::SegQueue;
use std::cell::Cell;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::{self, ThreadId};

static NEXT_INSTANCE_CACHE_ID: AtomicUsize = AtomicUsize::new(1);

const INSTANCE_CACHE_SLOTS: usize = 32;

thread_local! {
    // One slot per allocator family (cache id modulo slots); a collision only costs the slow path.
    static LAST_INSTANCE: [Cell<(usize, usize)>; INSTANCE_CACHE_SLOTS] =
        const { [const { Cell::new((0, 0)) }; INSTANCE_CACHE_SLOTS] };
}

struct Instance {
    allocator: AllocUtil,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
/// A stable allocation handle that follows its block when a carrier migrates.
pub struct InstanceAllocation {
    instance: usize,
    allocation: Allocation,
}

impl InstanceAllocation {
    /// Original allocator instance assigned when the block was created.
    pub const fn instance(self) -> usize {
        self.instance
    }

    pub(crate) fn from_parts(instance: usize, id: u64, size: usize) -> Self {
        Self {
            instance,
            allocation: Allocation::from_parts(id, size),
        }
    }

    pub(crate) fn allocation_id(self) -> u64 {
        self.allocation.id()
    }
}

#[derive(Clone, Copy)]
enum AllocationRoute {
    Current {
        instance: usize,
        allocation: Allocation,
    },
    Pooled {
        pool_id: u64,
    },
    Homecoming {
        homecoming_id: u64,
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
/// A handle names its block by address and the instance that owned the block's carrier when the
/// handle was made. Like erts' carrier `allctr` word (erl_alloc_util.c:1736 get_used_allctr), a
/// carrier that leaves that instance records the new owner of its blocks; only those blocks have an
/// entry in `routes`, so the common alloc/free path takes no shared lock.
///
/// Port of scheduler-specific allocator, delayed-free, and carrier-pool behavior
/// in `erl_alloc_util.c:2260-2299,3968-4030,4180-4200`, OTP-29.1.1.
pub struct ThreadSpecificAllocators {
    // parking_lot: the uncontended lock is one CAS, on every alloc and free.
    instances: Vec<parking_lot::Mutex<Instance>>,
    /// Cross-thread frees. Lock-free so a foreign free does not take the owner's mutex.
    /// Port of erl_alloc_util.c:2225 (`enqueue_dealloc_other_instance` / `ddq_enqueue`), OTP-29.1.1.
    delayed: Vec<SegQueue<(InstanceAllocation, Allocation)>>,
    thread_instances: Mutex<HashMap<ThreadId, usize>>,
    /// Owner of blocks whose carrier left the instance named in their handle, by block address.
    routes: Mutex<HashMap<u64, AllocationRoute>>,
    /// Number of `routes` entries; zero lets handles route to their own instance without locking.
    routed: AtomicUsize,
    carrier_pool: Mutex<Vec<PooledCarrier>>,
    /// Number of pooled carriers, read without the pool lock on every allocation.
    pooled: AtomicUsize,
    homecomings: Mutex<Vec<HomecomingCarrier>>,
    next_pool_id: Mutex<u64>,
    pool_stats: Mutex<CarrierPoolStats>,
    thread_specific: bool,
    cache_id: usize,
}

impl ThreadSpecificAllocators {
    /// Creates `instance_count` scheduler-local instances.
    pub fn new(
        instance_count: usize,
        thread_specific: bool,
        strategy: Strategy,
        options: AllocUtilOptions,
    ) -> Self {
        Self::new_for_type(
            instance_count,
            thread_specific,
            strategy,
            options,
            "eheap_alloc",
        )
    }

    /// Creates instances tagged with the selected ERTS allocator name.
    pub fn new_for_type(
        instance_count: usize,
        thread_specific: bool,
        strategy: Strategy,
        options: AllocUtilOptions,
        allocation_type: &'static str,
    ) -> Self {
        let count = instance_count.max(1);
        Self {
            instances: (0..count)
                .map(|instance| {
                    parking_lot::Mutex::new(Instance {
                        allocator: AllocUtil::new_for_instance(
                            strategy,
                            options,
                            allocation_type,
                            instance,
                            true,
                        ),
                    })
                })
                .collect(),
            delayed: (0..count).map(|_| SegQueue::new()).collect(),
            thread_instances: Mutex::new(HashMap::default()),
            routes: Mutex::new(HashMap::default()),
            routed: AtomicUsize::new(0),
            carrier_pool: Mutex::new(Vec::new()),
            pooled: AtomicUsize::new(0),
            homecomings: Mutex::new(Vec::new()),
            next_pool_id: Mutex::new(1),
            pool_stats: Mutex::new(CarrierPoolStats::default()),
            thread_specific,
            cache_id: NEXT_INSTANCE_CACHE_ID.fetch_add(1, Ordering::Relaxed),
        }
    }

    /// Allocates on the instance assigned to the current thread.
    pub fn alloc(&self, size: usize) -> Result<InstanceAllocation, AllocError> {
        self.alloc_with_ptr(size).map(|(handle, _)| handle)
    }

    /// Allocates and returns the stable payload pointer.
    pub fn alloc_with_ptr(
        &self,
        size: usize,
    ) -> Result<(InstanceAllocation, *mut u64), AllocError> {
        let instance = self.current_instance();
        let mut state = self.lock_instance(instance);
        self.drain_and_publish(instance, &mut state)?;
        if self.pooled.load(Ordering::Acquire) != 0 && state.allocator.needs_carrier(size)? {
            self.fetch_for_size(instance, &mut state, size)?;
        }
        let allocation = state.allocator.alloc(size)?;
        let ptr = state.allocator.payload_ptr(allocation)?;
        Ok((
            InstanceAllocation {
                instance,
                allocation,
            },
            ptr,
        ))
    }

    /// Resizes an allocation on its current carrier-owning instance.
    pub fn realloc(
        &self,
        handle: InstanceAllocation,
        size: usize,
    ) -> Result<InstanceAllocation, AllocError> {
        self.realloc_with_ptr(handle, size)
            .map(|(handle, _)| handle)
    }

    /// Resizes an allocation and returns the handle and payload address it now has.
    pub fn realloc_with_ptr(
        &self,
        handle: InstanceAllocation,
        size: usize,
    ) -> Result<(InstanceAllocation, *mut u64), AllocError> {
        let (instance, allocation) = self.route(handle)?;
        let mut state = self.lock_instance(instance);
        self.drain_and_publish(instance, &mut state)?;
        let resized = state.allocator.realloc(allocation, size)?;
        let ptr = state.allocator.payload_ptr(resized)?;
        self.publish_transfers(instance, &mut state)?;
        // The new handle names the owning instance directly, so any route entry is stale.
        self.forget_route(allocation.id());
        Ok((
            InstanceAllocation {
                instance,
                allocation: resized,
            },
            ptr,
        ))
    }

    /// Frees immediately on the current instance or queues the free for its owner.
    /// Port of erl_alloc_util.c:6216 (erts_alcu_free_thr_pref) delayed-dealloc enqueue, OTP-29.1.1.
    pub fn free(&self, handle: InstanceAllocation) -> Result<(), AllocError> {
        let (instance, allocation) = self.route(handle)?;
        let current = self.current_instance();
        if current != instance {
            // Port of erl_alloc_util.c:6225-6230 (erts_alcu_free_thr_pref), OTP-29.1.1:
            // a block freed by another scheduler is queued on the owning instance
            // without taking that instance's mutex.
            self.delayed[instance].push((handle, allocation));
            return Ok(());
        }
        let mut state = self.lock_instance(instance);
        self.drain_and_publish(instance, &mut state)?;
        state.allocator.free(allocation)?;
        self.publish_transfers(instance, &mut state)?;
        self.forget_route(allocation.id());
        Ok(())
    }

    /// Writes bytes through the allocation's current carrier owner.
    pub fn write(
        &self,
        handle: InstanceAllocation,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), AllocError> {
        let (instance, allocation) = self.route(handle)?;
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
        let (instance, allocation) = self.route(handle)?;
        self.lock_instance(instance)
            .allocator
            .read(allocation, offset, out)
    }

    /// Returns the stable payload address while the allocation remains live.
    pub fn allocation_ptr(&self, handle: InstanceAllocation) -> Result<*mut u64, AllocError> {
        let (instance, allocation) = self.route(handle)?;
        self.lock_instance(instance)
            .allocator
            .allocation_ptr(allocation)
    }

    /// Processes delayed frees for every instance.
    ///
    /// Used by `erts_debug:set_internal_state(wait, deallocations)`, which must
    /// observe blocks a non-owner scheduler already queued.
    pub fn drain_all_deallocations(&self) -> Result<usize, AllocError> {
        let mut total = 0;
        for instance in 0..self.instances.len() {
            total += self.drain_deallocations(instance)?;
        }
        Ok(total)
    }

    /// Processes the delayed-free queue for one instance.
    pub fn drain_deallocations(&self, instance: usize) -> Result<usize, AllocError> {
        let mut state = self.lock_instance(instance);
        let drained = self.drain_locked(instance, &mut state)?;
        let count = drained.len();
        self.clear_routes(drained);
        self.publish_transfers(instance, &mut state)?;
        Ok(count)
    }

    /// Returns the number of frees waiting for the instance.
    pub fn pending_deallocations(&self, instance: usize) -> usize {
        self.delayed[instance].len()
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
        if let Some(instance) = LAST_INSTANCE.with(|cache| {
            let (cache_id, instance) = cache[self.cache_id % INSTANCE_CACHE_SLOTS].get();
            (cache_id == self.cache_id).then_some(instance)
        }) {
            return instance;
        }
        let id = thread::current().id();
        let mut assignments = self
            .thread_instances
            .lock()
            .expect("thread-instance lock poisoned");
        if let Some(instance) = assignments.get(&id) {
            LAST_INSTANCE.with(|cache| {
                cache[self.cache_id % INSTANCE_CACHE_SLOTS].set((self.cache_id, *instance));
            });
            return *instance;
        }
        let instance = assignments.len() % self.instances.len();
        assignments.insert(id, instance);
        LAST_INSTANCE.with(|cache| {
            cache[self.cache_id % INSTANCE_CACHE_SLOTS].set((self.cache_id, instance));
        });
        instance
    }

    /// Current size of allocated blocks across this allocator's instances.
    // Port of erts/emulator/beam/erl_alloc_util.c:5952 (erts_alcu_current_size), OTP-29.1.1.
    pub(crate) fn current_blocks_size(&self) -> usize {
        self.instances
            .iter()
            .enumerate()
            .map(|(instance, _)| self.lock_instance(instance).allocator.stats().blocks_size)
            .sum()
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

    #[inline]
    fn lock_instance(&self, instance: usize) -> parking_lot::MutexGuard<'_, Instance> {
        self.instances[instance].lock()
    }

    /// Runs queued cross-thread frees and hands abandoned carriers to the pool.
    #[inline(always)]
    fn drain_and_publish(&self, instance: usize, state: &mut Instance) -> Result<(), AllocError> {
        if !self.delayed[instance].is_empty() {
            let drained = self.drain_locked(instance, state)?;
            self.clear_routes(drained);
        }
        self.publish_transfers(instance, state)
    }

    /// The instance owning `handle`'s block now, and the block's allocation there.
    #[inline]
    fn route(&self, handle: InstanceAllocation) -> Result<(usize, Allocation), AllocError> {
        if self.routed.load(Ordering::Acquire) == 0 {
            return Ok((handle.instance, handle.allocation));
        }
        match self.ensure_current_route(handle)? {
            AllocationRoute::Current {
                instance,
                allocation,
            } => Ok((instance, allocation)),
            _ => Err(AllocError::Corrupt),
        }
    }

    fn forget_route(&self, id: u64) {
        if self.routed.load(Ordering::Acquire) == 0 {
            return;
        }
        let mut routes = self.routes.lock().expect("allocation-route lock poisoned");
        if routes.remove(&id).is_some() {
            self.routed.fetch_sub(1, Ordering::AcqRel);
        }
    }

    fn set_route(
        &self,
        routes: &mut HashMap<u64, AllocationRoute>,
        id: u64,
        route: AllocationRoute,
    ) {
        if routes.insert(id, route).is_none() {
            self.routed.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn clear_routes(&self, handles: Vec<InstanceAllocation>) {
        if handles.is_empty() || self.routed.load(Ordering::Acquire) == 0 {
            return;
        }
        let mut routes = self.routes.lock().expect("allocation-route lock poisoned");
        for handle in handles {
            if routes.remove(&handle.allocation.id()).is_some() {
                self.routed.fetch_sub(1, Ordering::AcqRel);
            }
        }
    }

    fn ensure_current_route(
        &self,
        handle: InstanceAllocation,
    ) -> Result<AllocationRoute, AllocError> {
        let current_route = |routes: &HashMap<u64, AllocationRoute>| {
            routes
                .get(&handle.allocation.id())
                .copied()
                .unwrap_or(AllocationRoute::Current {
                    instance: handle.instance,
                    allocation: handle.allocation,
                })
        };
        let route = current_route(&self.routes.lock().expect("allocation-route lock poisoned"));
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
            self.pooled.fetch_sub(1, Ordering::AcqRel);
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
        Ok(current_route(
            &self.routes.lock().expect("allocation-route lock poisoned"),
        ))
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
        self.pooled.fetch_sub(1, Ordering::AcqRel);
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
            if let Some(route) = routes.get_mut(&old.id())
                && matches!(route, AllocationRoute::Pooled { pool_id: id, .. } if *id == pool_id)
            {
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
            if let Some(route) = routes.get_mut(&old.id())
                && matches!(route, AllocationRoute::Homecoming { homecoming_id: id, .. } if *id == homecoming_id)
            {
                *route = AllocationRoute::Current {
                    instance,
                    allocation: new,
                };
            }
        }
    }

    #[inline(always)]
    fn publish_transfers(&self, instance: usize, state: &mut Instance) -> Result<(), AllocError> {
        if !state.allocator.has_pending_carriers() {
            return Ok(());
        }
        self.publish_pending_transfers(instance, state)
    }

    #[cold]
    fn publish_pending_transfers(
        &self,
        instance: usize,
        state: &mut Instance,
    ) -> Result<(), AllocError> {
        let transfers = state.allocator.take_pending_carriers();
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
                    if let Some(route) = routes.get_mut(&old.id()) {
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
                    self.set_route(
                        &mut routes,
                        allocation.id(),
                        AllocationRoute::Pooled { pool_id: id },
                    );
                }
                pool.push(PooledCarrier { id, transfer });
                self.pooled.fetch_add(1, Ordering::AcqRel);
            } else {
                for (allocation, _) in transfer.allocations() {
                    self.set_route(
                        &mut routes,
                        allocation.id(),
                        AllocationRoute::Homecoming { homecoming_id: id },
                    );
                }
                self.homecomings
                    .lock()
                    .expect("homecoming lock poisoned")
                    .push(HomecomingCarrier { id, transfer });
            }
        }
        Ok(())
    }

    fn drain_locked(
        &self,
        instance: usize,
        state: &mut Instance,
    ) -> Result<Vec<InstanceAllocation>, AllocError> {
        let mut drained = Vec::new();
        let queue = &self.delayed[instance];
        while let Some((handle, allocation)) = queue.pop() {
            if let Err(error) = state.allocator.free(allocation) {
                queue.push((handle, allocation));
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
