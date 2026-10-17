//! Scheduler-local allocator instances, delayed frees, and shared MBC carriers.

use crate::alloc_util::HashMap;
use crate::alloc_util::{
    AllocError, AllocUtil, AllocUtilOptions, Allocation, AllocatorInfo, CarrierPoolStats,
    CarrierTransfer, Strategy, set_dyn_sbct,
};
use crossbeam_queue::SegQueue;
use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

thread_local! {
    /// The allocator instance of this thread, shared by every allocator family.
    ///
    /// Port of the per-thread `alc_ix` word of erts (`erts_get_thr_alloc_ix` in
    /// erl_alloc.c), OTP-29.1.1: zero until the thread registers.
    static ALC_IX: Cell<usize> = const { Cell::new(0) };
    static CLAIM: RefCell<Option<InstanceClaim>> = const { RefCell::new(None) };
}

/// Scheduler numbers whose thread currently owns the instance of that number.
static CLAIMED: Mutex<BTreeSet<usize>> = Mutex::new(BTreeSet::new());

static OWNER_NOTIFIER: OnceLock<fn(usize)> = OnceLock::new();

/// Releases a scheduler instance when its owning thread exits.
struct InstanceClaim(usize);

impl Drop for InstanceClaim {
    fn drop(&mut self) {
        ALC_IX.with(|ix| ix.set(0));
        CLAIMED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.0);
    }
}

/// The kind of thread that registers with the allocator, numbered as erts numbers its schedulers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadKind {
    /// Normal scheduler `no`, one based. It owns instance `no`.
    Scheduler(usize),
    /// Dirty CPU scheduler `no`, one based.
    DirtyCpu(usize),
    /// Dirty I/O scheduler `no`, one based.
    DirtyIo(usize),
}

/// Why a thread could not be registered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegisterError {
    /// The calling thread already registered.
    AlreadyRegistered,
    /// Scheduler numbers start at one.
    InvalidNumber,
    /// Another live thread owns this scheduler instance.
    InstanceTaken(usize),
}

/// Binds the calling thread to its allocator instance and returns the instance index.
///
/// Port of `erts_alloc_register_scheduler` in erl_alloc.c, OTP-29.1.1: normal scheduler `no` gets
/// instance `no`. A dirty scheduler gets instance 0 unless dirty allocator instances (`+Mdai`) are
/// configured; then dirty scheduler `no` of its type gets `schedulers + (no - 1) % dirty + 1`. Every
/// thread that never registers (aux, async, poll, main, NIF and driver threads) uses instance 0.
///
/// A scheduler instance has one owner. A second live thread asking for the same scheduler number
/// gets [`RegisterError::InstanceTaken`] and keeps using instance 0; the number is free again when
/// the owner exits.
pub fn register_thread(kind: ThreadKind) -> Result<usize, RegisterError> {
    if CLAIM.with(|claim| claim.borrow().is_some()) || ALC_IX.with(Cell::get) != 0 {
        return Err(RegisterError::AlreadyRegistered);
    }
    let (schedulers, dirty) = crate::typed::configured().unwrap_or((0, 0));
    let (ix, claimed) = match kind {
        ThreadKind::Scheduler(0) | ThreadKind::DirtyCpu(0) | ThreadKind::DirtyIo(0) => {
            return Err(RegisterError::InvalidNumber);
        }
        ThreadKind::Scheduler(no) => (no, Some(no)),
        ThreadKind::DirtyCpu(no) | ThreadKind::DirtyIo(no) => (
            if dirty == 0 {
                0
            } else {
                schedulers + (no - 1) % dirty + 1
            },
            None,
        ),
    };
    if let Some(no) = claimed {
        let mut owners = CLAIMED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !owners.insert(no) {
            return Err(RegisterError::InstanceTaken(no));
        }
        CLAIM.with(|claim| *claim.borrow_mut() = Some(InstanceClaim(no)));
    }
    ALC_IX.with(|current| current.set(ix));
    Ok(ix)
}

/// Installs the callback that wakes the owner of a scheduler instance (once).
///
/// Port of `erts_alloc_notify_delayed_dealloc` in erl_alloc.c, OTP-29.1.1. The callback receives
/// the instance index; returns false when one is already installed.
pub fn set_owner_notifier(notify: fn(usize)) -> bool {
    OWNER_NOTIFIER.set(notify).is_ok()
}

/// Wakes the owner of `instance` so it handles its delayed frees; a no-op until a notifier is set.
pub fn notify_owner(instance: usize) {
    if let Some(notify) = OWNER_NOTIFIER.get() {
        notify(instance);
    }
}

struct Instance {
    allocator: AllocUtil,
}

/// A request another thread asks the owner of an instance to run.
type OwnerRequest = Box<dyn FnOnce(&ThreadSpecificAllocators) + Send>;

/// Delayed frees handled per owner-work pass.
///
/// Port of `ERTS_ALCU_DD_OPS_LIM_HIGH` in erl_alloc_util.h, OTP-29.1.1.
const OWNER_WORK_DD_LIMIT: usize = 20;

/// How long a requester waits for its owner before it asks the owner again.
const OWNER_WAIT_SLICE: Duration = Duration::from_micros(200);

/// What other threads may read or write about an instance without taking it.
///
/// The counters are single-writer mirrors the owner refreshes whenever it releases the instance,
/// like the size words erts reads in `erts_alcu_foreign_size` (erl_alloc_util.c, OTP-29.1.1); the
/// threshold is the `sbc_threshold` word `erts_alloc_set_dyn_param` writes.
struct Shared {
    blocks_size: AtomicUsize,
    carriers_size: AtomicUsize,
    sbct: Arc<AtomicUsize>,
    strategy: Strategy,
    requests: SegQueue<OwnerRequest>,
    work_scheduled: AtomicBool,
}

/// The lock on an instance; releasing it publishes the counter mirror.
struct InstanceGuard<'a> {
    guard: parking_lot::MutexGuard<'a, Instance>,
    shared: &'a Shared,
}

impl std::ops::Deref for InstanceGuard<'_> {
    type Target = Instance;

    #[inline(always)]
    fn deref(&self) -> &Instance {
        &self.guard
    }
}

impl std::ops::DerefMut for InstanceGuard<'_> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Instance {
        &mut self.guard
    }
}

impl Drop for InstanceGuard<'_> {
    #[inline(always)]
    fn drop(&mut self) {
        let (blocks_size, carriers_size) = self.guard.allocator.size_counters();
        self.shared
            .blocks_size
            .store(blocks_size, Ordering::Relaxed);
        self.shared
            .carriers_size
            .store(carriers_size, Ordering::Relaxed);
    }
}

fn owner_is_live(instance: usize) -> bool {
    CLAIMED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .contains(&instance)
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
    shared: Vec<Shared>,
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
        Self::new_with_global(
            instance_count,
            thread_specific,
            strategy,
            strategy,
            options,
            allocation_type,
        )
    }

    /// Like [`ThreadSpecificAllocators::new_for_type`], with a separate strategy for the shared
    /// instance 0 (`temp_alloc` uses afit on scheduler instances and goodfit on instance 0).
    pub fn new_with_global(
        instance_count: usize,
        thread_specific: bool,
        strategy: Strategy,
        global_strategy: Strategy,
        options: AllocUtilOptions,
        allocation_type: &'static str,
    ) -> Self {
        let count = instance_count.max(1);
        let allocators: Vec<AllocUtil> = (0..count)
            .map(|instance| {
                AllocUtil::new_for_instance(
                    if thread_specific && instance == 0 {
                        global_strategy
                    } else {
                        strategy
                    },
                    options,
                    allocation_type,
                    instance,
                    true,
                )
            })
            .collect();
        let shared = allocators
            .iter()
            .enumerate()
            .map(|(instance, allocator)| Shared {
                blocks_size: AtomicUsize::new(0),
                carriers_size: AtomicUsize::new(0),
                sbct: allocator.sbct_cell(),
                strategy: if thread_specific && instance == 0 {
                    global_strategy
                } else {
                    strategy
                },
                requests: SegQueue::new(),
                work_scheduled: AtomicBool::new(false),
            })
            .collect();
        Self {
            instances: allocators
                .into_iter()
                .map(|allocator| parking_lot::Mutex::new(Instance { allocator }))
                .collect(),
            shared,
            delayed: (0..count).map(|_| SegQueue::new()).collect(),
            routes: Mutex::new(HashMap::default()),
            routed: AtomicUsize::new(0),
            carrier_pool: Mutex::new(Vec::new()),
            pooled: AtomicUsize::new(0),
            homecomings: Mutex::new(Vec::new()),
            next_pool_id: Mutex::new(1),
            pool_stats: Mutex::new(CarrierPoolStats::default()),
            thread_specific,
        }
    }

    /// Number of instances, including the shared instance 0.
    pub fn instance_count(&self) -> usize {
        self.instances.len()
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

    /// Applies a dynamic `sbct` to every instance; true if any instance accepted it.
    ///
    /// Port of `erts_alloc_set_dyn_param` in erl_alloc.c, OTP-29.1.1: the calling thread writes the
    /// threshold word of every instance, no instance is locked and no owner is asked.
    pub fn try_set_dyn_sbct(&self, value: usize) -> bool {
        let mut ok = false;
        for shared in &self.shared {
            ok |= set_dyn_sbct(shared.strategy, &shared.sbct, value);
        }
        ok
    }

    /// Processes delayed frees of the instances no scheduler owns (instance 0 and the dirty
    /// instances) on the calling thread.
    ///
    /// Port of the aux and dirty threads' `erts_alloc_handle_delayed_dealloc` pass in erl_alloc.c,
    /// OTP-29.1.1. Scheduler instances drain on their owners: see
    /// [`ThreadSpecificAllocators::drain_deallocations`] and
    /// [`ThreadSpecificAllocators::handle_owner_work`].
    pub fn drain_shared_deallocations(&self) -> Result<usize, AllocError> {
        let schedulers = crate::typed::configured().map_or(0, |(schedulers, _)| schedulers);
        let mut total = 0;
        for instance in 0..self.instances.len() {
            if instance == 0 || instance > schedulers {
                total += self.drain_deallocations(instance)?;
            }
        }
        Ok(total)
    }

    /// Processes the delayed-free queue for one instance, on its owner.
    ///
    /// Port of `erts_alcu_check_delayed_dealloc` run by the owning scheduler, OTP-29.1.1. A call
    /// from the owner, or for an instance with no live owner, drains in place; any other thread
    /// queues the drain on the owner and waits for it.
    pub fn drain_deallocations(&self, instance: usize) -> Result<usize, AllocError> {
        self.on_owner(instance, move |this, state| {
            let drained = this.drain_locked(instance, state)?;
            let count = drained.len();
            this.clear_routes(drained);
            this.publish_transfers(instance, state)?;
            Ok(count)
        })
    }

    /// Runs the requests other threads queued for `instance` and up to
    /// [`OWNER_WORK_DD_LIMIT`] delayed frees; true when more frees remain.
    ///
    /// Port of the `ERTS_SSI_AUX_WORK_DD` handler (`erts_alloc_handle_delayed_dealloc`,
    /// erl_alloc.c) and of `erts_alloc_notify_delayed_dealloc`, OTP-29.1.1: the owner calls this
    /// from its aux work and is notified again while queued frees remain.
    pub fn handle_owner_work(&self, instance: usize) -> Result<bool, AllocError> {
        self.shared[instance]
            .work_scheduled
            .store(false, Ordering::Release);
        self.run_owner_requests(instance);
        let mut state = self.lock_instance(instance);
        let drained = self.drain_limited(instance, &mut state, OWNER_WORK_DD_LIMIT)?;
        self.clear_routes(drained);
        self.publish_transfers(instance, &mut state)?;
        drop(state);
        let more = !self.delayed[instance].is_empty();
        if more {
            self.schedule_owner_work(instance);
        }
        Ok(more)
    }

    /// Runs the requests other threads queued for `instance`, without handling delayed frees.
    pub fn run_owner_requests(&self, instance: usize) {
        while let Some(request) = self.shared[instance].requests.pop() {
            request(self);
        }
    }

    fn schedule_owner_work(&self, instance: usize) {
        if !self.shared[instance]
            .work_scheduled
            .swap(true, Ordering::AcqRel)
        {
            notify_owner(instance);
        }
    }

    fn owned_by_other_thread(&self, instance: usize) -> bool {
        self.thread_specific
            && instance != 0
            && self.current_instance() != instance
            && owner_is_live(instance)
    }

    /// Runs `work` on `instance` the way erts does: in place when the caller owns it or nobody
    /// does, else by the owner, which the caller waits for.
    ///
    /// Port of `request_alloc_info` / `erts_alloc_info` scheduling in erl_alloc.c, OTP-29.1.1.
    fn on_owner<R, F>(&self, instance: usize, work: F) -> R
    where
        F: FnOnce(&Self, &mut Instance) -> R + Send + 'static,
        R: Send + 'static,
    {
        if !self.owned_by_other_thread(instance) {
            let mut state = self.lock_instance(instance);
            return work(self, &mut state);
        }
        let (reply, answer) = mpsc::channel();
        self.shared[instance].requests.push(Box::new(move |this| {
            let mut state = this.lock_instance(instance);
            let _ = reply.send(work(this, &mut state));
        }));
        self.schedule_owner_work(instance);
        let own = ALC_IX.with(Cell::get);
        let mut waited = 0u32;
        loop {
            match answer.recv_timeout(OWNER_WAIT_SLICE) {
                Ok(result) => return result,
                Err(RecvTimeoutError::Disconnected) => {
                    panic!("allocator owner request dropped without a result")
                }
                Err(RecvTimeoutError::Timeout) => {}
            }
            if own != 0 {
                crate::typed::run_owner_requests(own);
            }
            if !owner_is_live(instance) {
                self.run_owner_requests(instance);
            } else {
                waited += 1;
                if waited.is_multiple_of(50) {
                    notify_owner(instance);
                }
            }
        }
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

    /// Returns the allocator instance of the calling thread: the one it registered, else 0.
    ///
    /// Port of `erts_get_thr_alloc_ix` in erl_alloc.h, OTP-29.1.1. A registered number beyond this
    /// allocator's instance count also maps to 0.
    #[inline]
    pub fn current_instance(&self) -> usize {
        if !self.thread_specific {
            return 0;
        }
        let ix = ALC_IX.with(Cell::get);
        if ix < self.instances.len() { ix } else { 0 }
    }

    /// Current size of allocated blocks across this allocator's instances.
    ///
    /// Port of `erts_alcu_foreign_size` (erl_alloc_util.c, OTP-29.1.1), which reads the size
    /// counters of another thread's instance without a lock: each owner publishes them when it
    /// releases its instance.
    // Port of erts/emulator/beam/erl_alloc_util.c:5952 (erts_alcu_current_size), OTP-29.1.1.
    pub(crate) fn current_blocks_size(&self) -> usize {
        self.shared
            .iter()
            .map(|shared| shared.blocks_size.load(Ordering::Relaxed))
            .sum()
    }

    /// Returns allocator information with the shared `{mbcs_pool, ...}` section.
    ///
    /// Gathered on the owner of `instance`; see [`ThreadSpecificAllocators::drain_deallocations`].
    pub fn info(&self, instance: usize) -> AllocatorInfo {
        let mut info = self.on_owner(instance, |_, state| state.allocator.info());
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
    fn lock_instance(&self, instance: usize) -> InstanceGuard<'_> {
        InstanceGuard {
            guard: self.instances[instance].lock(),
            shared: &self.shared[instance],
        }
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
        self.drain_limited(instance, state, usize::MAX)
    }

    fn drain_limited(
        &self,
        instance: usize,
        state: &mut Instance,
        limit: usize,
    ) -> Result<Vec<InstanceAllocation>, AllocError> {
        let mut drained = Vec::new();
        let queue = &self.delayed[instance];
        while drained.len() < limit
            && let Some((handle, allocation)) = queue.pop()
        {
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
    use std::thread;

    /// Registration is process wide, so tests that register threads must not overlap.
    static REGISTRATION: Mutex<()> = Mutex::new(());

    fn registration() -> std::sync::MutexGuard<'static, ()> {
        REGISTRATION
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn four_instances() -> Arc<ThreadSpecificAllocators> {
        Arc::new(ThreadSpecificAllocators::new(
            4,
            true,
            Strategy::AoffCbf,
            AllocUtilOptions::default(),
        ))
    }

    #[test]
    fn unregistered_threads_use_instance_zero() {
        let allocators = four_instances();
        for _ in 0..3 {
            let worker_allocators = Arc::clone(&allocators);
            let handle = thread::spawn(move || {
                let handle = worker_allocators.alloc(24).unwrap();
                worker_allocators.free(handle).unwrap();
                handle.instance()
            })
            .join()
            .unwrap();
            assert_eq!(handle, 0);
        }
        assert_eq!(allocators.current_instance(), 0);
    }

    #[test]
    fn registered_scheduler_thread_gets_its_own_instance() {
        let _serial = registration();
        let allocators = four_instances();
        for no in [3, 1, 2] {
            let worker_allocators = Arc::clone(&allocators);
            let (registered, current, instance) = thread::spawn(move || {
                let registered = register_thread(ThreadKind::Scheduler(no));
                let handle = worker_allocators.alloc(24).unwrap();
                worker_allocators.free(handle).unwrap();
                (
                    registered,
                    worker_allocators.current_instance(),
                    handle.instance(),
                )
            })
            .join()
            .unwrap();
            assert_eq!(registered, Ok(no));
            assert_eq!(current, no);
            assert_eq!(instance, no);
        }
    }

    #[test]
    fn scheduler_beyond_instance_count_falls_back_to_zero() {
        let _serial = registration();
        let allocators = four_instances();
        let worker_allocators = Arc::clone(&allocators);
        let instance = thread::spawn(move || {
            register_thread(ThreadKind::Scheduler(7)).unwrap();
            let handle = worker_allocators.alloc(24).unwrap();
            worker_allocators.free(handle).unwrap();
            handle.instance()
        })
        .join()
        .unwrap();
        assert_eq!(instance, 0);
    }

    #[test]
    fn duplicate_scheduler_registration_is_rejected() {
        let _serial = registration();
        let owner_ready = Arc::new(Barrier::new(2));
        let second_done = Arc::new(Barrier::new(2));
        let owner = {
            let (owner_ready, second_done) = (Arc::clone(&owner_ready), Arc::clone(&second_done));
            thread::spawn(move || {
                assert_eq!(register_thread(ThreadKind::Scheduler(2)), Ok(2));
                assert_eq!(
                    register_thread(ThreadKind::Scheduler(3)),
                    Err(RegisterError::AlreadyRegistered)
                );
                owner_ready.wait();
                second_done.wait();
            })
        };
        owner_ready.wait();
        let second = thread::spawn(|| {
            let taken = register_thread(ThreadKind::Scheduler(2));
            let other = register_thread(ThreadKind::Scheduler(3));
            (taken, other)
        })
        .join()
        .unwrap();
        assert_eq!(second, (Err(RegisterError::InstanceTaken(2)), Ok(3)));
        second_done.wait();
        owner.join().unwrap();
        let reused = thread::spawn(|| register_thread(ThreadKind::Scheduler(2)))
            .join()
            .unwrap();
        assert_eq!(reused, Ok(2));
        let zero = thread::spawn(|| register_thread(ThreadKind::Scheduler(0)))
            .join()
            .unwrap();
        assert_eq!(zero, Err(RegisterError::InvalidNumber));
    }

    #[test]
    fn dirty_threads_share_instance_zero() {
        let _serial = registration();
        let allocators = four_instances();
        let workers: Vec<_> = [
            ThreadKind::DirtyCpu(1),
            ThreadKind::DirtyCpu(2),
            ThreadKind::DirtyIo(1),
        ]
        .into_iter()
        .map(|kind| {
            let worker_allocators = Arc::clone(&allocators);
            thread::spawn(move || {
                assert_eq!(register_thread(kind), Ok(0));
                let handle = worker_allocators.alloc(24).unwrap();
                worker_allocators.free(handle).unwrap();
                handle.instance()
            })
        })
        .collect();
        for worker in workers {
            assert_eq!(worker.join().unwrap(), 0);
        }
    }

    #[test]
    fn owner_notifier_is_called_with_the_instance() {
        static NOTIFIED: AtomicUsize = AtomicUsize::new(usize::MAX);
        notify_owner(2);
        assert_eq!(NOTIFIED.load(Ordering::Relaxed), usize::MAX);
        assert!(set_owner_notifier(|instance| {
            NOTIFIED.store(instance, Ordering::Relaxed);
        }));
        assert!(!set_owner_notifier(|_| {}));
        notify_owner(3);
        assert_eq!(NOTIFIED.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn cross_instance_free_is_delayed_until_owner_drains() {
        let allocators = Arc::new(ThreadSpecificAllocators::new(
            2,
            true,
            Strategy::AoffCbf,
            AllocUtilOptions::default(),
        ));
        let _serial = registration();
        let allocation = allocators.alloc(24).unwrap();
        let owner = allocation.instance;
        assert_eq!(owner, 0);
        let barrier = Arc::new(Barrier::new(2));
        let worker_allocators = Arc::clone(&allocators);
        let worker_barrier = Arc::clone(&barrier);
        let worker = thread::spawn(move || {
            assert_eq!(register_thread(ThreadKind::Scheduler(1)), Ok(1));
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

    fn within<T: Send + 'static>(
        timeout: Duration,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Option<T> {
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let _ = sender.send(work());
        });
        receiver.recv_timeout(timeout).ok()
    }

    #[test]
    fn blocks_size_and_dyn_sbct_do_not_lock_instances() {
        let allocators = four_instances();
        let live = allocators.alloc(1000).unwrap();
        let held = [allocators.lock_instance(0), allocators.lock_instance(1)];
        let worker_allocators = Arc::clone(&allocators);
        let result = within(Duration::from_secs(2), move || {
            let size = worker_allocators.current_blocks_size();
            let accepted = worker_allocators.try_set_dyn_sbct(8192);
            (size, accepted)
        });
        drop(held);
        let (size, accepted) = result.expect("gathering waited for an instance lock");
        assert!(size >= 1000, "blocks size {size}");
        assert!(accepted);
        allocators.free(live).unwrap();
        assert_eq!(allocators.current_blocks_size(), 0);
    }

    #[test]
    fn dyn_sbct_applies_to_the_next_allocation_of_every_instance() {
        let allocators = four_instances();
        let before = allocators.alloc(10_000).unwrap();
        assert_eq!(allocators.info(0).sbcs.blocks, 0);
        assert!(!allocators.try_set_dyn_sbct(100));
        assert!(allocators.try_set_dyn_sbct(8192));
        let after = allocators.alloc(10_000).unwrap();
        let info = allocators.info(0);
        assert_eq!(info.sbcs.blocks, 1);
        assert_eq!(info.options.sbct, 8192);
        allocators.free(before).unwrap();
        allocators.free(after).unwrap();
    }

    #[test]
    fn info_and_drain_for_scheduler_instance_run_on_the_owner() {
        let _serial = registration();
        let allocators = four_instances();
        let (ready_sender, ready) = mpsc::channel();
        let (go_sender, go) = mpsc::channel::<()>();
        let (stop_sender, stop) = mpsc::channel::<()>();
        let owner = {
            let allocators = Arc::clone(&allocators);
            thread::spawn(move || {
                assert_eq!(register_thread(ThreadKind::Scheduler(1)), Ok(1));
                let handles: Vec<_> = (0..3).map(|_| allocators.alloc(24).unwrap()).collect();
                ready_sender.send(handles).unwrap();
                go.recv().unwrap();
                while stop.try_recv().is_err() {
                    allocators.handle_owner_work(1).unwrap();
                    thread::sleep(Duration::from_micros(100));
                }
            })
        };
        let handles = ready.recv().unwrap();
        let worker_allocators = Arc::clone(&allocators);
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let info = worker_allocators.info(1);
            sender
                .send((info.instance, info.calls.alloc_calls))
                .unwrap();
        });
        assert!(
            receiver.recv_timeout(Duration::from_millis(300)).is_err(),
            "info answered before the owner ran its work"
        );
        go_sender.send(()).unwrap();
        assert_eq!(receiver.recv_timeout(Duration::from_secs(5)), Ok((1, 3)));

        allocators.free(handles[0]).unwrap();
        allocators.free(handles[1]).unwrap();
        assert!(allocators.drain_deallocations(1).unwrap() <= 2);
        assert_eq!(allocators.pending_deallocations(1), 0);
        stop_sender.send(()).unwrap();
        owner.join().unwrap();
        assert_eq!(allocators.info(1).mbcs.blocks, 1);
        allocators.free(handles[2]).unwrap();
    }

    #[test]
    fn owner_work_drains_a_bounded_number_of_frees_and_asks_again() {
        let _serial = registration();
        let allocators = four_instances();
        let (ready_sender, ready) = mpsc::channel();
        let (done_sender, done) = mpsc::channel::<()>();
        let owner = {
            let allocators = Arc::clone(&allocators);
            thread::spawn(move || {
                assert_eq!(register_thread(ThreadKind::Scheduler(1)), Ok(1));
                let handles: Vec<_> = (0..25).map(|_| allocators.alloc(24).unwrap()).collect();
                ready_sender.send(handles).unwrap();
                done.recv().unwrap();
                let first = allocators.handle_owner_work(1).unwrap();
                let left = allocators.pending_deallocations(1);
                let second = allocators.handle_owner_work(1).unwrap();
                (first, left, second, allocators.pending_deallocations(1))
            })
        };
        let handles = ready.recv().unwrap();
        for handle in handles {
            allocators.free(handle).unwrap();
        }
        assert_eq!(allocators.pending_deallocations(1), 25);
        done_sender.send(()).unwrap();
        assert_eq!(owner.join().unwrap(), (true, 5, false, 0));
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
        let _serial = registration();
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
            assert_eq!(register_thread(ThreadKind::Scheduler(1)), Ok(1));
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
