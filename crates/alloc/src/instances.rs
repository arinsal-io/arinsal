//! Scheduler-local allocator instances, delayed frees, and shared MBC carriers.

use crate::alloc_util::{
    AllocError, AllocUtil, AllocUtilOptions, Allocation, AllocatorInfo, CRR_ALCTR_FLG_IN_POOL,
    CarrierPoolStats, CarrierTransfer, Strategy, get_used_allctr, set_dyn_sbct,
};
use crate::ddq::{DdHead, DdStatus, DdTail, node_info};
use crate::raw::WordView;
use std::cell::{Cell, RefCell, UnsafeCell};
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
    if CLAIM.with(|claim| claim.borrow().is_some()) || thread_alloc_ix() != 0 {
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
    let scheduler = if matches!(kind, ThreadKind::Scheduler(_)) {
        NORMAL_SCHEDULER_BIT
    } else {
        0
    };
    ALC_IX.with(|current| current.set(ix | scheduler));
    Ok(ix)
}

/// The allocator instance index the calling thread registered, 0 for a thread that did not.
///
/// Port of `erts_get_thr_alloc_ix` in erl_alloc.h, OTP-29.1.1. A scheduler reads this once and
/// hands the value down to the `*_at` allocation calls, the way erts passes `esdp->no` instead of
/// looking the scheduler up on every allocation.
#[inline]
pub fn thread_alloc_ix() -> usize {
    ALC_IX.with(Cell::get) & !NORMAL_SCHEDULER_BIT
}

/// Whether the calling thread is a normal scheduler eligible for scheduler-preferred pools.
pub fn thread_is_scheduler() -> bool {
    ALC_IX.with(Cell::get) & NORMAL_SCHEDULER_BIT != 0
}

/// [`thread_alloc_ix`] and [`thread_is_scheduler`] from one read of the thread's word, for the
/// message-reference paths that need both on every call.
#[inline]
pub fn thread_alloc_ix_and_scheduler() -> (usize, bool) {
    let word = ALC_IX.with(Cell::get);
    (
        word & !NORMAL_SCHEDULER_BIT,
        word & NORMAL_SCHEDULER_BIT != 0,
    )
}

/// Set in a normal scheduler's thread word, above any allocator index.
const NORMAL_SCHEDULER_BIT: usize = 1 << 32;

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
    /// `allctr->fix`: the free lists of the fixed-size types this instance serves.
    fix: Vec<FixList>,
    /// The dequeue side of the instance's delayed-dealloc queue (`ddq->head`).
    ddq: DdHead,
}

/// Number of fixed-size allocation types (`ERTS_ALC_NO_FIXED_SIZES`) the port knows.
pub const FIX_TYPES: usize = 5;

/// Longest free list of one fixed-size type.
///
/// Port of erts/emulator/beam/erl_alloc_util.c (`ERTS_ALCU_FIX_MAX_LIST_SZ`), OTP-29.1.1.
const FIX_MAX_LIST_SIZE: usize = 1000;

/// Free list of one fixed-size type in one instance.
///
/// Port of erts/emulator/beam/erl_alloc_util.h (`ErtsAlcFixList_t`, the `cpool` variant),
/// OTP-29.1.1. erts threads the list through the first word of each free block; the blocks here
/// are named by their allocation, so the list keeps those.
#[derive(Default)]
struct FixList {
    /// `type_size`: zero until the type is first allocated.
    type_size: usize,
    /// Intrusive `fix->list` head, linked through the first payload word.
    list: usize,
    list_size: usize,
    min_list_size: usize,
    /// `u.cpool.shrink_list`: blocks still to give back to the carriers.
    shrink_list: usize,
    used: usize,
    allocated: usize,
}

/// A request another thread asks the owner of an instance to run.
type OwnerRequest = Box<dyn FnOnce(&ThreadSpecificAllocators, &mut Instance) + Send>;

/// Delayed frees handled per owner-work pass.
///
/// Port of `ERTS_ALCU_DD_OPS_LIM_HIGH` in erl_alloc_util.c, OTP-29.1.1.
const OWNER_WORK_DD_LIMIT: usize = 20;

/// Delayed frees handled by an allocation or free on the owner (`ERTS_ALCU_HANDLE_DD_IN_OP`).
///
/// Port of `ERTS_ALCU_DD_OPS_LIM_LOW` in erl_alloc_util.c, OTP-29.1.1.
const DD_OPS_LIM_LOW: usize = 2;

/// Bit of a queued block's info word where its size starts; below it is its fixed-size type.
const FIX_INFO_SHIFT: usize = 8;

/// The type field of a queued block that is not of a fixed-size type: it goes back to its
/// carrier, not to a fix list (erts `handle_delayed_dealloc` tells the two apart by the
/// `ERTS_ALC_FIX_TYPE` flag of the block's `type` word).
const NOT_FIX: usize = (1 << FIX_INFO_SHIFT) - 1;

/// How long a requester waits for its owner before it asks the owner again.
const OWNER_WAIT_SLICE: Duration = Duration::from_micros(200);

/// What other threads may read or write about an instance without taking it.
///
/// The counters are single-writer mirrors the owner refreshes whenever it releases the instance,
/// like the size words erts reads in `erts_alcu_foreign_size` (erl_alloc_util.c, OTP-29.1.1); the
/// threshold is the `sbc_threshold` word `erts_alloc_set_dyn_param` writes.
struct Shared {
    sbct: Arc<AtomicUsize>,
    strategy: Strategy,
    /// Requests other threads queued for the owner (erts `misc_aux_work` jobs), and their count
    /// so the owner tests for work without taking the lock.
    requests: Mutex<std::collections::VecDeque<OwnerRequest>>,
    request_count: AtomicUsize,
    work_scheduled: AtomicBool,
}

/// The allocator state of one instance, reachable through a shared reference.
///
/// Port of the `thread_safe` split of `erts_alcu_alloc_thr_pref` and friends (erl_alloc_util.c,
/// OTP-29.1.1): erts creates scheduler instances with `thread_safe = 0`, so their owner touches
/// them without a lock, and creates instance 0 (and the dirty instances) with `thread_safe = 1`.
/// Access follows the same split:
///
/// * instance 0, the dirty instances and every instance of a non thread specific allocator: under
///   [`Slot::lock`];
/// * a scheduler instance: by its owner thread alone, with no lock. A thread that is not the owner
///   touches it only while it holds the [`CLAIMED`] set and the number is not in it, which keeps
///   any thread from becoming the owner meanwhile.
struct OwnerCell(UnsafeCell<Instance>);

// SAFETY: the cell is only dereferenced under one of the two exclusion rules documented on
// `OwnerCell`, so at most one thread has a reference to the `Instance` at any time, and
// `Instance` (an `AllocUtil`) is `Send`.
#[allow(unsafe_code)]
unsafe impl Sync for OwnerCell {}

/// An instance with its lock, and the instance's current block size words for readers on other
/// threads.
#[repr(C, align(128))]
struct Slot {
    blocks_size: Arc<[AtomicUsize; 2]>,
    lock: parking_lot::Mutex<()>,
    state: OwnerCell,
}

/// Exclusive access to an instance.
struct InstanceGuard<'a> {
    state: &'a mut Instance,
    _lock: Option<parking_lot::MutexGuard<'a, ()>>,
}

impl std::ops::Deref for InstanceGuard<'_> {
    type Target = Instance;

    #[inline(always)]
    fn deref(&self) -> &Instance {
        self.state
    }
}

impl std::ops::DerefMut for InstanceGuard<'_> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Instance {
        self.state
    }
}

/// True when the calling thread registered as the owner of scheduler instance `instance`.
fn owns_instance(instance: usize) -> bool {
    CLAIM
        .try_with(|claim| {
            claim
                .borrow()
                .as_ref()
                .is_some_and(|claim| claim.0 == instance)
        })
        .unwrap_or(false)
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

    pub(crate) fn from_payload(instance: usize, payload: *mut u64, size: usize) -> Self {
        // Port of erts/emulator/beam/erl_alloc_util.h:432 (ABLK_TO_MBC), OTP-29.1.1.
        Self {
            instance,
            allocation: Allocation::from_payload(payload, size),
        }
    }

    pub(crate) fn allocation_id(self) -> u64 {
        self.allocation.id()
    }
}

struct PooledCarrier {
    transfer: CarrierTransfer,
}

struct HomecomingCarrier {
    id: u64,
    transfer: CarrierTransfer,
}

/// Owns allocator instances and the carrier pool between them.
///
/// The owner of a block is read from the `allctr` word of its carrier header, as erts'
/// `get_used_allctr` (erl_alloc_util.c:1736) does: a carrier that changes hands rewrites that word,
/// so no table follows the blocks.
///
/// Port of scheduler-specific allocator, delayed-free, and carrier-pool behavior
/// in `erl_alloc_util.c:2260-2299,3968-4030,4180-4200`, OTP-29.1.1.
pub struct ThreadSpecificAllocators {
    // parking_lot: the uncontended lock is one CAS, on every alloc and free of instance 0.
    instances: Vec<Slot>,
    /// Instances `1..=scheduler_instances` belong to scheduler threads and take no lock.
    scheduler_instances: usize,
    /// Carriers sent back to their origin instance (the `HOMECOMING_MBC_BLK_HDR` entries of
    /// erts' queue), with their count so the common path tests for them without the lock.
    homecoming_ids: Vec<Mutex<Vec<u64>>>,
    homecoming_count: Vec<AtomicUsize>,
    /// The enqueue side of each instance's delayed-dealloc queue, whose nodes are the freed
    /// blocks (`allctr->dd.q`); the dequeue side is in the instance.
    /// Never resized: a queue's marker address is its empty value.
    ddq: Vec<DdTail>,
    shared: Vec<Shared>,
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
                let mut allocator = AllocUtil::new_for_instance(
                    if thread_specific && instance == 0 {
                        global_strategy
                    } else {
                        strategy
                    },
                    options,
                    allocation_type,
                    instance,
                    true,
                );
                // Port of the `ix != 0 || init->mmbc0` condition in `erts_alcu_start`,
                // erl_alloc_util.c:6927-6944, OTP-29.1.1. `mmbc0` defaults on in
                // `ERTS_AU_INIT__`; `set_default_ets_alloc_opts` alone clears it (erl_alloc.c:402-412).
                if instance != 0 || allocation_type != "ets_alloc" {
                    allocator
                        .initialize_main_carrier()
                        .expect("failed to create allocator main carrier");
                }
                allocator
            })
            .collect();
        let shared = allocators
            .iter()
            .enumerate()
            .map(|(instance, allocator)| Shared {
                sbct: allocator.sbct_cell(),
                strategy: if thread_specific && instance == 0 {
                    global_strategy
                } else {
                    strategy
                },
                requests: Mutex::new(std::collections::VecDeque::new()),
                request_count: AtomicUsize::new(0),
                work_scheduled: AtomicBool::new(false),
            })
            .collect();
        let ddq: Vec<DdTail> = (0..count).map(|_| DdTail::new()).collect();
        for tail in &ddq {
            tail.init();
        }
        let progress = crate::sspa::progress_ops();
        Self {
            scheduler_instances: if thread_specific {
                crate::typed::configured()
                    .map_or(count - 1, |(schedulers, _)| schedulers)
                    .min(count - 1)
            } else {
                0
            },
            instances: allocators
                .into_iter()
                .enumerate()
                .map(|(instance, allocator)| Slot {
                    blocks_size: allocator.blocks_size_cell(),
                    lock: parking_lot::Mutex::new(()),
                    state: OwnerCell(UnsafeCell::new(Instance {
                        allocator,
                        fix: (0..FIX_TYPES).map(|_| FixList::default()).collect(),
                        ddq: DdHead::new(&ddq[instance], progress),
                    })),
                })
                .collect(),
            shared,
            homecoming_ids: (0..count).map(|_| Mutex::new(Vec::new())).collect(),
            homecoming_count: (0..count).map(|_| AtomicUsize::new(0)).collect(),
            ddq,
            carrier_pool: Mutex::new(Vec::new()),
            pooled: AtomicUsize::new(0),
            homecomings: Mutex::new(Vec::new()),
            next_pool_id: Mutex::new(1),
            pool_stats: Mutex::new(CarrierPoolStats::default()),
            thread_specific,
        }
    }

    /// Instances `1..=n` owned by scheduler threads.
    pub fn scheduler_instance_count(&self) -> usize {
        self.scheduler_instances
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
    #[inline]
    pub fn alloc_with_ptr(
        &self,
        size: usize,
    ) -> Result<(InstanceAllocation, *mut u64), AllocError> {
        self.alloc_with_ptr_at(thread_alloc_ix(), size)
    }

    /// [`ThreadSpecificAllocators::alloc_with_ptr`] for a caller that already knows its thread's
    /// allocator index (see [`thread_alloc_ix`]), so no thread-local read is needed.
    ///
    /// `ix` must be the index of the calling thread; any other value allocates on an instance the
    /// caller does not own, which a debug build rejects.
    pub fn alloc_with_ptr_at(
        &self,
        ix: usize,
        size: usize,
    ) -> Result<(InstanceAllocation, *mut u64), AllocError> {
        let instance = self.instance_for(ix);
        debug_assert_eq!(instance, self.current_instance());
        let mut state = self.lock_instance(instance);
        if self.has_delayed(instance, &state) {
            self.drain_delayed_and_publish(instance, &mut state)?;
        }
        debug_assert!(!state.allocator.has_pending_carriers());
        if self.pooled.load(Ordering::Acquire) != 0 && state.allocator.needs_carrier(size)? {
            self.fetch_for_size(&mut state, size)?;
        }
        let allocation = state.allocator.alloc(size)?;
        let ptr = state.allocator.payload_address(allocation);
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
    ///
    /// Port of `erts_alcu_realloc_thr_pref` (erl_alloc_util.c), OTP-29.1.1: a block owned by the
    /// calling thread's instance is resized in place; a block owned by another instance is
    /// allocated afresh on the calling thread's instance, copied, and the old block is queued
    /// on its owner without taking the owner's lock.
    pub fn realloc_with_ptr(
        &self,
        handle: InstanceAllocation,
        size: usize,
    ) -> Result<(InstanceAllocation, *mut u64), AllocError> {
        let current = self.current_instance();
        let allocation = handle.allocation;
        let used = get_used_allctr(allocation.payload_address());
        if used.instance != current {
            return self.realloc_foreign(handle, allocation, size);
        }
        let mut state = self.lock_instance(current);
        self.drain_and_publish(current, &mut state)?;
        if used.flags != 0 && self.used_allctr(current, &mut state, allocation)? != current {
            drop(state);
            return self.realloc_foreign(handle, allocation, size);
        }
        let resized = state.allocator.realloc(allocation, size)?;
        let ptr = state.allocator.payload_address(resized);
        self.publish_transfers(current, &mut state)?;
        Ok((
            InstanceAllocation {
                instance: current,
                allocation: resized,
            },
            ptr,
        ))
    }

    /// Moves a block owned by another instance to the calling thread's instance.
    ///
    /// Port of the `used_allctr != pref_allctr` branch of `erts_alcu_realloc_thr_pref`
    /// (erl_alloc_util.c), OTP-29.1.1: allocate in the caller's instance, copy the smaller of
    /// the two sizes, then free the old block, which queues it on its owner.
    fn realloc_foreign(
        &self,
        handle: InstanceAllocation,
        old: Allocation,
        size: usize,
    ) -> Result<(InstanceAllocation, *mut u64), AllocError> {
        let (new_handle, new_ptr) = self.alloc_with_ptr(size)?;
        let copy = size.min(old.size());
        // The caller owns the live old block and the new block is exclusive to this thread.
        let source = WordView::new(old.payload_address() as *mut u64, copy.div_ceil(8));
        let mut target = WordView::new(new_ptr, copy.div_ceil(8));
        target.bytes_mut()[..copy].copy_from_slice(&source.bytes()[..copy]);
        self.free(handle)?;
        Ok((new_handle, new_ptr))
    }

    /// Frees immediately on the current instance or queues the free for its owner.
    /// Port of erl_alloc_util.c:6216 (erts_alcu_free_thr_pref) delayed-dealloc enqueue, OTP-29.1.1.
    #[inline]
    pub fn free(&self, handle: InstanceAllocation) -> Result<(), AllocError> {
        self.free_at(thread_alloc_ix(), handle)
    }

    /// [`ThreadSpecificAllocators::free`] for a caller that already knows its thread's allocator
    /// index (see [`thread_alloc_ix`]).
    ///
    /// `ix` must be the index of the calling thread; a debug build rejects any other value.
    #[inline]
    pub fn free_at(&self, ix: usize, handle: InstanceAllocation) -> Result<(), AllocError> {
        self.free_thr_pref(ix, NOT_FIX, handle.allocation)
    }

    /// Frees `allocation` from the thread with allocator index `ix`: the owner frees it at once
    /// (fixed-size blocks of type `fix_ix` go through its free list), any other thread queues it
    /// for the owner without taking the owner's lock.
    ///
    /// Port of erl_alloc_util.c:6216 (erts_alcu_free_thr_pref) with `get_used_allctr` and, for
    /// a fixed-size type, `fix_cpool_free`, OTP-29.1.1.
    #[inline(always)]
    fn free_thr_pref(
        &self,
        ix: usize,
        fix_ix: usize,
        allocation: Allocation,
    ) -> Result<(), AllocError> {
        let current = self.instance_for(ix);
        debug_assert_eq!(current, self.current_instance());
        let used = get_used_allctr(allocation.payload_address());
        if used.instance != current {
            self.enqueue_fix(used.instance, current, fix_ix, allocation);
            return Ok(());
        }
        let mut state = self.lock_instance(current);
        if used.flags != 0 {
            let owner = self.used_allctr(current, &mut state, allocation)?;
            if owner != current {
                drop(state);
                self.enqueue_fix(owner, current, fix_ix, allocation);
                return Ok(());
            }
        }
        if fix_ix == NOT_FIX {
            state.allocator.free(allocation)?;
        } else {
            fix_free_owned(&mut state, fix_ix, allocation)?;
        }
        self.publish_transfers(current, &mut state)
    }

    /// Writes bytes into the payload of a live block.
    ///
    /// Handles are block addresses, so no instance is consulted and no lock is taken; the
    /// caller owns the live block, as with a pointer into an erts block.
    pub fn write(
        &self,
        handle: InstanceAllocation,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), AllocError> {
        let end = payload_range(handle, offset, bytes.len())?;
        let mut view = payload_view(handle);
        view.bytes_mut()[offset..end].copy_from_slice(bytes);
        Ok(())
    }

    /// Reads bytes from the payload of a live block, without consulting any instance.
    pub fn read(
        &self,
        handle: InstanceAllocation,
        offset: usize,
        out: &mut [u8],
    ) -> Result<(), AllocError> {
        let end = payload_range(handle, offset, out.len())?;
        out.copy_from_slice(&payload_view(handle).bytes()[offset..end]);
        Ok(())
    }

    /// Returns the payload address of a live block, without consulting any instance.
    pub fn allocation_ptr(&self, handle: InstanceAllocation) -> Result<*mut u64, AllocError> {
        Ok(handle.allocation.payload_address() as *mut u64)
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
            let mut count = 0;
            let progress = crate::sspa::progress_ops();
            let tail = &this.ddq[instance];
            loop {
                let (freed, _) = this.drain_limited(instance, state, usize::MAX, true)?;
                count += freed;
                if !tail.pending(&state.ddq) || !state.ddq.can_advance(tail, progress) {
                    break;
                }
            }
            this.publish_transfers(instance, state)?;
            Ok(count)
        })
    }

    /// Runs one unbounded delayed-deallocation pass and reports the follow-up work it needs.
    ///
    /// Port of `erts_alcu_check_delayed_dealloc` and `handle_delayed_dealloc` in
    /// erl_alloc_util.c, OTP-29.1.1. The caller must re-arm owner work after thread progress when
    /// `need_thr_progress` is set; repeating the pass immediately cannot advance `unref_end`.
    pub fn flush_deallocations(&self, instance: usize) -> Result<DdStatus, AllocError> {
        self.on_owner(instance, move |this, state| {
            let (_, status) = this.drain_limited(instance, state, usize::MAX, true)?;
            this.publish_transfers(instance, state)?;
            Ok(status)
        })
    }

    /// Runs the requests other threads queued for `instance` and up to
    /// [`OWNER_WORK_DD_LIMIT`] delayed frees; the result tells whether frees remain behind the
    /// limit and whether queued blocks wait for thread progress.
    ///
    /// Port of the `ERTS_SSI_AUX_WORK_DD` handler (`erts_alloc_handle_delayed_dealloc`,
    /// erl_alloc.c) and of `erts_alloc_notify_delayed_dealloc`, OTP-29.1.1: the owner calls this
    /// from its aux work and is notified again while queued frees remain. A thread that does not
    /// own a scheduler instance does nothing.
    pub fn handle_owner_work(&self, instance: usize) -> Result<DdStatus, AllocError> {
        if self.lock_free(instance) && thread_alloc_ix() != instance {
            return Ok(DdStatus::default());
        }
        self.shared[instance]
            .work_scheduled
            .store(false, Ordering::Release);
        let mut state = self.lock_instance(instance);
        self.run_requests_on(instance, &mut state);
        let (_, mut status) =
            self.drain_limited(instance, &mut state, OWNER_WORK_DD_LIMIT, true)?;
        self.publish_transfers(instance, &mut state)?;
        drop(state);
        status.more_work |= self.homecoming_count[instance].load(Ordering::Relaxed) != 0;
        if status.more_work {
            self.schedule_owner_work(instance);
        }
        Ok(status)
    }

    /// Runs the requests other threads queued for `instance`, without handling delayed frees.
    ///
    /// Does nothing for a scheduler instance the calling thread does not own.
    pub fn run_owner_requests(&self, instance: usize) {
        if self.shared[instance].request_count.load(Ordering::Acquire) == 0
            || (self.lock_free(instance) && thread_alloc_ix() != instance)
        {
            return;
        }
        let mut state = self.lock_instance(instance);
        self.run_requests_on(instance, &mut state);
    }

    fn run_requests_on(&self, instance: usize, state: &mut Instance) {
        let shared = &self.shared[instance];
        while shared.request_count.load(Ordering::Acquire) != 0 {
            let request = shared
                .requests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop_front();
            let Some(request) = request else { break };
            shared.request_count.fetch_sub(1, Ordering::AcqRel);
            request(self, state);
        }
    }

    fn schedule_owner_work(&self, instance: usize) {
        // Port of erts/emulator/beam/erl_alloc_util.c (enqueue_dealloc_other_instance): erts
        // notifies the owner only when `ddq_enqueue` found its queue idle. Test first, so a
        // delayed free while the request is pending does not write the shared flag again.
        let flag = &self.shared[instance].work_scheduled;
        if !flag.load(Ordering::Acquire) && !flag.swap(true, Ordering::AcqRel) {
            notify_owner(instance);
        }
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
        if !self.lock_free(instance) || thread_alloc_ix() == instance {
            let mut state = self.lock_instance(instance);
            return work(self, &mut state);
        }
        let mut work = Some(work);
        let (reply, answer) = mpsc::channel();
        {
            let claims = CLAIMED
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !claims.contains(&instance) {
                let mut state = self.lock_unowned(instance, &claims);
                let work = work.take().expect("work runs once");
                return work(self, &mut state);
            }
            let work = work.take().expect("work runs once");
            let shared = &self.shared[instance];
            shared
                .requests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push_back(Box::new(move |this, state| {
                    let _ = reply.send(work(this, state));
                }));
            shared.request_count.fetch_add(1, Ordering::AcqRel);
        }
        self.schedule_owner_work(instance);
        let own = thread_alloc_ix();
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
            let claims = CLAIMED
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if claims.contains(&instance) {
                drop(claims);
                waited += 1;
                if waited.is_multiple_of(50) {
                    notify_owner(instance);
                }
            } else {
                let mut state = self.lock_unowned(instance, &claims);
                self.run_requests_on(instance, &mut state);
            }
        }
    }

    /// Allocates a block of fixed-size type `fix_ix` (`size` bytes) on the instance of the
    /// calling thread, whose allocator index is `ix`, taking it from the type's free list when
    /// the list has one.
    ///
    /// Port of erts/emulator/beam/erl_alloc_util.c (fix_cpool_alloc), OTP-29.1.1.
    pub fn fix_alloc_with_ptr_at(
        &self,
        ix: usize,
        fix_ix: usize,
        size: usize,
    ) -> Result<(InstanceAllocation, *mut u64), AllocError> {
        let instance = self.instance_for(ix);
        debug_assert_eq!(instance, self.current_instance());
        let mut state = self.lock_instance(instance);
        if self.has_delayed(instance, &state) {
            self.drain_delayed_and_publish(instance, &mut state)?;
        }
        let fix = state
            .fix
            .get_mut(fix_ix)
            .ok_or(AllocError::InvalidAllocation)?;
        if fix.type_size == 0 {
            fix.type_size = size;
        }
        // erts fixes the size of each type at boot. A process that hosts schedulers of several
        // task types allocates the other sizes outside the list.
        let listed = fix.type_size == size;
        if listed && let Some(allocation) = fix_list_pop(fix) {
            fix.min_list_size = fix.min_list_size.min(fix.list_size);
            fix.used += 1;
            fix_check_shrink(&mut state, fix_ix)?;
            return Ok((
                InstanceAllocation {
                    instance,
                    allocation,
                },
                allocation.payload_address() as *mut u64,
            ));
        }
        if self.pooled.load(Ordering::Acquire) != 0 && state.allocator.needs_carrier(size)? {
            self.fetch_for_size(&mut state, size)?;
        }
        let allocation = state.allocator.alloc(size)?;
        let ptr = state.allocator.payload_address(allocation);
        if listed {
            let fix = &mut state.fix[fix_ix];
            fix.used += 1;
            fix.allocated += 1;
        }
        Ok((
            InstanceAllocation {
                instance,
                allocation,
            },
            ptr,
        ))
    }

    /// Allocates a fixed-size payload for its owner without constructing a routed block handle.
    #[inline(always)]
    pub fn fix_alloc_payload_at(
        &self,
        ix: usize,
        fix_ix: usize,
        size: usize,
    ) -> Result<*mut u64, AllocError> {
        let instance = self.instance_for(ix);
        debug_assert_eq!(instance, self.current_instance());
        let mut state = self.lock_instance(instance);
        if self.has_delayed(instance, &state) {
            self.drain_and_publish(instance, &mut state)?;
        }
        let fix = state
            .fix
            .get_mut(fix_ix)
            .ok_or(AllocError::InvalidAllocation)?;
        if fix.type_size == 0 {
            fix.type_size = size;
        }
        let listed = fix.type_size == size;
        if listed && fix.list != 0 {
            let payload = fix_list_pop_payload(fix).expect("nonempty fix list");
            fix.min_list_size = fix.min_list_size.min(fix.list_size);
            fix.used += 1;
            fix_check_shrink(&mut state, fix_ix)?;
            return Ok(payload as *mut u64);
        }
        if self.pooled.load(Ordering::Acquire) != 0 && state.allocator.needs_carrier(size)? {
            self.fetch_for_size(&mut state, size)?;
        }
        let allocation = state.allocator.alloc(size)?;
        let payload = state.allocator.payload_address(allocation);
        if listed {
            let fix = &mut state.fix[fix_ix];
            fix.used += 1;
            fix.allocated += 1;
        }
        Ok(payload)
    }

    /// Frees a fixed-size payload of type `fix_ix` (`size` bytes, the type size) from the calling
    /// thread: the instance named by the block's carrier puts it on its free list, any other
    /// thread queues it for that instance.
    ///
    /// Port of erts/emulator/beam/erl_alloc_util.c (erts_alcu_free_thr_pref, get_used_allctr and
    /// fix_cpool_free), OTP-29.1.1.
    #[inline(always)]
    #[allow(unsafe_code)]
    pub(crate) fn fix_free_payload_at(
        &self,
        fix_ix: usize,
        payload: *mut u64,
        size: usize,
    ) -> Result<(), AllocError> {
        let current = self.instance_for(thread_alloc_ix());
        debug_assert_eq!(current, self.current_instance());
        let used = get_used_allctr(payload as usize);
        if used.instance != current || used.flags != 0 {
            return self.free_thr_pref(
                thread_alloc_ix(),
                fix_ix,
                Allocation::from_payload(payload, size),
            );
        }
        let mut state = self.lock_instance(current);
        let fix = state
            .fix
            .get_mut(fix_ix)
            .ok_or(AllocError::InvalidAllocation)?;
        if fix.type_size == 0 {
            return Err(AllocError::InvalidAllocation);
        }
        if fix.type_size != size {
            state
                .allocator
                .free(Allocation::from_payload(payload, size))?;
            return self.publish_transfers(current, &mut state);
        }
        fix.used = fix.used.saturating_sub(1);
        if fix.shrink_list == 0 && fix.list_size < FIX_MAX_LIST_SIZE {
            // SAFETY: this owner holds the live, word-aligned fixed-size payload exclusively.
            unsafe { payload.write(fix.list as u64) };
            fix.list = payload as usize;
            fix.list_size += 1;
            return Ok(());
        }
        let allocation = Allocation::from_payload(payload, size);
        fix.allocated = fix.allocated.saturating_sub(1);
        state.allocator.free(allocation)?;
        fix_check_shrink(&mut state, fix_ix)?;
        self.publish_transfers(current, &mut state)
    }

    /// Frees a block of fixed-size type `fix_ix` from the thread with allocator index `ix`: the
    /// owning instance puts it on its free list, another thread queues it for the owner.
    ///
    /// Port of erts/emulator/beam/erl_alloc_util.c (fix_cpool_free through
    /// erts_alcu_free_thr_pref and handle_delayed_dealloc), OTP-29.1.1.
    pub fn fix_free_at(
        &self,
        ix: usize,
        fix_ix: usize,
        handle: InstanceAllocation,
    ) -> Result<(), AllocError> {
        self.free_thr_pref(ix, fix_ix, handle.allocation)
    }

    /// One shrink pass over the free lists of the calling thread's instance (allocator index
    /// `ix`), run from the owner's aux work.
    pub fn fix_shrink_at(&self, ix: usize, lower_limit: bool) -> Result<FixShrink, AllocError> {
        let instance = self.instance_for(ix);
        let mut state = self.lock_instance(instance);
        let result = fix_shrink_owned(&mut state, lower_limit)?;
        self.publish_transfers(instance, &mut state)?;
        Ok(result)
    }

    /// Blocks of fixed-size type `fix_ix` in use and allocated (in use or on the free list) on
    /// `instance` (`erts_alloc_fix_info` `used` and `allocated`).
    pub fn fix_info(&self, instance: usize, fix_ix: usize) -> (usize, usize) {
        self.on_owner(instance, move |_, state| {
            state
                .fix
                .get(fix_ix)
                .map_or((0, 0), |fix| (fix.used, fix.allocated))
        })
    }

    /// Bytes of fixed-size type `fix_ix` allocated and in use on `instance`: the block counts of
    /// [`ThreadSpecificAllocators::fix_info`] times the type size, as `sz_info_fix` reports them.
    // Port of erts/emulator/beam/erl_alloc_util.c:4897 (sz_info_fix), OTP-29.1.1.
    pub fn fix_bytes(&self, instance: usize, fix_ix: usize) -> (usize, usize) {
        self.on_owner(instance, move |_, state| {
            state.fix.get(fix_ix).map_or((0, 0), |fix| {
                (fix.type_size * fix.allocated, fix.type_size * fix.used)
            })
        })
    }

    /// Returns the number of frees waiting for the instance, fixed-size blocks included.
    #[cfg(test)]
    pub fn pending_deallocations(&self, instance: usize) -> usize {
        self.homecoming_count[instance].load(Ordering::Relaxed) + self.ddq[instance].queued()
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
        self.instance_for(thread_alloc_ix())
    }

    /// The instance a thread with allocator index `ix` allocates on.
    #[inline(always)]
    fn instance_for(&self, ix: usize) -> usize {
        if self.thread_specific && ix < self.instances.len() {
            ix
        } else {
            0
        }
    }

    /// Current size of allocated blocks across this allocator's instances.
    ///
    /// Port of `erts_alcu_foreign_size` (erl_alloc_util.c, OTP-29.1.1), which reads the size
    /// counters of another thread's instance without a lock.
    // Port of erts/emulator/beam/erl_alloc_util.c:5952 (erts_alcu_current_size), OTP-29.1.1.
    pub(crate) fn current_blocks_size(&self) -> usize {
        self.instances
            .iter()
            .map(|slot| {
                slot.blocks_size
                    .iter()
                    .map(|size| size.load(Ordering::Relaxed))
                    .sum::<usize>()
            })
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

    /// Runs queued cross-thread frees and hands abandoned carriers to the pool.
    #[inline(always)]
    fn drain_and_publish(&self, instance: usize, state: &mut Instance) -> Result<(), AllocError> {
        if self.has_delayed(instance, state) {
            self.drain_delayed_and_publish(instance, state)?;
        }
        self.publish_transfers(instance, state)
    }

    /// Whether `instance` has queued frees to look at: blocks of the plain queue, or the
    /// delayed-dealloc queue of fixed-size blocks is not idle (`ddq_check_incoming` has a use).
    #[inline(always)]
    fn has_delayed(&self, instance: usize, state: &Instance) -> bool {
        self.homecoming_count[instance].load(Ordering::Relaxed) != 0
            || self.ddq[instance].pending(&state.ddq)
    }

    #[inline(always)]
    fn drain_delayed_and_publish(
        &self,
        instance: usize,
        state: &mut Instance,
    ) -> Result<(), AllocError> {
        self.drain_limited(instance, state, DD_OPS_LIM_LOW, false)?;
        self.publish_transfers(instance, state)
    }

    /// Queues a freed block on the instance that owns it, using the block as the queue node, and
    /// wakes the owner when the block went to the end of the queue. `fix_ix` is the block's
    /// fixed-size type, or [`NOT_FIX`].
    ///
    /// Port of `enqueue_dealloc_other_instance` and `erts_alcu_free_thr_pref`
    /// (erl_alloc_util.c, OTP-29.1.1): `cinit` is the difference of the two instance numbers
    /// (`used_allctr->dd.ix - pref_allctr->dd.ix`) that spreads racing enqueuers.
    #[inline(always)]
    fn enqueue_fix(&self, instance: usize, current: usize, fix_ix: usize, allocation: Allocation) {
        debug_assert!(fix_ix < 1 << FIX_INFO_SHIFT);
        // The block becomes the queue node, its payload holding the `next` and `info` words: a
        // block is never smaller than `min_block_size`, which holds a free-tree node.
        let info = fix_ix | (allocation.size() << FIX_INFO_SHIFT);
        if self.ddq[instance].enqueue(
            allocation.payload_address(),
            info,
            instance.wrapping_sub(current),
            crate::sspa::progress_ops(),
        ) {
            self.schedule_owner_work(instance);
        }
    }

    /// Queues the carrier `id` for its origin `instance` to take back.
    fn enqueue_homecoming(&self, instance: usize, id: u64) {
        self.homecoming_ids[instance]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(id);
        self.homecoming_count[instance].fetch_add(1, Ordering::Release);
    }

    /// The instance that owns `allocation`'s block, read from its carrier header while the caller
    /// holds `instance`. A carrier of `instance` in the pool or on its way home is taken back first.
    ///
    /// Port of the IN_POOL loop of `get_used_allctr` (erl_alloc_util.c, OTP-29.1.1). Known
    /// deviation: erts sets BUSY on the pooled carrier and frees into it in place; a pooled carrier
    /// here is a detached value, so its origin imports it before it touches the block.
    #[inline]
    fn used_allctr(
        &self,
        instance: usize,
        state: &mut Instance,
        allocation: Allocation,
    ) -> Result<usize, AllocError> {
        let used = get_used_allctr(allocation.payload_address());
        if used.instance != instance || used.flags & CRR_ALCTR_FLG_IN_POOL == 0 {
            return Ok(used.instance);
        }
        self.take_back_carrier(state, used.carrier)?;
        let used = get_used_allctr(allocation.payload_address());
        // The carrier left the pool for another instance before this one took the pool lock;
        // only the origin takes a homecoming carrier, so it cannot still name this instance.
        if used.instance == instance && used.flags & CRR_ALCTR_FLG_IN_POOL != 0 {
            return Err(AllocError::Corrupt);
        }
        Ok(used.instance)
    }

    /// Imports the carrier at address `carrier` from the pool or the homecoming list, if it is
    /// still there.
    ///
    /// Port of `cpool_fetch` and the `HOMECOMING_MBC_BLK_HDR` branch of `handle_delayed_dealloc`
    /// (erl_alloc_util.c, OTP-29.1.1), run by the origin instance.
    #[cold]
    fn take_back_carrier(&self, state: &mut Instance, carrier: usize) -> Result<(), AllocError> {
        let mut pool = self
            .carrier_pool
            .lock()
            .expect("carrier-pool lock poisoned");
        if let Some(index) = pool
            .iter()
            .position(|entry| entry.transfer.carrier_address() == carrier)
        {
            self.pooled.fetch_sub(1, Ordering::AcqRel);
            let transfer = pool.swap_remove(index).transfer;
            // Imported under the pool lock, so the new owner word is in place before another
            // thread can look for the carrier.
            state.allocator.import_carrier_transfer(transfer)?;
            drop(pool);
            self.pool_stats
                .lock()
                .expect("pool-stats lock poisoned")
                .fetch
                .inc();
            return Ok(());
        }
        let transfer = {
            let mut homecomings = self.homecomings.lock().expect("homecoming lock poisoned");
            let Some(index) = homecomings
                .iter()
                .position(|entry| entry.transfer.carrier_address() == carrier)
            else {
                return Ok(());
            };
            homecomings.swap_remove(index).transfer
        };
        drop(pool);
        state.allocator.import_carrier_transfer(transfer)?;
        Ok(())
    }

    /// Takes back the carrier `homecoming_id` that was sent to `instance`, if it is still waiting.
    ///
    /// Port of the `HOMECOMING_MBC_BLK_HDR` branch of `handle_delayed_dealloc` (erl_alloc_util.c,
    /// OTP-29.1.1), run by the origin instance.
    fn import_homecoming(
        &self,
        state: &mut Instance,
        homecoming_id: u64,
    ) -> Result<(), AllocError> {
        let transfer = {
            let mut homecomings = self.homecomings.lock().expect("homecoming lock poisoned");
            let Some(index) = homecomings
                .iter()
                .position(|entry| entry.id == homecoming_id)
            else {
                return Ok(());
            };
            homecomings.swap_remove(index).transfer
        };
        state.allocator.import_carrier_transfer(transfer)?;
        Ok(())
    }

    fn fetch_for_size(&self, state: &mut Instance, size: usize) -> Result<(), AllocError> {
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
        state.allocator.import_carrier_transfer(entry.transfer)?;
        drop(pool);
        self.pool_stats
            .lock()
            .expect("pool-stats lock poisoned")
            .fetch
            .inc();
        Ok(())
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
        let mut sent_home = Vec::new();
        let mut pool = self
            .carrier_pool
            .lock()
            .expect("carrier-pool lock poisoned");
        for transfer in transfers {
            if transfer.origin_instance() == instance
                && pool.len() >= state.allocator.carrier_pool_limit()
            {
                state.allocator.import_carrier_transfer(transfer)?;
                continue;
            }
            if transfer.origin_instance() == instance {
                pool.push(PooledCarrier { transfer });
                pool.last()
                    .expect("just pushed")
                    .transfer
                    .set_in_pool(instance);
                self.pooled.fetch_add(1, Ordering::AcqRel);
            } else {
                let id = {
                    let mut next = self.next_pool_id.lock().expect("pool-id lock poisoned");
                    let id = *next;
                    *next += 1;
                    id
                };
                let origin = transfer.origin_instance();
                {
                    let mut homecomings =
                        self.homecomings.lock().expect("homecoming lock poisoned");
                    homecomings.push(HomecomingCarrier { id, transfer });
                    homecomings
                        .last()
                        .expect("just pushed")
                        .transfer
                        .set_in_pool(instance);
                }
                self.enqueue_homecoming(origin, id);
                sent_home.push(origin);
            }
        }
        drop(pool);
        for origin in sent_home {
            self.schedule_owner_work(origin);
        }
        Ok(())
    }

    /// Handles up to `limit` queue entries of `instance`; returns the number and the handles of
    /// the blocks freed and what the owner's aux work has left to do.
    ///
    /// Port of `handle_delayed_dealloc` (erl_alloc_util.c, OTP-29.1.1): a block is freed here, or
    /// redirected to the instance that owns its carrier now; a homecoming marker takes the
    /// carrier back. A block of a pooled or homecoming carrier takes the carrier back first.
    /// `want_progress` is `need_thr_progress != NULL`. Blocks of fixed-size types come from the
    /// instance's `ddq` (`ddq_dequeue`, then `ddq_check_incoming` once the queue runs dry); the
    /// others and the homecoming markers from the plain queue.
    fn drain_limited(
        &self,
        instance: usize,
        state: &mut Instance,
        limit: usize,
        want_progress: bool,
    ) -> Result<(usize, DdStatus), AllocError> {
        let mut freed = 0;
        let mut status = DdStatus::default();
        let progress = crate::sspa::progress_ops();
        let tail = &self.ddq[instance];
        let mut ops = 0usize;
        let mut have_checked_incoming = false;
        loop {
            ops = ops.saturating_add(1);
            if ops > limit {
                if state.ddq.has_dequeueable() {
                    status.more_work = true;
                }
                break;
            }
            let Some(node) = state.ddq.dequeue(tail) else {
                if have_checked_incoming {
                    break;
                }
                let need = state.ddq.check_incoming(tail, progress);
                status.need_thr_progress |= need && want_progress;
                have_checked_incoming = true;
                // `goto dequeue`: the check does not count as an operation.
                ops -= 1;
                continue;
            };
            let info = node_info(node);
            let fix_ix = info & ((1 << FIX_INFO_SHIFT) - 1);
            let size = info >> FIX_INFO_SHIFT;
            let allocation = Allocation::from_payload(node as *mut u64, size);
            match self.used_allctr(instance, state, allocation) {
                Ok(owner) if owner == instance => {}
                Ok(owner) => {
                    self.enqueue_fix(owner, instance, fix_ix, allocation);
                    continue;
                }
                Err(error) => {
                    self.enqueue_fix(instance, instance, fix_ix, allocation);
                    return Err(error);
                }
            }
            let released = if fix_ix == NOT_FIX {
                state.allocator.free(allocation)
            } else {
                fix_free_owned(state, fix_ix, allocation)
            };
            if let Err(error) = released {
                self.enqueue_fix(instance, instance, fix_ix, allocation);
                return Err(error);
            }
            // A carrier this free abandoned goes to the pool now, so the owner word of every
            // block the next entries name is in its final state (erts inserts in abandon_carrier).
            self.publish_transfers(instance, state)?;
            freed += 1;
        }
        if want_progress && !status.need_thr_progress && !status.more_work {
            let need = state.ddq.check_incoming(tail, progress);
            status.need_thr_progress |= need;
        }
        // The carriers sent home, which erts queues as `HOMECOMING_MBC_BLK_HDR` nodes.
        while ops <= limit && self.homecoming_count[instance].load(Ordering::Acquire) != 0 {
            let id = self.homecoming_ids[instance]
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop();
            let Some(id) = id else { break };
            self.homecoming_count[instance].fetch_sub(1, Ordering::AcqRel);
            ops = ops.saturating_add(1);
            if let Err(error) = self.import_homecoming(state, id) {
                self.enqueue_homecoming(instance, id);
                return Err(error);
            }
        }
        Ok((freed, status))
    }
}

/// The owner's half of fix_cpool_free: the block goes on the free list unless the list is full.
///
/// Port of erts/emulator/beam/erl_alloc_util.c (fix_cpool_free), OTP-29.1.1. erts also trims the
/// lists from aux work (fix_cpool_alloc_shrink); the port keeps only the list size limit.
fn fix_free_owned(
    state: &mut Instance,
    fix_ix: usize,
    allocation: Allocation,
) -> Result<(), AllocError> {
    let type_size = state
        .fix
        .get(fix_ix)
        .ok_or(AllocError::InvalidAllocation)?
        .type_size;
    // The size read back from the block header is the payload capacity of its block, which
    // exceeds the type size for a type smaller than the minimum block (erts compares nothing:
    // the free list is selected by the type).
    if allocation.size() != state.allocator.payload_capacity(type_size) {
        return state.allocator.free(allocation);
    }
    let fix = &mut state.fix[fix_ix];
    fix.used = fix.used.saturating_sub(1);
    if fix.shrink_list == 0 && fix.list_size < FIX_MAX_LIST_SIZE {
        fix_list_push(fix, allocation);
        return Ok(());
    }
    fix.allocated = fix.allocated.saturating_sub(1);
    state.allocator.free(allocation)?;
    fix_check_shrink(state, fix_ix)
}

/// Give one listed block back to its carrier while a shrink is pending.
///
/// Port of erts/emulator/beam/erl_alloc_util.c (fix_cpool_check_shrink), OTP-29.1.1.
fn fix_check_shrink(state: &mut Instance, fix_ix: usize) -> Result<(), AllocError> {
    let fix = &mut state.fix[fix_ix];
    if fix.shrink_list == 0 {
        return Ok(());
    }
    let Some(allocation) = fix_list_pop(fix) else {
        fix.shrink_list = 0;
        return Ok(());
    };
    fix.shrink_list -= 1;
    fix.min_list_size = fix.min_list_size.min(fix.list_size);
    fix.allocated = fix.allocated.saturating_sub(1);
    state.allocator.free(allocation)
}

/// Links a fixed-size block through the first payload word, as `fix_cpool_free` does.
#[inline(always)]
#[allow(unsafe_code)]
fn fix_list_push(fix: &mut FixList, allocation: Allocation) {
    let payload = allocation.payload_address();
    // SAFETY: the live fixed-size payload is word aligned and has room for the link word.
    unsafe { (payload as *mut u64).write(fix.list as u64) };
    fix.list = payload;
    fix.list_size += 1;
}

/// Pops the intrusive head and rebuilds allocator identity from its block header.
#[inline(always)]
fn fix_list_pop(fix: &mut FixList) -> Option<Allocation> {
    let payload = fix_list_pop_payload(fix)?;
    Some(Allocation::from_payload(payload as *mut u64, fix.type_size))
}

#[inline(always)]
#[allow(unsafe_code)]
fn fix_list_pop_payload(fix: &mut FixList) -> Option<usize> {
    let payload = fix.list;
    if payload == 0 {
        return None;
    }
    // SAFETY: the list head names a live, word-aligned payload whose first word is its next link.
    fix.list = unsafe { (payload as *const u64).read() as usize };
    fix.list_size -= 1;
    Some(payload)
}

/// Most blocks one shrink pass gives back per list.
///
/// Port of erts/emulator/beam/erl_alloc_util.c (`ERTS_ALC_FIX_MAX_SHRINK_OPS`), OTP-29.1.1.
const FIX_MAX_SHRINK_OPS: usize = 30;

/// What one shrink pass leaves to do.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FixShrink {
    /// Blocks are still to be given back (erts `ERTS_SSI_AUX_WORK_FIX_ALLOC_DEALLOC`).
    pub dealloc: bool,
    /// Some free list holds blocks, so the periodic pass stays scheduled.
    pub listed: bool,
}

/// One shrink pass over the free lists of an instance. `lower_limit` is the periodic pass
/// that sets the blocks to give back to the fewest the list held since the last pass.
///
/// Port of erts/emulator/beam/erl_alloc_util.c (fix_cpool_alloc_shrink), OTP-29.1.1.
fn fix_shrink_owned(state: &mut Instance, lower_limit: bool) -> Result<FixShrink, AllocError> {
    let mut result = FixShrink::default();
    for fix_ix in 0..state.fix.len() {
        {
            let fix = &mut state.fix[fix_ix];
            if lower_limit {
                fix.shrink_list = fix.min_list_size;
                fix.min_list_size = fix.list_size;
            }
        }
        for _ in 0..FIX_MAX_SHRINK_OPS {
            let fix = &mut state.fix[fix_ix];
            if fix.shrink_list == 0 {
                break;
            }
            let Some(allocation) = fix_list_pop(fix) else {
                fix.shrink_list = 0;
                break;
            };
            fix.shrink_list -= 1;
            fix.allocated = fix.allocated.saturating_sub(1);
            state.allocator.free(allocation)?;
        }
        let fix = &mut state.fix[fix_ix];
        fix.min_list_size = fix.min_list_size.min(fix.list_size);
        if fix.list_size != 0 {
            result.dealloc |= fix.shrink_list > 0;
            result.listed = true;
        }
    }
    Ok(result)
}

#[allow(unsafe_code)]
impl ThreadSpecificAllocators {
    /// Whether `instance` is a scheduler instance, which its owner uses without a lock.
    #[inline(always)]
    fn lock_free(&self, instance: usize) -> bool {
        instance.wrapping_sub(1) < self.scheduler_instances
    }

    /// Takes the instance for the calling thread, which must be its owner when it is a scheduler
    /// instance and takes the instance lock otherwise.
    ///
    /// Port of the `thread_safe` branch of `erts_alcu_alloc_thr_pref` (erl_alloc_util.c,
    /// OTP-29.1.1): `ERTS_ALCU_FLG_THREAD_SAFE` allocators lock, scheduler instances do not.
    #[inline(always)]
    fn lock_instance(&self, instance: usize) -> InstanceGuard<'_> {
        let slot = &self.instances[instance];
        if self.lock_free(instance) {
            debug_assert!(
                owns_instance(instance),
                "scheduler instance {instance} touched by a thread that does not own it"
            );
            // SAFETY: `instance` is a scheduler instance and the caller is its registered owner
            // (checked above in debug builds; every caller reaches here through the thread's own
            // allocator index or through the owner's aux work). Registration gives an instance
            // one owner at a time, and a non owner only enters through `lock_unowned`, which
            // excludes registration, so no other reference to the state exists.
            let state = unsafe { &mut *slot.state.0.get() };
            InstanceGuard { state, _lock: None }
        } else {
            let lock = slot.lock.lock();
            // SAFETY: the instance lock is held, and every other access to a locked instance
            // takes it first.
            let state = unsafe { &mut *slot.state.0.get() };
            InstanceGuard {
                state,
                _lock: Some(lock),
            }
        }
    }

    /// Takes a scheduler instance that has no owner thread. `claims` is the held [`CLAIMED`] set,
    /// which does not contain `instance`, so no thread can register as its owner until the
    /// guard is gone and the caller releases `claims`.
    fn lock_unowned<'a>(
        &'a self,
        instance: usize,
        claims: &std::sync::MutexGuard<'_, BTreeSet<usize>>,
    ) -> InstanceGuard<'a> {
        debug_assert!(self.lock_free(instance) && !claims.contains(&instance));
        let slot = &self.instances[instance];
        // SAFETY: the scheduler instance has no owner and registration of one needs `CLAIMED`,
        // which the caller holds; other non owner threads also hold `CLAIMED` while they touch it.
        let state = unsafe { &mut *slot.state.0.get() };
        InstanceGuard { state, _lock: None }
    }
}

/// End offset of `len` bytes at `offset` inside the payload, checked against the block size.
fn payload_range(
    handle: InstanceAllocation,
    offset: usize,
    len: usize,
) -> Result<usize, AllocError> {
    offset
        .checked_add(len)
        .filter(|end| *end <= handle.allocation.size())
        .ok_or(AllocError::OutOfBounds)
}

/// The payload of a live block as words. Payloads are word aligned and padded to whole words.
fn payload_view(handle: InstanceAllocation) -> WordView {
    WordView::new(
        handle.allocation.payload_address() as *mut u64,
        handle.allocation.size().div_ceil(8),
    )
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

    fn with_scheduler_instances(
        mut allocators: ThreadSpecificAllocators,
    ) -> Arc<ThreadSpecificAllocators> {
        allocators.scheduler_instances = allocators.instances.len() - 1;
        Arc::new(allocators)
    }

    fn four_instances() -> Arc<ThreadSpecificAllocators> {
        with_scheduler_instances(ThreadSpecificAllocators::new(
            4,
            true,
            Strategy::AoffCbf,
            AllocUtilOptions::default(),
        ))
    }

    #[test]
    #[ignore = "timing: cargo test --release -p arinsal-alloc instance_cycle_bench -- --ignored --nocapture"]
    fn instance_cycle_bench() {
        let _serial = registration();
        let allocators = four_instances();
        thread::spawn(move || {
            assert_eq!(register_thread(ThreadKind::Scheduler(1)), Ok(1));
            let mut state = 0x2545_f491_4f6c_dd1d_u64;
            let mut next = move || {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state
            };
            let cycles: usize = std::env::var("FRAG_CYCLES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(200_000);
            let mut live = Vec::with_capacity(32);
            let started = std::time::Instant::now();
            for _ in 0..cycles {
                for _ in 0..26 {
                    live.push(allocators.alloc(8 + (next() % 12) as usize * 8).unwrap());
                }
                for handle in live.drain(..) {
                    allocators.free(handle).unwrap();
                }
            }
            let nanos = started.elapsed().as_nanos() as f64;
            eprintln!(
                "instance layer: {:.2} ns per alloc+free pair",
                nanos / (cycles as f64 * 26.0)
            );
        })
        .join()
        .unwrap();
    }

    #[test]
    #[ignore = "timing: cargo test --release -p arinsal-alloc cross_thread_handle_bench -- --ignored --nocapture"]
    fn cross_thread_handle_bench() {
        // The signal node pattern: one scheduler allocates a batch, another frees it. Reports the
        // allocating side (which also drains the frees queued for it) and the freeing side apart.
        let _serial = registration();
        let allocators = four_instances();
        for fixed in [false, true] {
            let (tx, rx) = std::sync::mpsc::channel::<Vec<InstanceAllocation>>();
            let (back_tx, back_rx) = std::sync::mpsc::channel::<()>();
            let producer = Arc::clone(&allocators);
            let consumer = Arc::clone(&allocators);
            let (rounds, batch) = (2_000usize, 200usize);
            let a = thread::spawn(move || {
                assert_eq!(register_thread(ThreadKind::Scheduler(1)), Ok(1));
                let mut total = std::time::Duration::ZERO;
                for _ in 0..rounds {
                    let started = std::time::Instant::now();
                    let blocks: Vec<_> = (0..batch)
                        .map(|_| {
                            if fixed {
                                producer.fix_alloc_with_ptr_at(1, 0, 80).unwrap().0
                            } else {
                                producer.alloc(80).unwrap()
                            }
                        })
                        .collect();
                    total += started.elapsed();
                    tx.send(blocks).unwrap();
                    back_rx.recv().unwrap();
                }
                total.as_nanos() as f64 / (rounds * batch) as f64
            });
            let b = thread::spawn(move || {
                assert_eq!(register_thread(ThreadKind::Scheduler(2)), Ok(2));
                let mut total = std::time::Duration::ZERO;
                for blocks in rx {
                    let started = std::time::Instant::now();
                    for handle in blocks {
                        if fixed {
                            consumer.fix_free_at(2, 0, handle).unwrap();
                        } else {
                            consumer.free(handle).unwrap();
                        }
                    }
                    total += started.elapsed();
                    back_tx.send(()).unwrap();
                }
                total.as_nanos() as f64 / (rounds * batch) as f64
            });
            let (pa, pb) = (a.join().unwrap(), b.join().unwrap());
            eprintln!(
                "{}: alloc side {pa:.1} ns/block, free side {pb:.1} ns/block",
                if fixed { "fix list" } else { "general" }
            );
        }
    }

    #[test]
    #[ignore = "timing: cargo test --release -p arinsal-alloc same_thread_fix_cycle_bench -- --ignored --nocapture"]
    fn same_thread_fix_cycle_bench() {
        let _serial = registration();
        let allocators = four_instances();
        thread::spawn(move || {
            assert_eq!(register_thread(ThreadKind::Scheduler(1)), Ok(1));
            for _ in 0..10_000 {
                let payload = allocators.fix_alloc_payload_at(1, 0, 80).unwrap();
                allocators.fix_free_payload_at(0, payload, 80).unwrap();
            }
            let cycles = 10_000_000usize;
            let started = std::time::Instant::now();
            for index in 0..cycles {
                let payload = allocators.fix_alloc_payload_at(1, 0, 80).unwrap();
                std::hint::black_box(payload);
                allocators.fix_free_payload_at(0, payload, 80).unwrap();
                std::hint::black_box(index);
            }
            let work = started.elapsed().as_secs_f64() * 1e9;
            let started = std::time::Instant::now();
            for index in 0..cycles {
                std::hint::black_box(index);
            }
            let empty = started.elapsed().as_secs_f64() * 1e9;
            eprintln!(
                "fix alloc+free: {:.2} ns/pair",
                (work - empty) / cycles as f64
            );
        })
        .join()
        .unwrap();
    }

    #[test]
    #[ignore = "timing: cargo test --release -p arinsal-alloc cross_thread_cycle_bench -- --ignored --nocapture"]
    fn cross_thread_cycle_bench() {
        let _serial = registration();
        let allocators = four_instances();
        let (tx, rx) = std::sync::mpsc::channel::<Vec<usize>>();
        let (back_tx, back_rx) = std::sync::mpsc::channel::<()>();
        let producer = Arc::clone(&allocators);
        let consumer = Arc::clone(&allocators);
        let (rounds, batch) = (2_000usize, 200usize);
        let allocating = thread::spawn(move || {
            assert_eq!(register_thread(ThreadKind::Scheduler(1)), Ok(1));
            let mut total = std::time::Duration::ZERO;
            for _ in 0..rounds {
                let started = std::time::Instant::now();
                let payloads = (0..batch)
                    .map(|_| producer.fix_alloc_payload_at(1, 0, 80).unwrap() as usize)
                    .collect();
                total += started.elapsed();
                tx.send(payloads).unwrap();
                back_rx.recv().unwrap();
            }
            total.as_secs_f64() * 1e9 / (rounds * batch) as f64
        });
        let freeing = thread::spawn(move || {
            assert_eq!(register_thread(ThreadKind::Scheduler(2)), Ok(2));
            let mut total = std::time::Duration::ZERO;
            for payloads in rx {
                let started = std::time::Instant::now();
                for payload in payloads {
                    consumer
                        .fix_free_payload_at(0, payload as *mut u64, 80)
                        .unwrap();
                }
                total += started.elapsed();
                back_tx.send(()).unwrap();
            }
            total.as_secs_f64() * 1e9 / (rounds * batch) as f64
        });
        eprintln!(
            "cross-thread fix: alloc {:.2} ns/block, free {:.2} ns/block",
            allocating.join().unwrap(),
            freeing.join().unwrap()
        );
    }

    #[test]
    fn owner_instance_has_no_lock() {
        let _serial = registration();
        let allocators = four_instances();
        assert!(!allocators.lock_free(0));
        for instance in 1..4 {
            assert!(allocators.lock_free(instance));
        }
        let worker = Arc::clone(&allocators);
        thread::spawn(move || {
            assert_eq!(register_thread(ThreadKind::Scheduler(2)), Ok(2));
            let handle = worker.alloc(100).unwrap();
            assert_eq!(handle.instance(), 2);
            {
                let state = worker.lock_instance(2);
                assert!(state._lock.is_none());
                assert!(!worker.instances[2].lock.is_locked());
            }
            {
                let state = worker.lock_instance(0);
                assert!(state._lock.is_some());
                assert!(worker.instances[0].lock.is_locked());
            }
            worker.free(handle).unwrap();
        })
        .join()
        .unwrap();
    }

    #[test]
    fn foreign_frees_are_never_lost() {
        const OWNERS: usize = 3;
        const ROUNDS: usize = 2000;
        let _serial = registration();
        let allocators = four_instances();
        let start = Arc::new(Barrier::new(OWNERS));
        let all_freed = Arc::new(Barrier::new(OWNERS));
        let drained = Arc::new(Barrier::new(OWNERS));
        let (senders, receivers): (Vec<_>, Vec<_>) = (0..OWNERS)
            .map(|_| mpsc::channel::<InstanceAllocation>())
            .unzip();
        let mut receivers: Vec<_> = receivers.into_iter().map(Some).collect();
        let workers: Vec<_> = (0..OWNERS)
            .map(|index| {
                let allocators = Arc::clone(&allocators);
                let next = senders[(index + 1) % OWNERS].clone();
                let inbox = receivers[index].take().unwrap();
                let (start, all_freed, drained) = (
                    Arc::clone(&start),
                    Arc::clone(&all_freed),
                    Arc::clone(&drained),
                );
                thread::spawn(move || {
                    let own = index + 1;
                    assert_eq!(register_thread(ThreadKind::Scheduler(own)), Ok(own));
                    start.wait();
                    let mut kept = Vec::new();
                    for round in 0..ROUNDS {
                        for n in 0..24 {
                            let size = if n == 0 && round % 16 == 0 {
                                300_000
                            } else {
                                8 + (n * 40 + round) % 600
                            };
                            let handle = allocators.alloc(size).unwrap();
                            assert_eq!(handle.instance(), own);
                            if n % 3 == 0 {
                                kept.push(handle);
                            } else {
                                next.send(handle).unwrap();
                            }
                        }
                        while let Ok(handle) = inbox.try_recv() {
                            allocators.free(handle).unwrap();
                        }
                        for handle in kept.drain(..) {
                            allocators.free(handle).unwrap();
                        }
                        if round % 7 == 0 {
                            allocators.handle_owner_work(own).unwrap();
                        }
                    }
                    drop(next);
                    for handle in inbox {
                        allocators.free(handle).unwrap();
                    }
                    all_freed.wait();
                    while allocators.pending_deallocations(own) != 0 {
                        allocators.handle_owner_work(own).unwrap();
                    }
                    allocators.drain_deallocations(own).unwrap();
                    drained.wait();
                })
            })
            .collect();
        drop(senders);
        for worker in workers {
            worker.join().unwrap();
        }
        for instance in 0..allocators.instance_count() {
            assert_eq!(allocators.pending_deallocations(instance), 0);
        }
        assert_eq!(allocators.current_blocks_size(), 0);
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
    fn fixed_size_frees_from_many_threads_all_reach_the_owner() {
        // Two scheduler threads and an unmanaged thread free fixed-size blocks of instance 1
        // at once; the owner finds every one back on its free list through the ddq protocol.
        let _serial = registration();
        let allocators = four_instances();
        let per_thread = 3_000usize;
        let (ready_sender, ready) = mpsc::channel::<Vec<Vec<InstanceAllocation>>>();
        let (go_sender, go) = mpsc::channel::<()>();
        let owner = {
            let allocators = Arc::clone(&allocators);
            thread::spawn(move || {
                assert_eq!(register_thread(ThreadKind::Scheduler(1)), Ok(1));
                let mut parts = vec![Vec::new(), Vec::new(), Vec::new()];
                for part in &mut parts {
                    for _ in 0..per_thread {
                        part.push(allocators.fix_alloc_with_ptr_at(1, 0, 80).unwrap().0);
                    }
                }
                ready_sender.send(parts).unwrap();
                go.recv().unwrap();
                let mut rounds = 0;
                while allocators.fix_bytes(1, 0).1 != 0 {
                    allocators.handle_owner_work(1).unwrap();
                    allocators.drain_deallocations(1).unwrap();
                    rounds += 1;
                    assert!(rounds < 1_000, "queued blocks never reach the owner");
                }
                allocators.fix_bytes(1, 0)
            })
        };
        let mut parts = ready.recv().unwrap();
        let senders: Vec<_> = (0..3)
            .map(|index| {
                let allocators = Arc::clone(&allocators);
                let blocks = parts.remove(0);
                thread::spawn(move || {
                    // The third thread never registers: an unmanaged enqueuer on instance 0.
                    let ix = if index < 2 {
                        register_thread(ThreadKind::Scheduler(index + 2)).unwrap()
                    } else {
                        0
                    };
                    for handle in blocks {
                        allocators.fix_free_at(ix, 0, handle).unwrap();
                    }
                })
            })
            .collect();
        for sender in senders {
            sender.join().unwrap();
        }
        go_sender.send(()).unwrap();
        let (allocated, used) = owner.join().unwrap();
        assert_eq!(used, 0);
        // The free list keeps at most FIX_MAX_LIST_SIZE blocks; the others went back to the carrier.
        assert_eq!(allocated, 80 * FIX_MAX_LIST_SIZE);
        assert_eq!(allocators.pending_deallocations(1), 0);
    }

    #[test]
    fn passed_index_allocates_on_the_owner_and_queues_a_foreign_free() {
        let _serial = registration();
        let allocators = four_instances();
        let owner_allocators = Arc::clone(&allocators);
        let (handle, ptr) = thread::spawn(move || {
            assert_eq!(register_thread(ThreadKind::Scheduler(1)), Ok(1));
            let ix = thread_alloc_ix();
            assert_eq!(ix, 1);
            let (handle, ptr) = owner_allocators.alloc_with_ptr_at(ix, 64).unwrap();
            assert_eq!(handle.instance(), 1);
            assert_eq!(ptr, owner_allocators.allocation_ptr(handle).unwrap());
            let (second, _) = owner_allocators.alloc_with_ptr_at(ix, 64).unwrap();
            owner_allocators.free_at(ix, second).unwrap();
            assert_eq!(owner_allocators.pending_deallocations(1), 0);
            (handle, ptr as usize)
        })
        .join()
        .unwrap();
        assert_ne!(ptr, 0);
        let foreign_allocators = Arc::clone(&allocators);
        thread::spawn(move || {
            assert_eq!(register_thread(ThreadKind::Scheduler(2)), Ok(2));
            foreign_allocators
                .free_at(thread_alloc_ix(), handle)
                .unwrap();
        })
        .join()
        .unwrap();
        assert_eq!(allocators.pending_deallocations(1), 1);
        assert_eq!(allocators.drain_deallocations(1).unwrap(), 1);
        assert_eq!(allocators.current_blocks_size(), 0);
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
        let held = allocators.lock_instance(0);
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
                // ddq protocol: blocks become dequeueable once `unref_end` passes them, so the
                // first passes may free nothing; every pass frees at most the limit.
                let mut passes = Vec::new();
                let mut left = allocators.pending_deallocations(1);
                while left != 0 && passes.len() < 16 {
                    let status = allocators.handle_owner_work(1).unwrap();
                    let now = allocators.pending_deallocations(1);
                    passes.push((left - now, status.more_work));
                    left = now;
                }
                (passes, left)
            })
        };
        let handles = ready.recv().unwrap();
        for handle in handles {
            allocators.free(handle).unwrap();
        }
        assert_eq!(allocators.pending_deallocations(1), 25);
        done_sender.send(()).unwrap();
        let (passes, left) = owner.join().unwrap();
        assert_eq!(left, 0, "{passes:?}");
        assert!(
            passes
                .iter()
                .all(|(freed, _)| *freed <= OWNER_WORK_DD_LIMIT),
            "{passes:?}"
        );
        // A pass that stopped at the limit asked for another one.
        assert!(
            passes
                .iter()
                .any(|(freed, more)| *freed == OWNER_WORK_DD_LIMIT && *more),
            "{passes:?}"
        );
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

    fn pooling_allocators(instances: usize) -> Arc<ThreadSpecificAllocators> {
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
        with_scheduler_instances(ThreadSpecificAllocators::new(
            instances,
            true,
            Strategy::AoffCbf,
            options,
        ))
    }

    /// Instance 0 owns a carrier with `first` and `live`, abandoned into the pool by a free.
    fn pooled_carrier(
        allocators: &ThreadSpecificAllocators,
    ) -> (InstanceAllocation, InstanceAllocation) {
        let first = allocators.alloc(15_500_000).unwrap();
        let live = allocators.alloc(14_000_000).unwrap();
        allocators.write(live, 0, b"carrier migration").unwrap();
        let trigger = allocators.alloc(1_500_000).unwrap();
        allocators.free(trigger).unwrap();
        assert_eq!(allocators.pooled_carrier_count(), 1);
        (first, live)
    }

    #[test]
    fn abandoned_carrier_migrates_and_its_header_names_the_owner() {
        let _serial = registration();
        let allocators = pooling_allocators(2);
        let (first, live) = pooled_carrier(&allocators);
        let pool_info = allocators.info(0).mbcs_pool.unwrap();
        assert_eq!(pool_info.carriers, 1);
        assert_eq!(pool_info.blocks, 1);

        let worker_allocators = Arc::clone(&allocators);
        let worker = thread::spawn(move || {
            assert_eq!(register_thread(ThreadKind::Scheduler(1)), Ok(1));
            assert_eq!(worker_allocators.current_instance(), 1);
            let mut bytes = [0; 17];
            assert_eq!(
                get_used_allctr(live.allocation.payload_address()).instance,
                0
            );
            assert_eq!(worker_allocators.pooled_carrier_count(), 1);
            worker_allocators.read(live, 0, &mut bytes).unwrap();
            assert_eq!(&bytes, b"carrier migration");
            let next = worker_allocators.alloc(1_500_000).unwrap();
            assert_eq!(worker_allocators.pooled_carrier_count(), 0);
            assert_eq!(
                get_used_allctr(live.allocation.payload_address()).instance,
                1
            );
            worker_allocators.free(next).unwrap();
            assert_eq!(worker_allocators.homecoming_carrier_count(), 1);
            assert_eq!(
                get_used_allctr(live.allocation.payload_address()).instance,
                0
            );
            worker_allocators.read(live, 0, &mut bytes).unwrap();
            assert_eq!(&bytes, b"carrier migration");
        });
        worker.join().unwrap();
        assert_eq!(allocators.homecoming_carrier_count(), 1);
        assert_eq!(allocators.pending_deallocations(0), 1);
        assert_eq!(allocators.drain_deallocations(0).unwrap(), 0);
        assert_eq!(allocators.homecoming_carrier_count(), 0);
        assert_eq!(allocators.pooled_carrier_count(), 0);
        let pool_info = allocators.carrier_pool_stats();
        assert_eq!(pool_info.fetch.count, 1);
        assert_eq!(pool_info.fetch.giga, 0);
        allocators.free(live).unwrap();
        allocators.free(first).unwrap();
    }

    #[test]
    fn foreign_free_of_pooled_block_is_queued_on_origin() {
        let _serial = registration();
        let allocators = pooling_allocators(2);
        let (first, live) = pooled_carrier(&allocators);
        let worker_allocators = Arc::clone(&allocators);
        let held = allocators.lock_instance(0);
        let queued = within(Duration::from_secs(5), move || {
            assert_eq!(register_thread(ThreadKind::Scheduler(1)), Ok(1));
            worker_allocators.free(live).unwrap();
            (
                worker_allocators.pending_deallocations(0),
                worker_allocators.pooled_carrier_count(),
            )
        });
        drop(held);
        assert_eq!(
            queued.expect("a foreign free must not lock the origin instance"),
            (1, 1)
        );
        assert_eq!(allocators.drain_deallocations(0).unwrap(), 1);
        assert_eq!(allocators.pending_deallocations(0), 0);
        allocators.free(first).unwrap();
    }

    #[test]
    fn foreign_free_does_not_import_the_pooled_carrier() {
        let _serial = registration();
        let allocators = pooling_allocators(2);
        let (first, live) = pooled_carrier(&allocators);
        let worker_allocators = Arc::clone(&allocators);
        within(Duration::from_secs(5), move || {
            assert_eq!(register_thread(ThreadKind::Scheduler(1)), Ok(1));
            worker_allocators.free(live).unwrap();
        })
        .unwrap();
        assert_eq!(allocators.pooled_carrier_count(), 1);
        assert_eq!(allocators.carrier_pool_stats().fetch.count, 0);
        allocators.drain_deallocations(0).unwrap();
        allocators.free(first).unwrap();
    }

    #[test]
    fn homecoming_is_enqueued_not_imported_by_foreign_thread() {
        let _serial = registration();
        let allocators = pooling_allocators(2);
        let (first, live) = pooled_carrier(&allocators);
        let worker_allocators = Arc::clone(&allocators);
        let held = allocators.lock_instance(0);
        let result = within(Duration::from_secs(5), move || {
            assert_eq!(register_thread(ThreadKind::Scheduler(1)), Ok(1));
            let next = worker_allocators.alloc(1_500_000).unwrap();
            worker_allocators.free(next).unwrap();
            let sent_home = (
                worker_allocators.homecoming_carrier_count(),
                worker_allocators.pending_deallocations(0),
            );
            worker_allocators.free(live).unwrap();
            (sent_home, worker_allocators.pending_deallocations(0))
        });
        drop(held);
        let (sent_home, queued) =
            result.expect("sending a carrier home must not lock the origin instance");
        assert_eq!(sent_home, (1, 1));
        assert_eq!(queued, 2);
        assert_eq!(allocators.drain_deallocations(0).unwrap(), 1);
        assert_eq!(allocators.homecoming_carrier_count(), 0);
        assert_eq!(allocators.pending_deallocations(0), 0);
        allocators.free(first).unwrap();
    }

    #[test]
    fn homecoming_schedules_work_for_the_origin_owner() {
        static HOME: AtomicUsize = AtomicUsize::new(usize::MAX);
        let _serial = registration();
        let allocators = pooling_allocators(2);
        let (first, live) = pooled_carrier(&allocators);
        let worker_allocators = Arc::clone(&allocators);
        thread::spawn(move || {
            assert_eq!(register_thread(ThreadKind::Scheduler(1)), Ok(1));
            let next = worker_allocators.alloc(1_500_000).unwrap();
            worker_allocators.free(next).unwrap();
            HOME.store(
                worker_allocators.pending_deallocations(0),
                Ordering::Relaxed,
            );
        })
        .join()
        .unwrap();
        assert_eq!(HOME.load(Ordering::Relaxed), 1);
        assert!(allocators.shared[0].work_scheduled.load(Ordering::Acquire));
        allocators.free(live).unwrap();
        allocators.free(first).unwrap();
    }

    #[test]
    fn block_queued_on_origin_is_redirected_when_the_carrier_moved_on() {
        let _serial = registration();
        let allocators = pooling_allocators(3);
        let (first, live) = pooled_carrier(&allocators);
        let freer_allocators = Arc::clone(&allocators);
        thread::spawn(move || {
            assert_eq!(register_thread(ThreadKind::Scheduler(1)), Ok(1));
            freer_allocators.free(live).unwrap();
        })
        .join()
        .unwrap();
        assert_eq!(allocators.pending_deallocations(0), 1);
        let taker_allocators = Arc::clone(&allocators);
        let next = thread::spawn(move || {
            assert_eq!(register_thread(ThreadKind::Scheduler(2)), Ok(2));
            taker_allocators.alloc(1_500_000).unwrap()
        })
        .join()
        .unwrap();
        assert_eq!(allocators.pooled_carrier_count(), 0);
        assert_eq!(allocators.drain_deallocations(0).unwrap(), 0);
        assert_eq!(allocators.pending_deallocations(0), 0);
        assert_eq!(allocators.pending_deallocations(2), 1);
        assert_eq!(allocators.drain_deallocations(2).unwrap(), 1);
        allocators.free(next).unwrap();
        allocators.free(first).unwrap();
    }

    /// Every place that takes an instance lock, with the reason the caller owns the instance.
    #[test]
    fn instance_locks_are_taken_only_by_the_owner_paths() {
        let source = include_str!("instances.rs");
        let production = &source[..source.find("#[cfg(test)]\nmod tests").unwrap()];
        let mut sites = Vec::new();
        let mut current = "";
        for line in production.lines() {
            let line = line.trim_start();
            if let Some(rest) = line
                .strip_prefix("pub fn ")
                .or_else(|| line.strip_prefix("pub(crate) fn "))
                .or_else(|| line.strip_prefix("fn "))
            {
                current = rest.split(['(', '<']).next().unwrap();
            }
            if line.contains(".lock_instance(") {
                sites.push(current);
            }
            if line.contains(".lock_unowned(") {
                sites.push("unowned");
            }
        }
        similar_asserts::assert_eq!(
            sites,
            [
                "alloc_with_ptr_at",
                "realloc_with_ptr",
                "free_thr_pref",
                "handle_owner_work",
                "run_owner_requests",
                "on_owner",
                "unowned",
                "unowned",
                "fix_alloc_with_ptr_at",
                "fix_alloc_payload_at",
                "fix_free_payload_at",
                "fix_shrink_at",
            ]
        );
    }

    #[test]
    fn foreign_realloc_moves_block_to_calling_instance() {
        let _serial = registration();
        let allocators = four_instances();
        let (owned_tx, owned_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let owner_allocators = Arc::clone(&allocators);
        let owner = thread::spawn(move || {
            assert_eq!(register_thread(ThreadKind::Scheduler(1)), Ok(1));
            let handle = owner_allocators.alloc(64).unwrap();
            let pattern: Vec<u8> = (0..64).collect();
            owner_allocators.write(handle, 0, &pattern).unwrap();
            owned_tx.send((handle, pattern)).unwrap();
            done_rx.recv().unwrap();
            assert_eq!(owner_allocators.pending_deallocations(1), 1);
            assert_eq!(owner_allocators.drain_deallocations(1).unwrap(), 1);
            assert_eq!(owner_allocators.pending_deallocations(1), 0);
        });
        let (handle, pattern) = owned_rx.recv().unwrap();
        let worker_allocators = Arc::clone(&allocators);
        let moved = thread::spawn(move || {
            assert_eq!(register_thread(ThreadKind::Scheduler(2)), Ok(2));
            let (moved, ptr) = worker_allocators.realloc_with_ptr(handle, 256).unwrap();
            assert_eq!(ptr, worker_allocators.allocation_ptr(moved).unwrap());
            let mut bytes = vec![0; 64];
            worker_allocators.read(moved, 0, &mut bytes).unwrap();
            assert_eq!(bytes, pattern);
            moved
        })
        .join()
        .unwrap();
        assert_eq!(moved.instance(), 2);
        assert_eq!(allocators.pending_deallocations(1), 1);
        done_tx.send(()).unwrap();
        owner.join().unwrap();
        allocators.free(moved).unwrap();
    }

    #[test]
    fn same_instance_realloc_stays_on_the_owner() {
        let _serial = registration();
        let allocators = four_instances();
        let worker_allocators = Arc::clone(&allocators);
        thread::spawn(move || {
            assert_eq!(register_thread(ThreadKind::Scheduler(1)), Ok(1));
            let handle = worker_allocators.alloc(64).unwrap();
            let grown = worker_allocators.realloc(handle, 256).unwrap();
            assert_eq!(grown.instance(), 1);
            assert_eq!(worker_allocators.pending_deallocations(1), 0);
            worker_allocators.free(grown).unwrap();
        })
        .join()
        .unwrap();
    }

    #[test]
    fn read_write_allocation_ptr_do_not_wait_for_owner_instance() {
        let allocators = four_instances();
        let handle = allocators.alloc(32).unwrap();
        assert_eq!(handle.instance(), 0);
        let guard = allocators.lock_instance(0);
        let (tx, rx) = std::sync::mpsc::channel();
        let worker_allocators = Arc::clone(&allocators);
        let worker = thread::spawn(move || {
            worker_allocators.write(handle, 8, b"pointer only").unwrap();
            let mut bytes = [0; 12];
            worker_allocators.read(handle, 8, &mut bytes).unwrap();
            let ptr = worker_allocators.allocation_ptr(handle).unwrap();
            tx.send((bytes, ptr as usize)).unwrap();
        });
        let (bytes, ptr) = rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("pointer-only access must not wait for the owner instance lock");
        drop(guard);
        worker.join().unwrap();
        assert_eq!(&bytes, b"pointer only");
        assert_eq!(ptr, handle.allocation.payload_address());
        assert!(matches!(
            allocators.write(handle, 30, b"abc"),
            Err(AllocError::OutOfBounds)
        ));
        allocators.free(handle).unwrap();
    }
}
