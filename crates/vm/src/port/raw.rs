//! Raw port operations with an exact ERTS descriptor or data-word owner.
// Port of erts/emulator/beam/erl_bif_port.c and erts/emulator/sys/unix/sys_drivers.c, OTP-29.1.1.

use rustix::fd::AsFd;
use std::alloc::Layout;
use std::ffi::CStr;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};

use arinsal_alloc::typed::{AllocBlock, ErtsAlcType};
use arinsal_sched::Scheduler;
use arinsal_term::{HeapAlloc, Term, TermError, copy_struct};

use crate::Process;

use super::PortDataBlock;

/// `SET_CLOEXEC(fd)`: `fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC)`.
// Port of erts/emulator/sys/unix/erl_child_setup.c (`SET_CLOEXEC`), OTP-29.1.1.
pub(super) fn set_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is a live descriptor the caller still owns; F_GETFD only reads its flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is still live; F_SETFD writes the previous flags with FD_CLOEXEC set.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `pipe()` with no close-on-exec: spawn_start's `ifd`/`ofd` must survive `exec`.
// Port of erts/emulator/sys/unix/sys_drivers.c (`spawn_start`), OTP-29.1.1.
pub(super) fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: `pipe` writes two new descriptors into `fds` or returns -1.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both descriptors are live and uniquely owned by this function.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// `pipe()` then `SET_CLOEXEC` on both ends.
// Port of erts/emulator/sys/unix/erl_child_setup.c (`pipe` + `SET_CLOEXEC`), OTP-29.1.1.
pub(super) fn pipe_cloexec() -> io::Result<(OwnedFd, OwnedFd)> {
    let (read, write) = pipe()?;
    set_cloexec(read.as_raw_fd())?;
    set_cloexec(write.as_raw_fd())?;
    Ok((read, write))
}

/// `socket()` then `SET_CLOEXEC`.
// Port of erts/emulator/drivers/common/inet_drv.c (`sock_open`) and
// erts/emulator/sys/unix/erl_child_setup.c (`SET_CLOEXEC`), OTP-29.1.1.
pub(super) fn socket_cloexec(domain: i32, kind: i32, protocol: i32) -> io::Result<OwnedFd> {
    // SAFETY: `socket` returns a new descriptor or -1.
    let fd = unsafe { libc::socket(domain, kind, protocol) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a live descriptor this function still owns.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    set_cloexec(fd)?;
    Ok(owned)
}

/// `accept()` then `SET_CLOEXEC`.
// Port of erts/emulator/drivers/common/inet_drv.c (`sock_accept`) and
// erts/emulator/sys/unix/erl_child_setup.c (`SET_CLOEXEC`), OTP-29.1.1.
pub(super) fn accept_cloexec(fd: impl AsFd) -> io::Result<OwnedFd> {
    let listen = fd.as_fd().as_raw_fd();
    // SAFETY: `listen` is a listening socket; a null address buffer is valid for accept(2).
    let accepted = unsafe { libc::accept(listen, std::ptr::null_mut(), std::ptr::null_mut()) };
    if accepted < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `accepted` is a live descriptor this function still owns.
    let owned = unsafe { OwnedFd::from_raw_fd(accepted) };
    set_cloexec(accepted)?;
    Ok(owned)
}

/// `socketpair()` with no close-on-exec: forker_start creates the UDS before fork.
// Port of erts/emulator/sys/unix/sys_drivers.c (`forker_start`), OTP-29.1.1.
pub(super) fn socketpair(domain: i32, kind: i32, protocol: i32) -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: `socketpair` writes two new descriptors into `fds` or returns -1.
    if unsafe { libc::socketpair(domain, kind, protocol, fds.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both descriptors are live and uniquely owned by this function.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// `fork`, then in the child `dup2` the UDS onto fd 3, `setsid`, `execv`.
// Port of erts/emulator/sys/unix/sys_drivers.c (`forker_start`), OTP-29.1.1.
pub(super) fn forker_fork_exec(
    executable: &CStr,
    helper_fd: RawFd,
    max_files: &CStr,
) -> io::Result<()> {
    let argv0 = c"erl_child_setup";
    // SAFETY: forker_start forks from the emulator; the child uses only async-signal-safe
    // calls (dup2, setsid, execv, _exit) before the image is replaced.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        // SAFETY: this is the forked child; only async-signal-safe calls until execv/_exit.
        unsafe {
            if helper_fd != 3 && libc::dup2(helper_fd, 3) < 0 {
                libc::_exit(1);
            }
            libc::setsid();
            let argv: [*const libc::c_char; 3] =
                [argv0.as_ptr(), max_files.as_ptr(), std::ptr::null()];
            libc::execv(executable.as_ptr(), argv.as_ptr());
            libc::_exit(1);
        }
    }
    Ok(())
}

/// `isatty(0) && isatty(1)` of forker_start's tty-mode write.
// Port of erts/emulator/sys/unix/sys_drivers.c (`forker_start`), OTP-29.1.1.
pub(super) fn stdio_is_tty() -> bool {
    // SAFETY: isatty only inspects stdin/stdout of this process.
    unsafe { libc::isatty(0) != 0 && libc::isatty(1) != 0 }
}

/// Write `sizeof(termios)` of stdin's mode to `fd`, as forker_start does for erl_child_setup.
// Port of erts/emulator/sys/unix/sys_drivers.c (`forker_start`), OTP-29.1.1.
pub(super) fn write_tty_mode(fd: RawFd) -> io::Result<()> {
    // SAFETY: termios is a C POD; zeroed is a valid bit pattern for tcgetattr to overwrite.
    let mut mode = unsafe { std::mem::zeroed::<libc::termios>() };
    // SAFETY: tcgetattr writes into the local `mode` from fd 0.
    if unsafe { libc::tcgetattr(0, &mut mode) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `mode` is a live local; the slice is its exact byte size and not mutated here.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&raw const mode).cast::<u8>(),
            std::mem::size_of::<libc::termios>(),
        )
    };
    let mut pos = 0;
    while pos < bytes.len() {
        // SAFETY: `fd` is the forker UDS still in blocking mode; `bytes[pos..]` is readable.
        let n = unsafe { libc::write(fd, bytes[pos..].as_ptr().cast(), bytes.len() - pos) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted || err.kind() == io::ErrorKind::WouldBlock {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "erl_child_setup closed",
            ));
        }
        pos += n as usize;
    }
    Ok(())
}

/// `dup` then `SET_CLOEXEC`.
// Port of erts/emulator/sys/unix/sys_drivers.c (`spawn_start` `dup`) and
// erts/emulator/sys/unix/erl_child_setup.c (`SET_CLOEXEC`), OTP-29.1.1.
pub(super) fn duplicate_fd_cloexec(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: `dup` only reads `fd` and returns a new owned descriptor.
    let duplicate = unsafe { libc::dup(fd) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `duplicate` is a live descriptor this function still owns.
    let owned = unsafe { OwnedFd::from_raw_fd(duplicate) };
    set_cloexec(duplicate)?;
    Ok(owned)
}

/// The atomic `prt->data` word: an immediate term or a pointer to its heap block.
pub(super) struct PortDataCell(AtomicU64);

impl PortDataCell {
    /// Create the cell with the port's initial immediate term.
    pub(super) const fn new(initial: u64) -> Self {
        Self(AtomicU64::new(initial))
    }

    /// Load an immediate value without copying a heap block.
    // Port of erts/emulator/beam/erl_bif_port.c:769 (`erts_port_data_read`), OTP-29.1.1.
    pub(super) fn load_immediate(&self) -> Option<Term> {
        let word = self.0.load(Ordering::Acquire);
        (word != 0 && word & 3 != 0)
            .then(|| Term::from_immed_word(word))
            .flatten()
    }

    /// Copy the current port data to the caller's process heap while the port-table lookup is
    /// protected by thread progress.
    // Port of erts/emulator/beam/erl_bif_port.c:743 (`port_get_data_1`), OTP-29.1.1.
    pub(super) fn copy_term(&self, heap: &mut impl HeapAlloc) -> Result<Term, TermError> {
        let word = self.0.load(Ordering::Acquire);
        if word == 0 {
            return Err(TermError::BadArg);
        }
        if word & 3 != 0 {
            return Term::from_immed_word(word).ok_or(TermError::BadArg);
        }
        let pointer = word as *const PortDataBlock;
        // SAFETY: `PortTable::with_from` keeps this managed-thread lookup in its thread-progress
        // section. Writers atomically exchange the word and defer freeing the old block until
        // every such lookup has passed a later thread-progress point, as erts does for port data.
        let block = unsafe { &*pointer };
        copy_struct(block.term, heap, block.hsize)
    }

    /// Atomically replace the immediate or heap-block pointer, matching `erts_atomic_xchg_wb`.
    // Port of erts/emulator/beam/erl_bif_port.c:720 (`port_set_data_2`), OTP-29.1.1.
    pub(super) fn swap(&self, new_word: u64) -> u64 {
        self.0.swap(new_word, Ordering::AcqRel)
    }
}

/// Allocate the header and copied words together, as `ErtsPortDataHeap` does.
// Port of erts/emulator/beam/erl_bif_port.c:704-716 (`port_set_data_2`), OTP-29.1.1.
pub(super) fn new_data_word(term: Term, hsize: usize) -> Result<u64, TermError> {
    let (layout, words_offset) = Layout::new::<PortDataBlock>()
        .extend(Layout::array::<std::mem::MaybeUninit<u64>>(hsize).map_err(|_| TermError::BadArg)?)
        .map_err(|_| TermError::BadArg)?;
    let layout = layout.pad_to_align();
    let allocation_words = layout.size() / std::mem::size_of::<u64>();
    let mut allocation = AllocBlock::new(ErtsAlcType::PORT_DATA_HEAP, allocation_words)
        .expect("port data heap allocation failed");
    let base = allocation.as_mut_slice().as_mut_ptr().cast::<u8>();
    let block = base.cast::<PortDataBlock>();
    // SAFETY: the allocation is aligned and large enough for the header and `hsize` trailing words.
    unsafe {
        block.write(PortDataBlock {
            later_op: arinsal_sched::ErtsThrPrgrLaterOp::new(),
            term,
            hsize,
            _owners: arinsal_term::message::InlineHeapOwners::new(),
        });
    }
    // SAFETY: the computed offset lies within this allocation.
    let words = unsafe { base.add(words_offset) }.cast::<std::mem::MaybeUninit<u64>>();
    // SAFETY: `words` points to the trailing `hsize` slots in this live allocation.
    let words = unsafe { std::slice::from_raw_parts_mut(words, hsize) };
    // SAFETY: the owner header is exclusively borrowed while this block is being initialized.
    let owners = unsafe { &mut (*block)._owners };
    let copied = {
        let mut heap = arinsal_term::message::InlineHeapAlloc::new(words, owners);
        copy_struct(term, &mut heap, hsize)
    };
    match copied {
        Ok(copied) => {
            // SAFETY: this allocation remains exclusively owned until published in the atomic word.
            unsafe { (*block).term = copied };
            Ok(allocation.into_raw().as_ptr() as u64)
        }
        Err(error) => {
            // SAFETY: the header was initialized above; dropping it releases linked off-heap owners.
            unsafe { std::ptr::drop_in_place(block) };
            Err(error)
        }
    }
}

/// Release an old heap block after any thread that loaded its `prt->data` word has quiesced.
// Port of erts/emulator/beam/erl_bif_port.c:626-636 (`cleanup_old_port_data`) and
// erl_process.c (`erts_schedule_thr_prgr_later_cleanup_op`), OTP-29.1.1.
pub(super) fn retire_data(word: u64, scheduler: &Scheduler<Process>) {
    if word == 0 || word & 3 != 0 {
        return;
    }
    let pointer = word as *mut PortDataBlock;
    // SAFETY: the atomic exchange transferred ownership of this live block; `hsize` and the
    // later-op node are read before enqueue, and the block stays alive until `free_port_data_heap`.
    let (hsize, lop) = unsafe { ((*pointer).hsize, &raw mut (*pointer).later_op) };
    let (layout, _) = Layout::new::<PortDataBlock>()
        .extend(Layout::array::<std::mem::MaybeUninit<u64>>(hsize).expect("valid port heap size"))
        .expect("valid port data layout");
    let size = layout.pad_to_align().size();
    scheduler.erts_schedule_thr_prgr_later_cleanup_op(
        free_port_data_heap,
        pointer.cast(),
        lop,
        size,
    );
}

fn free_port_data_heap(data: *mut ()) {
    let pointer = data.cast::<PortDataBlock>();
    // SAFETY: this later op runs once after thread progress; `hsize` recovers the allocation.
    let hsize = unsafe { (*pointer).hsize };
    let (layout, _) = Layout::new::<PortDataBlock>()
        .extend(Layout::array::<std::mem::MaybeUninit<u64>>(hsize).expect("valid port heap size"))
        .expect("valid port data layout");
    let allocation_words = layout.pad_to_align().size() / std::mem::size_of::<u64>();
    // SAFETY: the exchange transferred this exact live ERTS allocation; thread progress
    // excludes readers.
    unsafe { std::ptr::drop_in_place(pointer) };
    // SAFETY: this non-null pointer and allocation type/word count identify the same live block.
    let allocation = unsafe {
        AllocBlock::from_raw(
            std::ptr::NonNull::new_unchecked(pointer.cast()),
            ErtsAlcType::PORT_DATA_HEAP,
            allocation_words,
        )
    };
    drop(allocation);
}
