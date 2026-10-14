//! OTP 29.1.1 `prim_file` native operations.
//!
//! The stage 4 resource implementation can replace `FileHandle` and its local
//! reference encoding. Each handle is a local ref `[0x46494c45, low32(id),
//! high32(id)]`, backed by a unique, never reused table key. The VM runs every
//! operation flagged `ERL_NIF_DIRTY_JOB_IO_BOUND` in [`NIF_FUNCS`] on a dirty IO
//! scheduler ([`dirty_io`]). The table does not yet receive process death
//! notifications; the VM must close orphaned handles.

mod iovec;

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use arinsal_bifs::{BifError, BifFn, Ctx};
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{ExportEntry, FunEntry, HeapAlloc, Node, Term, from_owned, to_owned};
use num_traits::ToPrimitive;

const MAGIC: u32 = 0x4649_4c45;
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static HANDLES: OnceLock<Mutex<HashMap<u64, Arc<FileHandle>>>> = OnceLock::new();

struct FileHandle {
    file: Mutex<Option<File>>,
}

fn handles() -> &'static Mutex<HashMap<u64, Arc<FileHandle>>> {
    HANDLES.get_or_init(|| Mutex::new(HashMap::new()))
}

struct Heap<'a, H: HeapAlloc + ?Sized>(&'a mut H);
impl<H: HeapAlloc + ?Sized> HeapAlloc for Heap<'_, H> {
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        self.0.alloc(words)
    }
    fn retain_binary(&mut self, value: Arc<arinsal_term::RefcBinary>) {
        self.0.retain_binary(value)
    }
    fn link_bin_ref(
        &mut self,
        bin_ref: *mut u64,
        writable: bool,
        overhead_words: u64,
        owner: Option<arinsal_term::OwnedBinaryRef>,
    ) -> Result<(), arinsal_term::TermError> {
        HeapAlloc::link_bin_ref(self.0, bin_ref, writable, overhead_words, owner)
    }
    fn retain_writable_binary(
        &mut self,
        value: Arc<arinsal_term::WritableBinary>,
    ) -> Result<(), arinsal_term::TermError> {
        self.0.retain_writable_binary(value)
    }
    fn supports_writable_binary(&self) -> bool {
        self.0.supports_writable_binary()
    }
    fn retain_node(&mut self, value: Arc<Node>) {
        self.0.retain_node(value)
    }
    fn retain_fun(&mut self, value: Arc<FunEntry>) {
        self.0.retain_fun(value)
    }
    fn retain_export(&mut self, value: Arc<ExportEntry>) {
        self.0.retain_export(value)
    }
}

/// `prim_file` NIF entries: name, arity, implementation and whether erts flags the entry
/// `ERL_NIF_DIRTY_JOB_IO_BOUND`.
// Port of erts/emulator/nifs/common/prim_file_nif.c:177-219 (nif_funcs), OTP-29.1.1.
const NIF_FUNCS: [(&str, u8, BifFn, bool); 33] = [
    // File handle ops
    ("open_nif", 2, open_nif, true),
    ("close_nif", 1, close_nif, true),
    ("read_nif", 2, read_nif, true),
    ("write_nif", 2, write_nif, true),
    ("pread_nif", 3, pread_nif, true),
    ("pwrite_nif", 3, pwrite_nif, true),
    ("seek_nif", 3, seek_nif, true),
    ("sync_nif", 2, sync_nif, true),
    ("truncate_nif", 1, truncate_nif, true),
    ("allocate_nif", 3, allocate_nif, true),
    ("advise_nif", 4, advise_nif, true),
    ("read_handle_info_nif", 1, read_handle_info_nif, true),
    // Filesystem ops
    ("make_hard_link_nif", 2, make_hard_link_nif, true),
    ("make_soft_link_nif", 2, make_soft_link_nif, true),
    ("rename_nif", 2, rename_nif, true),
    ("read_info_nif", 2, read_info_nif, true),
    ("set_permissions_nif", 2, set_permissions_nif, true),
    ("set_owner_nif", 3, set_owner_nif, true),
    ("set_time_nif", 4, set_time_nif, true),
    ("read_link_nif", 1, read_link_nif, true),
    ("list_dir_nif", 1, list_dir_nif, true),
    ("make_dir_nif", 1, make_dir_nif, true),
    ("del_file_nif", 1, del_file_nif, true),
    ("del_dir_nif", 1, del_dir_nif, true),
    ("get_device_cwd_nif", 1, get_device_cwd_nif, true),
    ("set_cwd_nif", 1, set_cwd_nif, true),
    ("get_cwd_nif", 0, get_cwd_nif, true),
    // These operations are equivalent to chained calls of other operations, but have
    // been moved down to avoid excessive rescheduling.
    ("ipread_s32bu_p32bu_nif", 3, ipread_s32bu_p32bu_nif, true),
    ("read_file_nif", 1, read_file_nif, true),
    // Internal ops.
    ("get_handle_nif", 1, get_handle_nif, false),
    ("delayed_close_nif", 1, delayed_close_nif, true),
    ("altname_nif", 1, altname_nif, true),
    ("file_desc_to_ref_nif", 1, file_desc_to_ref_nif, true),
];

fn entry(module: &str, name: &str, arity: u8) -> Option<&'static (&'static str, u8, BifFn, bool)> {
    if module != "prim_file" {
        return None;
    }
    NIF_FUNCS
        .iter()
        .find(|(entry, entry_arity, _, _)| *entry == name && *entry_arity == arity)
}

/// Return the native implementation for a `prim_file` NIF entry.
pub fn lookup(module: &str, name: &str, arity: u8) -> Option<BifFn> {
    entry(module, name, arity).map(|(_, _, f, _)| *f)
}

/// Whether the `prim_file` NIF `name/arity` runs on a dirty IO scheduler
/// (`ERL_NIF_DIRTY_JOB_IO_BOUND` in erts' `nif_funcs`).
pub fn dirty_io(name: &str, arity: u8) -> bool {
    entry("prim_file", name, arity).is_some_and(|(_, _, _, dirty)| *dirty)
}

type Outcome = Result<O, BifError>;
fn call(
    ctx: &mut Ctx<'_>,
    args: &[Term],
    op: impl FnOnce(&[O]) -> Outcome,
) -> Result<Term, BifError> {
    let args = args
        .iter()
        .map(|arg| to_owned(*arg).map_err(|_| BifError::BADARG))
        .collect::<Result<Vec<_>, _>>()?;
    let result = op(&args)?;
    from_owned(&result, &mut Heap(&mut ctx.heap)).map_err(|_| BifError::SystemLimit)
}
fn atom(name: &str) -> O {
    O::atom(name)
}
fn pair(a: O, b: O) -> O {
    O::Tuple(vec![a, b])
}
fn ok() -> O {
    atom("ok")
}
fn success(value: O) -> O {
    pair(ok(), value)
}
fn error(name: &str) -> O {
    pair(atom("error"), atom(name))
}
fn invalid() -> O {
    error("einval")
}
fn number(value: &O) -> Option<i64> {
    match value {
        O::Int(n) => Some(*n),
        O::BigInt(n) => n.to_i64(),
        _ => None,
    }
}
fn numeric_i64(value: &O) -> Result<Option<i64>, BifError> {
    if matches!(value, O::Int(_) | O::BigInt(_) | O::Float(_)) {
        Ok(number(value))
    } else {
        Err(BifError::BADARG)
    }
}
fn signed(value: &O) -> Result<i64, BifError> {
    number(value).ok_or(BifError::BADARG)
}
fn u32_number(value: &O) -> Result<u32, BifError> {
    signed(value)?.try_into().map_err(|_| BifError::BADARG)
}
fn i32_number(value: &O) -> Result<i32, BifError> {
    signed(value)?.try_into().map_err(|_| BifError::BADARG)
}
fn integer(value: u64) -> O {
    i64::try_from(value)
        .map(O::Int)
        .unwrap_or_else(|_| O::BigInt(value.into()))
}
fn name(value: &O) -> Option<&str> {
    if let O::Atom(s) = value {
        Some(s)
    } else {
        None
    }
}
fn posix(err: &std::io::Error) -> O {
    posix_code(err.raw_os_error().unwrap_or(libc::EINVAL))
}
fn posix_code(code: i32) -> O {
    // Port of erts/emulator/beam/erl_errno_str.c:1229 (erl_errno_id), OTP-29.1.1.
    let name = match code {
        libc::EPERM => "eperm",
        libc::ENOENT => "enoent",
        libc::ESRCH => "esrch",
        libc::EINTR => "eintr",
        libc::EIO => "eio",
        libc::ENXIO => "enxio",
        libc::E2BIG => "e2big",
        libc::ENOEXEC => "enoexec",
        libc::EBADF => "ebadf",
        libc::ECHILD => "echild",
        libc::EDEADLK => "edeadlk",
        libc::ENOMEM => "enomem",
        libc::EACCES => "eacces",
        libc::EAGAIN => "eagain",
        libc::EFAULT => "efault",
        libc::EBUSY => "ebusy",
        libc::EEXIST => "eexist",
        libc::EXDEV => "exdev",
        libc::ENODEV => "enodev",
        libc::ENOTDIR => "enotdir",
        libc::EISDIR => "eisdir",
        libc::EINVAL => "einval",
        libc::ENFILE => "enfile",
        libc::EMFILE => "emfile",
        libc::ENOTTY => "enotty",
        libc::EFBIG => "efbig",
        libc::ENOSPC => "enospc",
        libc::ESPIPE => "espipe",
        libc::EROFS => "erofs",
        libc::EMLINK => "emlink",
        libc::EPIPE => "epipe",
        libc::EDOM => "edom",
        libc::ERANGE => "erange",
        libc::ENAMETOOLONG => "enametoolong",
        libc::ENOTEMPTY => "enotempty",
        libc::ELOOP => "eloop",
        libc::EOVERFLOW => "eoverflow",
        libc::ENOTSUP => "enotsup",
        libc::EOPNOTSUPP => "eopnotsupp",
        libc::EILSEQ => "eilseq",
        libc::ETIMEDOUT => "etimedout",
        libc::ECANCELED => "ecanceled",
        _ => return error(&format!("errno_{code}")),
    };
    error(name)
}
fn path(value: &O) -> Result<PathBuf, O> {
    // Port of erts/emulator/nifs/unix/unix_prim_file.c:91 (efile_marshal_path), OTP-29.1.1.
    let O::Binary(bytes) = value else {
        return Err(invalid());
    };
    if bytes.is_empty() {
        return Err(invalid());
    }
    let end = bytes.iter().position(|&b| b == 0).ok_or_else(invalid)?;
    if bytes[end..].iter().any(|&b| b != 0) {
        return Err(invalid());
    }
    Ok(PathBuf::from(OsStr::from_bytes(&bytes[..end])))
}
fn path_result(value: &O) -> Result<PathBuf, O> {
    path(value)
}
fn handle_id(value: &O) -> Result<u64, BifError> {
    match value {
        O::Ref {
            node,
            creation,
            ids,
        } if node == "nonode@nohost" && *creation == 0 && ids.len() == 3 && ids[0] == MAGIC => {
            Ok(u64::from(ids[1]) | (u64::from(ids[2]) << 32))
        }
        _ => Err(BifError::BADARG),
    }
}
fn ref_for(file: File) -> O {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    handles().lock().unwrap().insert(
        id,
        Arc::new(FileHandle {
            file: Mutex::new(Some(file)),
        }),
    );
    O::Ref {
        node: "nonode@nohost".into(),
        creation: 0,
        ids: vec![MAGIC, id as u32, (id >> 32) as u32],
    }
}
fn with_file(value: &O, op: impl FnOnce(&mut File) -> Outcome) -> Outcome {
    let id = handle_id(value)?;
    let handle = { handles().lock().unwrap().get(&id).cloned() };
    let Some(handle) = handle else {
        return Ok(invalid());
    };
    let mut guard = handle.file.lock().unwrap();
    let Some(file) = guard.as_mut() else {
        return Ok(invalid());
    };
    op(file)
}
fn close_impl(value: &O) -> Outcome {
    let id = handle_id(value)?;
    let handle = handles().lock().unwrap().remove(&id);
    let Some(handle) = handle else {
        return Ok(invalid());
    };
    let file = handle.file.lock().unwrap().take();
    if file.is_none() {
        return Ok(invalid());
    }
    drop(file);
    Ok(ok())
}
fn read_full(file: &mut File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut done = 0;
    while done < buf.len() {
        match file.read(&mut buf[done..]) {
            Ok(0) => break,
            Ok(n) => done += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(done)
}
fn pread_full(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
    let mut done = 0;
    while done < buf.len() {
        match file.read_at(&mut buf[done..], offset + done as u64) {
            Ok(0) => break,
            Ok(n) => done += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(done)
}
fn open_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        let O::List { elems: modes, tail } = &a[1] else {
            if a[1] == O::Nil {
                return open_modes(&a[0], &[]);
            }
            return Err(BifError::BADARG);
        };
        let _ = tail;
        open_modes(&a[0], modes)
    })
}
fn open_modes(path_arg: &O, modes: &[O]) -> Outcome {
    // Port of erts/emulator/nifs/common/prim_file_nif.c:497 and
    // erts/emulator/nifs/unix/unix_prim_file.c:138 (get_flags), OTP-29.1.1.
    let mut r = false;
    let mut w = false;
    let mut append = false;
    let mut exclusive = false;
    let mut directory = false;
    let mut skip_type = false;
    let mut sync = false;
    for mode in modes {
        match name(mode) {
            Some("read") => r = true,
            Some("write") => w = true,
            Some("append") => append = true,
            Some("exclusive") => exclusive = true,
            Some("directory") => directory = true,
            Some("skip_type_check") => skip_type = true,
            Some("sync") => sync = true,
            _ => {}
        }
    }
    if append || exclusive {
        w = true;
    } else if !r && !w {
        r = true;
    }
    let path = match path_result(path_arg) {
        Ok(p) => p,
        Err(e) => return Ok(e),
    };
    let mut opts = OpenOptions::new();
    opts.read(r)
        .write(w)
        .append(append)
        .create(w)
        .truncate(w && !r && !append)
        .create_new(exclusive);
    opts.custom_flags(
        if directory { libc::O_DIRECTORY } else { 0 } | if sync { libc::O_SYNC } else { 0 },
    );
    match opts.open(&path) {
        Ok(file) => {
            if !directory && !skip_type && file.metadata().is_ok_and(|m| m.is_dir()) {
                return Ok(error("eisdir"));
            }
            Ok(success(ref_for(file)))
        }
        Err(e) => Ok(posix(&e)),
    }
}
fn close_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| close_impl(&a[0]))
}
fn delayed_close_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| close_impl(&a[0]))
}
fn file_desc_to_ref_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        let fd = i32_number(&a[0])?;
        // SAFETY: fcntl only reads the descriptor state and does not take ownership.
        if unsafe { libc::fcntl(fd, libc::F_GETFL) } < 0 {
            return Ok(posix(&std::io::Error::last_os_error()));
        }
        // SAFETY: OTP transfers ownership of this existing file descriptor to the resource.
        Ok(success(ref_for(unsafe { File::from_raw_fd(fd) })))
    })
}
fn read_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        with_file(&a[0], |file| {
            let Some(size) = numeric_i64(&a[1])? else {
                return Ok(invalid());
            };
            if size < 0 {
                return Ok(invalid());
            }
            let Ok(size) = usize::try_from(size) else {
                return Ok(error("enomem"));
            };
            let mut buf = Vec::new();
            if buf.try_reserve_exact(size).is_err() {
                return Ok(error("enomem"));
            }
            buf.resize(size, 0);
            match read_full(file, &mut buf) {
                Ok(0) => Ok(atom("eof")),
                Ok(n) => {
                    buf.truncate(n);
                    Ok(success(O::Binary(buf)))
                }
                Err(e) => Ok(posix(&e)),
            }
        })
    })
}
fn pread_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        with_file(&a[0], |file| {
            let (Some(offset), Some(size)) = (numeric_i64(&a[1])?, numeric_i64(&a[2])?) else {
                return Ok(invalid());
            };
            if offset < 0 || size < 0 {
                return Ok(invalid());
            }
            let Ok(size) = usize::try_from(size) else {
                return Ok(error("enomem"));
            };
            let mut buf = Vec::new();
            if buf.try_reserve_exact(size).is_err() {
                return Ok(error("enomem"));
            }
            buf.resize(size, 0);
            match pread_full(file, &mut buf, offset as u64) {
                Ok(0) => Ok(atom("eof")),
                Ok(n) => {
                    buf.truncate(n);
                    Ok(success(O::Binary(buf)))
                }
                Err(e) => Ok(posix(&e)),
            }
        })
    })
}
/// Run `op` on the open file of handle `handle`; a closed handle is `{error, einval}`.
// Port of erts/emulator/nifs/common/prim_file_nif.c:315-357 (file_handle_wrapper),
// OTP-29.1.1.
fn with_file_term(
    ctx: &mut Ctx<'_>,
    handle: Term,
    op: impl FnOnce(&mut Ctx<'_>, &mut File) -> Result<Term, BifError>,
) -> Result<Term, BifError> {
    let id = handle_id(&to_owned(handle).map_err(|_| BifError::BADARG)?)?;
    let handle = { handles().lock().unwrap().get(&id).cloned() };
    let mut guard = handle.as_ref().map(|handle| handle.file.lock().unwrap());
    match guard.as_mut().and_then(|guard| guard.as_mut()) {
        Some(file) => op(ctx, file),
        None => owned_term(ctx, &invalid()),
    }
}
fn owned_term(ctx: &mut Ctx<'_>, value: &O) -> Result<Term, BifError> {
    from_owned(value, &mut Heap(&mut ctx.heap)).map_err(|_| BifError::SystemLimit)
}
fn atom_term(name: &str) -> Result<Term, BifError> {
    arinsal_term::global_atoms()
        .intern(name)
        .map(Term::atom)
        .map_err(|_| BifError::SystemLimit)
}
fn tuple_term(ctx: &mut Ctx<'_>, values: &[Term]) -> Result<Term, BifError> {
    arinsal_term::TermBuilder::new(&mut Heap(&mut ctx.heap))
        .tuple(values)
        .map_err(|_| BifError::SystemLimit)
}
fn write_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/nifs/common/prim_file_nif.c:688-710 (write_nif_impl),
    // OTP-29.1.1: the iovec references the argument binaries; nothing is copied but
    // on-heap and unaligned binaries.
    with_file_term(ctx, a[0], |ctx, file| {
        let mut copy = Vec::new();
        let mut input = iovec::inspect_iovec(a[1], 64, &mut copy).ok_or(BifError::BADARG)?;
        match iovec::efile_writev(&*file, &mut input) {
            Err(code) => owned_term(ctx, &posix_code(code)),
            Ok(_) if input.tail != Term::NIL => {
                let tail = input.tail;
                tuple_term(ctx, &[atom_term("continue")?, tail])
            }
            Ok(_) => atom_term("ok"),
        }
    })
}
fn pwrite_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/nifs/common/prim_file_nif.c:752-780 (pwrite_nif_impl),
    // OTP-29.1.1.
    with_file_term(ctx, a[0], |ctx, file| {
        let offset = to_owned(a[1]).map_err(|_| BifError::BADARG)?;
        let offset = numeric_i64(&offset)?;
        let mut copy = Vec::new();
        let mut input = iovec::inspect_iovec(a[2], 64, &mut copy).ok_or(BifError::BADARG)?;
        let Some(offset) = offset.filter(|offset| *offset >= 0) else {
            return owned_term(ctx, &invalid());
        };
        match iovec::efile_pwritev(&*file, offset as u64, &mut input) {
            Err(code) => owned_term(ctx, &posix_code(code)),
            Ok(bytes_written) if input.tail != Term::NIL => {
                let tail = input.tail;
                let written = owned_term(ctx, &integer(bytes_written))?;
                tuple_term(ctx, &[atom_term("continue")?, written, tail])
            }
            Ok(_) => atom_term("ok"),
        }
    })
}
fn seek_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        with_file(&a[0], |file| {
            let offset = signed(&a[2])?;
            let from = match name(&a[1]) {
                Some("bof") if offset >= 0 => SeekFrom::Start(offset as u64),
                Some("bof") => return Ok(invalid()),
                Some("cur") => SeekFrom::Current(offset),
                Some("eof") => SeekFrom::End(offset),
                _ => return Err(BifError::BADARG),
            };
            Ok(file
                .seek(from)
                .map(|n| success(integer(n)))
                .unwrap_or_else(|e| posix(&e)))
        })
    })
}
fn sync_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        with_file(&a[0], |file| {
            let data_only = i32_number(&a[1])?;
            let result = if data_only == 0 {
                file.sync_all()
            } else {
                file.sync_data()
            };
            Ok(result.map(|()| ok()).unwrap_or_else(|e| posix(&e)))
        })
    })
}
fn truncate_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        with_file(&a[0], |file| {
            let position = match file.stream_position() {
                Ok(p) => p,
                Err(e) => return Ok(posix(&e)),
            };
            Ok(file
                .set_len(position)
                .map(|()| ok())
                .unwrap_or_else(|e| posix(&e)))
        })
    })
}
fn advise_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        with_file(&a[0], |_| {
            let (Some(offset), Some(length)) = (numeric_i64(&a[1])?, numeric_i64(&a[2])?) else {
                return Ok(invalid());
            };
            if offset < 0
                || length < 0
                || !matches!(
                    name(&a[3]),
                    Some(
                        "normal" | "random" | "sequential" | "will_need" | "dont_need" | "no_reuse"
                    )
                )
            {
                return Ok(invalid());
            }
            // macOS has no POSIX_FADVISE; OTP treats advice as successful.
            Ok(ok())
        })
    })
}
fn allocate_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        with_file(&a[0], |file| {
            let (Some(offset), Some(length)) = (numeric_i64(&a[1])?, numeric_i64(&a[2])?) else {
                return Ok(invalid());
            };
            let Some(end) = offset
                .checked_add(length)
                .filter(|_| offset >= 0 && length >= 0)
            else {
                return Ok(invalid());
            };
            let old = match file.metadata() {
                Ok(m) => m.len(),
                Err(e) => return Ok(posix(&e)),
            };
            if end as u64 <= old {
                return Ok(ok());
            }
            // Port of erts/emulator/nifs/unix/unix_prim_file.c:600 (efile_allocate), OTP-29.1.1.
            let mut request = libc::fstore_t {
                fst_flags: libc::F_ALLOCATECONTIG,
                fst_posmode: libc::F_PEOFPOSMODE,
                fst_offset: 0,
                fst_length: end - old as i64,
                fst_bytesalloc: 0,
            };
            // SAFETY: request is initialized and file owns a valid descriptor.
            let mut ret =
                unsafe { libc::fcntl(file.as_raw_fd(), libc::F_PREALLOCATE, &mut request) };
            if ret < 0 {
                request.fst_flags = libc::F_ALLOCATEALL;
                // SAFETY: request remains initialized and file owns the descriptor.
                ret = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_PREALLOCATE, &mut request) };
            }
            if ret < 0 {
                return Ok(posix(&std::io::Error::last_os_error()));
            }
            Ok(file
                .set_len(end as u64)
                .map(|()| ok())
                .unwrap_or_else(|e| posix(&e)))
        })
    })
}
fn get_handle_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        with_file(&a[0], |file| {
            Ok(O::Binary(file.as_raw_fd().to_ne_bytes().to_vec()))
        })
    })
}
fn ipread_s32bu_p32bu_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        with_file(&a[0], |file| {
            let (Some(offset), Some(max)) = (numeric_i64(&a[1])?, numeric_i64(&a[2])?) else {
                return Ok(invalid());
            };
            if offset < 0 || max >= 1_i64 << 31 {
                return Ok(invalid());
            }
            let mut pointer = [0; 8];
            match pread_full(file, &mut pointer, offset as u64) {
                Ok(8) => {}
                Ok(_) => return Ok(atom("eof")),
                Err(e) => return Ok(posix(&e)),
            }
            let size = u32::from_be_bytes(pointer[..4].try_into().unwrap());
            let target = u32::from_be_bytes(pointer[4..].try_into().unwrap());
            if i64::from(size) > max {
                return Ok(atom("eof"));
            }
            let mut data = Vec::new();
            if data.try_reserve_exact(size as usize).is_err() {
                return Ok(error("enomem"));
            }
            data.resize(size as usize, 0);
            let payload = match pread_full(file, &mut data, u64::from(target)) {
                Ok(0) => atom("eof"),
                Ok(n) => {
                    data.truncate(n);
                    O::Binary(data)
                }
                Err(e) => return Ok(posix(&e)),
            };
            Ok(success(O::Tuple(vec![
                O::Int(i64::from(size)),
                O::Int(i64::from(target)),
                payload,
            ])))
        })
    })
}
fn file_info(meta: &fs::Metadata, access: &str) -> O {
    // Port of erts/emulator/nifs/common/prim_file_nif.c:996 (build_file_info) and
    // erts/emulator/nifs/unix/unix_prim_file.c:699 (build_file_info), OTP-29.1.1.
    let kind = meta.file_type();
    let file_type = if kind.is_dir() {
        "directory"
    } else if kind.is_file() {
        "regular"
    } else if kind.is_symlink() {
        "symlink"
    } else if meta.mode() & u32::from(libc::S_IFMT) == u32::from(libc::S_IFCHR)
        || meta.mode() & u32::from(libc::S_IFMT) == u32::from(libc::S_IFBLK)
    {
        "device"
    } else {
        "other"
    };
    O::Tuple(vec![
        atom("file_info"),
        integer(meta.len()),
        atom(file_type),
        atom(access),
        O::Int(meta.atime().clamp(-2_145_916_800, 253_402_300_799)),
        O::Int(meta.mtime().clamp(-2_145_916_800, 253_402_300_799)),
        O::Int(meta.ctime().clamp(-2_145_916_800, 253_402_300_799)),
        integer(u64::from(meta.mode())),
        integer(meta.nlink()),
        integer(meta.dev() as u32 as u64),
        integer(meta.rdev() as u32 as u64),
        integer(meta.ino() as u32 as u64),
        integer(u64::from(meta.uid())),
        integer(u64::from(meta.gid())),
    ])
}
fn path_access(path: &Path) -> String {
    let read = rustix::fs::access(path, rustix::fs::Access::READ_OK).is_ok();
    let write = rustix::fs::access(path, rustix::fs::Access::WRITE_OK).is_ok();
    match (read, write) {
        (true, true) => "read_write",
        (true, false) => "read",
        (false, true) => "write",
        _ => "none",
    }
    .into()
}
fn handle_access(meta: &fs::Metadata) -> &'static str {
    let mode = meta.mode();
    // SAFETY: geteuid/getegid are side-effect-free process credential queries.
    let uid = unsafe { libc::geteuid() };
    // SAFETY: getegid is a side-effect-free process credential query.
    let gid = unsafe { libc::getegid() };
    let bits = if uid == meta.uid() {
        (mode >> 6) & 7
    } else if gid == meta.gid() {
        (mode >> 3) & 7
    } else {
        mode & 7
    };
    match (bits & 4 != 0, bits & 2 != 0) {
        (true, true) => "read_write",
        (true, false) => "read",
        (false, true) => "write",
        _ => "none",
    }
}
fn read_info_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        let follow = i32_number(&a[1])? != 0;
        let path = match path_result(&a[0]) {
            Ok(p) => p,
            Err(e) => return Ok(e),
        };
        let meta = if follow {
            fs::metadata(&path)
        } else {
            fs::symlink_metadata(&path)
        };
        Ok(meta
            .map(|m| file_info(&m, &path_access(&path)))
            .unwrap_or_else(|e| posix(&e)))
    })
}
fn read_handle_info_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        with_file(&a[0], |file| {
            Ok(file
                .metadata()
                .map(|m| {
                    let access = handle_access(&m);
                    file_info(&m, access)
                })
                .unwrap_or_else(|e| posix(&e)))
        })
    })
}
fn read_file_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        let path = match path_result(&a[0]) {
            Ok(p) => p,
            Err(e) => return Ok(e),
        };
        if fs::metadata(&path).is_ok_and(|m| m.is_dir()) {
            return Ok(error("eisdir"));
        }
        Ok(fs::read(path)
            .map(|data| success(O::Binary(data)))
            .unwrap_or_else(|e| posix(&e)))
    })
}
fn list_dir_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        let path = match path_result(&a[0]) {
            Ok(p) => p,
            Err(e) => return Ok(e),
        };
        let entries = match fs::read_dir(path) {
            Ok(e) => e,
            Err(e) => return Ok(posix(&e)),
        };
        let mut names = Vec::new();
        for entry in entries {
            match entry {
                Ok(e) => names.push(O::Binary(e.file_name().into_vec())),
                Err(e) => return Ok(posix(&e)),
            }
        }
        Ok(success(O::list(names)))
    })
}
fn read_link_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        let path = match path_result(&a[0]) {
            Ok(p) => p,
            Err(e) => return Ok(e),
        };
        Ok(fs::read_link(path)
            .map(|target| success(O::Binary(target.into_os_string().into_vec())))
            .unwrap_or_else(|e| posix(&e)))
    })
}
fn unary_path(
    ctx: &mut Ctx<'_>,
    a: &[Term],
    op: impl FnOnce(PathBuf) -> std::io::Result<()>,
) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        let path = match path_result(&a[0]) {
            Ok(p) => p,
            Err(e) => return Ok(e),
        };
        Ok(op(path).map(|()| ok()).unwrap_or_else(|e| posix(&e)))
    })
}
fn binary_path(
    ctx: &mut Ctx<'_>,
    a: &[Term],
    op: impl FnOnce(PathBuf, PathBuf) -> std::io::Result<()>,
) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        let first = match path_result(&a[0]) {
            Ok(p) => p,
            Err(e) => return Ok(e),
        };
        let second = match path_result(&a[1]) {
            Ok(p) => p,
            Err(e) => return Ok(e),
        };
        Ok(op(first, second)
            .map(|()| ok())
            .unwrap_or_else(|e| posix(&e)))
    })
}
fn make_dir_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    unary_path(ctx, a, fs::create_dir)
}
fn del_file_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    unary_path(ctx, a, fs::remove_file)
}
fn del_dir_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    unary_path(ctx, a, fs::remove_dir)
}
fn rename_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    binary_path(ctx, a, fs::rename)
}
fn make_hard_link_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    binary_path(ctx, a, fs::hard_link)
}
fn make_soft_link_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    binary_path(ctx, a, std::os::unix::fs::symlink)
}
fn get_cwd_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |_| {
        Ok(std::env::current_dir()
            .map(|p| success(O::Binary(p.into_os_string().into_vec())))
            .unwrap_or_else(|e| posix(&e)))
    })
}
fn set_cwd_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    unary_path(ctx, a, std::env::set_current_dir)
}
fn get_device_cwd_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        i32_number(&a[0])?;
        Ok(error("enotsup"))
    })
}
fn altname_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| match path_result(&a[0]) {
        Ok(_) => Ok(error("enotsup")),
        Err(e) => Ok(e),
    })
}
fn set_permissions_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        let mode = u32_number(&a[1])? & 0o7777;
        let path = match path_result(&a[0]) {
            Ok(p) => p,
            Err(e) => return Ok(e),
        };
        // Port of erts/emulator/nifs/unix/unix_prim_file.c:819
        // (efile_set_permissions), OTP-29.1.1.
        let result = fs::set_permissions(&path, fs::Permissions::from_mode(mode))
            .or_else(|_| fs::set_permissions(&path, fs::Permissions::from_mode(mode & !0o6000)));
        Ok(result.map(|()| ok()).unwrap_or_else(|e| posix(&e)))
    })
}
fn set_owner_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        let uid = i32_number(&a[1])?;
        let gid = i32_number(&a[2])?;
        let path = match path_result(&a[0]) {
            Ok(p) => p,
            Err(e) => return Ok(e),
        };
        // chown(2) with the raw ids; -1 leaves an id unchanged.
        let owner = (uid != -1).then(|| rustix::fs::Uid::from_raw_unchecked(uid as u32));
        let group = (gid != -1).then(|| rustix::fs::Gid::from_raw_unchecked(gid as u32));
        Ok(rustix::fs::chown(&path, owner, group)
            .map(|()| ok())
            .unwrap_or_else(|e| posix(&e.into())))
    })
}
fn set_time_nif(ctx: &mut Ctx<'_>, a: &[Term]) -> Result<Term, BifError> {
    call(ctx, a, |a| {
        let atime = signed(&a[1])?;
        let mtime = signed(&a[2])?;
        let _ctime = signed(&a[3])?;
        let path = match path_result(&a[0]) {
            Ok(p) => p,
            Err(e) => return Ok(e),
        };
        // Port of erts/emulator/nifs/unix/unix_prim_file.c:844 (efile_set_time), OTP-29.1.1.
        // utimensat updates metadata without opening the file, as utime does in erts.
        let times = rustix::fs::Timestamps {
            last_access: rustix::fs::Timespec {
                tv_sec: atime,
                tv_nsec: 0,
            },
            last_modification: rustix::fs::Timespec {
                tv_sec: mtime,
                tv_nsec: 0,
            },
        };
        Ok(
            rustix::fs::utimensat(rustix::fs::CWD, &path, &times, rustix::fs::AtFlags::empty())
                .map(|()| ok())
                .unwrap_or_else(|e| posix(&e.into())),
        )
    })
}
