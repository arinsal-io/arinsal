//! `nif_setopt`, `nif_getopt`, `nif_info` and `nif_command`.

use super::*;

/// How the value of a native option is encoded. The names are `esock_setopt_bool_opt`
/// and friends.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OptKind {
    Bool,
    Int,
    Linger,
    /// Readable only, `SO_TYPE`.
    SocketType,
    /// `IP_TOS`: an integer, a TOS or DSCP name, or a precedence and TOS map.
    IpTos,
    Other,
}

fn option_kind(level: i32, opt: i32) -> OptKind {
    match (level, opt) {
        (
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR
            | libc::SO_KEEPALIVE
            | libc::SO_REUSEPORT
            | libc::SO_DONTROUTE
            | libc::SO_BROADCAST
            | libc::SO_OOBINLINE
            | libc::SO_DEBUG,
        ) => OptKind::Bool,
        (
            libc::SOL_SOCKET,
            libc::SO_RCVBUF | libc::SO_SNDBUF | libc::SO_RCVLOWAT | libc::SO_SNDLOWAT,
        ) => OptKind::Int,
        (libc::SOL_SOCKET, libc::SO_LINGER) => OptKind::Linger,
        (libc::SOL_SOCKET, libc::SO_TYPE) => OptKind::SocketType,
        (libc::IPPROTO_TCP, libc::TCP_NODELAY) => OptKind::Bool,
        (libc::IPPROTO_TCP, libc::TCP_KEEPCNT | libc::TCP_KEEPINTVL) => OptKind::Int,
        (libc::IPPROTO_IP, libc::IP_RECVTOS | libc::IP_RECVTTL | libc::IP_MULTICAST_LOOP) => {
            OptKind::Bool
        }
        (libc::IPPROTO_IP, libc::IP_TTL | libc::IP_MULTICAST_TTL) => OptKind::Int,
        (libc::IPPROTO_IP, libc::IP_TOS) => OptKind::IpTos,
        (libc::IPPROTO_IPV6, libc::IPV6_V6ONLY | libc::IPV6_MULTICAST_LOOP) => OptKind::Bool,
        (
            libc::IPPROTO_IPV6,
            libc::IPV6_UNICAST_HOPS | libc::IPV6_MULTICAST_HOPS | libc::IPV6_TCLASS,
        ) => OptKind::Int,
        _ => OptKind::Other,
    }
}

const DSCP_SHIFT: i32 = 2;
const DSCP_MASK: i32 = 0xfc;
const TOS_SHIFT: i32 = 1;
const TOS_MASK: i32 = 0x1e;
const TOS_PREC_SHIFT: i32 = 5;
const TOS_PREC_MASK: i32 = 0xe0;
const DSCP_NAMES: [(&str, i32); 24] = [
    ("cs0", 0),
    ("cs1", 8),
    ("cs2", 16),
    ("cs3", 24),
    ("cs4", 32),
    ("cs5", 40),
    ("cs6", 48),
    ("cs7", 56),
    ("af11", 10),
    ("af12", 12),
    ("af13", 14),
    ("af21", 18),
    ("af22", 20),
    ("af23", 22),
    ("af31", 26),
    ("af32", 28),
    ("af33", 30),
    ("af41", 34),
    ("af42", 36),
    ("af43", 38),
    ("ef", 46),
    ("voice_admit", 44),
    ("le", 1),
    ("nqb", 45),
];
const TOS_NAMES: [(&str, i32); 5] = [
    ("lowdelay", 8),
    ("throughput", 4),
    ("reliability", 2),
    ("mincost", 1),
    ("default", 0),
];
const PRECEDENCE_NAMES: [(&str, i32); 8] = [
    ("netcontrol", 56),
    ("internetcontrol", 48),
    ("critical_ecp", 40),
    ("flashoverride", 32),
    ("flash", 24),
    ("immediate", 16),
    ("priority", 8),
    ("routine", 0),
];

fn named(table: &[(&str, i32)], value: &O) -> Option<i32> {
    let text = name(value)?;
    table
        .iter()
        .find(|(name, _)| *name == text)
        .map(|(_, v)| *v)
}

fn unsigned_char(value: &O) -> Option<i32> {
    number(value)
        .and_then(|n| u32::try_from(n).ok())
        .map(|n| i32::from(n as u8))
}

/// `decode_ip_tos`.
fn decode_ip_tos(value: &O) -> Option<i32> {
    match value {
        O::Int(n) => i32::try_from(*n).ok(),
        O::Atom(_) => named(&TOS_NAMES[..4], value)
            .map(|tos| tos << TOS_SHIFT)
            .or_else(|| named(&DSCP_NAMES, value).map(|dscp| dscp << DSCP_SHIFT)),
        O::Map(_) => {
            let precedence = field(value, "precedence")?;
            let tos = field(value, "tos")?;
            let precedence = if is_integer(precedence) {
                unsigned_char(precedence)?
            } else {
                named(&PRECEDENCE_NAMES, precedence)?
            };
            let tos = if is_integer(tos) {
                unsigned_char(tos)?
            } else {
                named(&TOS_NAMES, tos)?
            };
            Some(((precedence << TOS_PREC_SHIFT) & TOS_PREC_MASK) | ((tos << TOS_SHIFT) & TOS_MASK))
        }
        _ => None,
    }
}

/// `encode_ip_tos`: `#{native, tos, dscp}`.
pub(super) fn encode_ip_tos(value: i32) -> O {
    let by_value = |table: &[(&str, i32)], number: i32| {
        table
            .iter()
            .find(|(_, v)| *v == number)
            .map_or_else(|| O::Int(number.into()), |(name, _)| atom(name))
    };
    let precedence = by_value(&PRECEDENCE_NAMES, (value & TOS_PREC_MASK) >> TOS_PREC_SHIFT);
    let tos = by_value(&TOS_NAMES, (value & TOS_MASK) >> TOS_SHIFT);
    let dscp = by_value(&DSCP_NAMES, (value & DSCP_MASK) >> DSCP_SHIFT);
    map(&[
        ("native", O::Int(value.into())),
        ("tos", map(&[("precedence", precedence), ("tos", tos)])),
        ("dscp", dscp),
    ])
}

/// `esock_make_error_integer_range`: `{invalid, {integer_range, Value}}`.
fn integer_range(value: &O) -> O {
    pair(atom("invalid"), pair(atom("integer_range"), value.clone()))
}

fn is_integer(value: &O) -> bool {
    matches!(value, O::Int(_) | O::BigInt(_))
}

/// `esock_decode_bool`.
fn decode_bool(value: &O) -> Option<bool> {
    match name(value) {
        Some("true") => Some(true),
        Some("false") => Some(false),
        _ => None,
    }
}

/// `esock_decode_bufsz`: a positive size or `default`.
pub(super) fn decode_bufsz(value: &O, default: i64) -> Option<i64> {
    match value {
        O::Int(size) if *size > 0 => Some(*size),
        O::Atom(text) if text == "default" => Some(default),
        _ => None,
    }
}

/// `esock_make_invalid(env, value)`.
fn invalid_value() -> O {
    invalid("value")
}

/// `esock_raise_invalid(env, {otp_socket_option, Opt})`.
fn raise_otp_option(opt: i32) -> BifError {
    crate::raise(pair(
        atom("invalid"),
        pair(atom("otp_socket_option"), O::Int(opt.into())),
    ))
}

pub(super) fn option(args: &[O], set: bool) -> Result<O, BifError> {
    let h = handle(&args[0])?;
    let native = if set {
        i32::try_from(number(&args[4]).ok_or(BifError::BADARG)?).map_err(|_| BifError::BADARG)?
    } else {
        0
    };
    let opt = match &args[2] {
        O::Int(n) => match i32::try_from(*n) {
            Ok(opt) => opt,
            Err(_) => return Ok(integer_range(&args[2])),
        },
        other if is_integer(other) => return Ok(integer_range(other)),
        _ => return Err(BifError::BADARG),
    };
    if name(&args[1]) == Some("otp") && (set || args.len() == 3) {
        if native != 0 {
            return Err(BifError::BADARG);
        }
        return if set {
            setopt_otp(&h, opt, &args[3])
        } else {
            getopt_otp(&h, opt)
        };
    }
    let level = match &args[1] {
        O::Atom(text) if text == "socket" => libc::SOL_SOCKET,
        O::Int(n) => match i32::try_from(*n) {
            Ok(level) => level,
            Err(_) => return Ok(integer_range(&args[1])),
        },
        other if is_integer(other) => return Ok(integer_range(other)),
        _ => return Err(BifError::BADARG),
    };
    if set {
        setopt(&h, level, opt, &args[3], native != 0)
    } else {
        getopt(&h, level, opt, &args[3..])
    }
}

fn setopt_otp(h: &Handle, opt: i32, value: &O) -> Result<O, BifError> {
    let mut st = h.state.lock().unwrap();
    let flag_option = |st: &State, open_state: u32, opt: i32| -> Option<O> {
        let _ = st;
        if !state_bits::is_open(open_state) {
            return Some(error("closed"));
        }
        match decode_bool(value) {
            Some(flag) => {
                h.otp_options.lock().unwrap().insert(opt, bool_atom(flag));
                None
            }
            None => Some(invalid_value()),
        }
    };
    match opt {
        OTP_OPT_DEBUG | OTP_OPT_IOW => {
            let state = st.write_state;
            Ok(flag_option(&st, state, opt).unwrap_or_else(|| atom("ok")))
        }
        OTP_OPT_SELECT_READ => {
            let state = st.read_state;
            Ok(flag_option(&st, state, opt).unwrap_or_else(|| atom("ok")))
        }
        OTP_OPT_CTRL_PROC => Ok(setopt_otp_ctrl_proc(h, &mut st, value)),
        OTP_OPT_RCVBUF => Ok(setopt_otp_rcvbuf(h, &st, value)),
        OTP_OPT_RCVCTRLBUF | OTP_OPT_SNDCTRLBUF => {
            let (state, default) = if opt == OTP_OPT_RCVCTRLBUF {
                (st.read_state, RECV_CTRL_BUFFER_SIZE_DEFAULT)
            } else {
                (st.write_state, SEND_CTRL_BUFFER_SIZE_DEFAULT)
            };
            if !state_bits::is_open(state) {
                return Ok(error("closed"));
            }
            Ok(match decode_bufsz(value, default) {
                Some(size) => {
                    h.otp_options.lock().unwrap().insert(opt, O::Int(size));
                    atom("ok")
                }
                None => invalid_value(),
            })
        }
        OTP_OPT_META => {
            if !state_bits::is_open(st.write_state) {
                return Ok(error("closed"));
            }
            let Some(me) = self_pid() else {
                return Err(BifError::BADARG);
            };
            if h.owner.lock().unwrap().as_ref() != Some(&me) {
                return Ok(error_invalid("not_owner"));
            }
            h.otp_options.lock().unwrap().insert(opt, value.clone());
            Ok(atom("ok"))
        }
        OTP_OPT_USE_REGISTRY => {
            if !state_bits::is_open(st.write_state) {
                return Ok(error("closed"));
            }
            if decode_bool(value) != Some(true) {
                return Ok(invalid_value());
            }
            if !use_reg(h) {
                h.otp_options
                    .lock()
                    .unwrap()
                    .insert(OTP_OPT_USE_REGISTRY, atom("true"));
                send_reg_msg("add", h);
            }
            Ok(atom("ok"))
        }
        _ => Err(raise_otp_option(opt)),
    }
}

/// `esock_setopt_otp_ctrl_proc`: the owner hands the socket to a new controlling
/// process and the controlling process monitor moves with it.
fn setopt_otp_ctrl_proc(h: &Handle, st: &mut State, value: &O) -> O {
    if !state_bits::is_open(st.write_state) {
        return error("closed");
    }
    let Some(me) = self_pid() else {
        return error("closed");
    };
    if h.owner.lock().unwrap().as_ref() != Some(&me) {
        return error_invalid("not_owner");
    }
    let O::Pid { node, .. } = value else {
        return invalid_value();
    };
    if node != "nonode@nohost" {
        return invalid_value();
    }
    demonitor_process(&me, st.ctrl_mon.take());
    *h.owner.lock().unwrap() = Some(value.clone());
    match monitor_process(h, value) {
        Some(monitor) => st.ctrl_mon = Some(monitor),
        None => {
            *h.owner.lock().unwrap() = None;
            let mut guard = h.socket.lock().unwrap();
            lifecycle::down_ctrl(h, &mut guard, st);
            st.read_state |= state_bits::CLOSING;
            st.write_state |= state_bits::CLOSING;
        }
    }
    atom("ok")
}

/// `esock_setopt_otp_rcvbuf`: `default | pos_integer() | {N, default | pos_integer()}`.
fn setopt_otp_rcvbuf(h: &Handle, st: &State, value: &O) -> O {
    if !state_bits::is_open(st.read_state) {
        return error("closed");
    }
    let (num, size) = match decode_bufsz(value, RECV_BUFFER_SIZE_DEFAULT) {
        Some(size) => (0, size),
        None => {
            let O::Tuple(parts) = value else {
                return invalid_value();
            };
            let [O::Int(num), size] = parts.as_slice() else {
                return invalid_value();
            };
            let (Some(num), Some(size)) = (
                u32::try_from(*num).ok().filter(|num| *num > 0),
                decode_bufsz(size, RECV_BUFFER_SIZE_DEFAULT),
            ) else {
                return invalid_value();
            };
            (num, size)
        }
    };
    let stored = if num == 0 {
        O::Int(size)
    } else {
        pair(O::Int(num.into()), O::Int(size))
    };
    h.otp_options.lock().unwrap().insert(OTP_OPT_RCVBUF, stored);
    atom("ok")
}

fn getopt_otp(h: &Handle, opt: i32) -> Result<O, BifError> {
    let st = h.state.lock().unwrap();
    let options = h.otp_options.lock().unwrap();
    let flag = |opt: i32| options.get(&opt).cloned().unwrap_or_else(|| atom("false"));
    let open_read = state_bits::is_open(st.read_state);
    let open_write = state_bits::is_open(st.write_state);
    let value = match opt {
        OTP_OPT_DEBUG | OTP_OPT_IOW | OTP_OPT_SELECT_READ if open_read => flag(opt),
        OTP_OPT_CTRL_PROC if open_read => h
            .owner
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| atom("undefined")),
        OTP_OPT_RCVBUF if open_read => options
            .get(&opt)
            .cloned()
            .unwrap_or(O::Int(RECV_BUFFER_SIZE_DEFAULT)),
        OTP_OPT_RCVCTRLBUF if open_read => options
            .get(&opt)
            .cloned()
            .unwrap_or(O::Int(RECV_CTRL_BUFFER_SIZE_DEFAULT)),
        OTP_OPT_SNDCTRLBUF if open_write => options
            .get(&opt)
            .cloned()
            .unwrap_or(O::Int(SEND_CTRL_BUFFER_SIZE_DEFAULT)),
        OTP_OPT_FD if open_read => {
            drop(options);
            let guard = h.socket.lock().unwrap();
            let fd = guard.as_ref().map_or(-1, AsRawFd::as_raw_fd);
            return Ok(ok(O::Int(fd.into())));
        }
        OTP_OPT_META if open_write => options
            .get(&opt)
            .cloned()
            .unwrap_or_else(|| atom("undefined")),
        OTP_OPT_USE_REGISTRY => options.get(&opt).cloned().unwrap_or_else(|| atom("false")),
        OTP_OPT_DOMAIN if open_read => atom(h.domain),
        OTP_OPT_DEBUG | OTP_OPT_IOW | OTP_OPT_SELECT_READ | OTP_OPT_CTRL_PROC | OTP_OPT_RCVBUF
        | OTP_OPT_RCVCTRLBUF | OTP_OPT_SNDCTRLBUF | OTP_OPT_FD | OTP_OPT_META | OTP_OPT_DOMAIN => {
            return Ok(error("closed"));
        }
        _ => return Err(raise_otp_option(opt)),
    };
    Ok(ok(value))
}

/// `esock_setopt_level_opt`: `ok | {error, Errno}`.
fn setsockopt_bytes(fd: i32, level: i32, opt: i32, bytes: &[u8]) -> O {
    // SAFETY: bytes is live for the call and its length is the option length.
    let status = unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            bytes.as_ptr().cast(),
            bytes.len() as libc::socklen_t,
        )
    };
    if status < 0 { last_error() } else { atom("ok") }
}

/// `getsockopt(2)` into a buffer of `size` bytes: the bytes the system wrote.
fn getsockopt_bytes(fd: i32, level: i32, opt: i32, size: usize) -> Result<Vec<u8>, O> {
    let mut bytes = vec![0u8; size];
    let mut len = bytes.len() as libc::socklen_t;
    // SAFETY: bytes is writable for len bytes and len starts at its capacity.
    let status = unsafe { libc::getsockopt(fd, level, opt, bytes.as_mut_ptr().cast(), &mut len) };
    if status < 0 {
        return Err(last_error());
    }
    bytes.truncate(len as usize);
    Ok(bytes)
}

fn setopt(h: &Handle, level: i32, opt: i32, value: &O, native: bool) -> Result<O, BifError> {
    let guard = h.socket.lock().unwrap();
    let st = h.state.lock().unwrap();
    let Some(s) = guard.as_ref() else {
        return Ok(error("closed"));
    };
    if !state_bits::is_open(st.write_state) {
        return Ok(error("closed"));
    }
    let fd = s.as_raw_fd();
    if native {
        let bytes = match value {
            O::Binary(bytes) => bytes.clone(),
            O::Int(n) => match i32::try_from(*n) {
                Ok(n) => n.to_ne_bytes().to_vec(),
                Err(_) => return Ok(error_invalid("value")),
            },
            other => match decode_bool(other) {
                Some(flag) => i32::from(flag).to_ne_bytes().to_vec(),
                None => return Ok(error_invalid("value")),
            },
        };
        return Ok(setsockopt_bytes(fd, level, opt, &bytes));
    }
    let bytes = match (option_kind(level, opt), value) {
        (OptKind::SocketType, _) => return Ok(invalid("socket_option")),
        (OptKind::IpTos, other) => match decode_ip_tos(other) {
            Some(tos) => tos.to_ne_bytes().to_vec(),
            None => return Ok(invalid_value()),
        },
        (OptKind::Linger, O::Atom(text)) if text == "abort" => encode_linger(1, 0),
        (OptKind::Linger, O::Map(_)) => {
            let onoff = field(value, "onoff").and_then(decode_bool);
            let linger = field(value, "linger")
                .and_then(number)
                .and_then(|n| i32::try_from(n).ok())
                .filter(|n| *n >= 0);
            match (onoff, linger) {
                (Some(onoff), Some(linger)) => encode_linger(i32::from(onoff), linger),
                _ => return Ok(invalid_value()),
            }
        }
        (OptKind::Linger, _) => return Ok(invalid_value()),
        (OptKind::Bool, other) => match decode_bool(other) {
            Some(flag) => i32::from(flag).to_ne_bytes().to_vec(),
            None => return Ok(invalid_value()),
        },
        (OptKind::Int, O::Int(n)) => match i32::try_from(*n) {
            Ok(n) => n.to_ne_bytes().to_vec(),
            Err(_) => return Ok(invalid_value()),
        },
        (OptKind::Int, _) => return Ok(invalid_value()),
        (OptKind::Other, O::Atom(text)) if text == "true" || text == "false" => {
            i32::from(text == "true").to_ne_bytes().to_vec()
        }
        (OptKind::Other, O::Int(n)) => match i32::try_from(*n) {
            Ok(n) => n.to_ne_bytes().to_vec(),
            Err(_) => return Err(BifError::BADARG),
        },
        (OptKind::Other, _) => return Ok(invalid_value()),
    };
    Ok(setsockopt_bytes(fd, level, opt, &bytes))
}

fn encode_linger(onoff: i32, linger: i32) -> Vec<u8> {
    let mut bytes = onoff.to_ne_bytes().to_vec();
    bytes.extend(linger.to_ne_bytes());
    bytes
}

/// `args` is the rest of the getopt arguments: nothing, or the kind and its value.
fn getopt(h: &Handle, level: i32, opt: i32, args: &[O]) -> Result<O, BifError> {
    let guard = h.socket.lock().unwrap();
    let st = h.state.lock().unwrap();
    let Some(s) = guard.as_ref() else {
        return Ok(error("closed"));
    };
    if !state_bits::is_open(st.read_state) {
        return Ok(error("closed"));
    }
    let fd = s.as_raw_fd();
    if args.len() == 2 && name(&args[0]) == Some("native") {
        let size = match &args[1] {
            O::Int(n) if *n > 0 && *n <= 65536 => *n as usize,
            O::Binary(value) if !value.is_empty() && value.len() <= 65536 => value.len(),
            _ => return Ok(invalid_value()),
        };
        return Ok(match getsockopt_bytes(fd, level, opt, size) {
            Ok(bytes) => ok(O::Binary(bytes)),
            Err(error) => error,
        });
    }
    if args.len() == 2 && name(&args[0]) != Some("value") {
        return Ok(invalid_value());
    }
    let kind = option_kind(level, opt);
    let size = if kind == OptKind::Linger { 8 } else { 4 };
    let bytes = match getsockopt_bytes(fd, level, opt, size) {
        Ok(bytes) => bytes,
        Err(error) => return Ok(error),
    };
    let int = |at: usize| {
        bytes
            .get(at..at + 4)
            .and_then(|part| <[u8; 4]>::try_from(part).ok())
            .map(i32::from_ne_bytes)
            .unwrap_or_default()
    };
    Ok(match kind {
        OptKind::Linger => ok(map(&[
            ("onoff", bool_atom(int(0) != 0)),
            ("linger", O::Int(int(4).into())),
        ])),
        OptKind::Bool => ok(bool_atom(int(0) != 0)),
        OptKind::IpTos => ok(encode_ip_tos(int(0))),
        OptKind::SocketType => ok(match int(0) {
            libc::SOCK_STREAM => atom("stream"),
            libc::SOCK_DGRAM => atom("dgram"),
            libc::SOCK_RAW => atom("raw"),
            libc::SOCK_SEQPACKET => atom("seqpacket"),
            other => O::Int(other.into()),
        }),
        _ => ok(O::Int(int(0).into())),
    })
}

/// `esock_socket_info_state`: the state atoms in the order erts lists them.
fn state_atoms(state: u32) -> O {
    let names = [
        (state_bits::BOUND, "bound"),
        (state_bits::LISTENING, "listening"),
        (state_bits::ACCEPTING, "accepting"),
        (state_bits::CONNECTING, "connecting"),
        (state_bits::CONNECTED, "connected"),
        (state_bits::SELECTED, "selected"),
        (state_bits::CLOSING, "closing"),
        (state_bits::CLOSED, "closed"),
        (state_bits::DTOR, "dtor"),
    ];
    O::list(
        names
            .into_iter()
            .filter(|(bit, _)| state & bit != 0)
            .map(|(_, text)| atom(text))
            .collect(),
    )
}

pub(super) fn info(value: &O) -> Result<O, BifError> {
    let h = handle(value)?;
    let st = h.state.lock().unwrap();
    let owner = h
        .owner
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_else(|| atom("undefined"));
    let requests = |current: &Option<Requestor>, queue: &VecDeque<Requestor>| {
        O::Int((queue.len() + usize::from(current.is_some())) as i64)
    };
    Ok(map(&[
        ("domain", atom(h.domain)),
        ("type", atom(h.kind)),
        ("protocol", O::Int(h.protocol.into())),
        ("owner", owner),
        ("counters", h.counters.lock().unwrap().term()),
        ("ctype", h.ctype.clone()),
        ("rstates", state_atoms(st.read_state)),
        ("wstates", state_atoms(st.write_state)),
        ("num_readers", requests(&st.current_reader, &st.readers_q)),
        ("num_writers", requests(&st.current_writer, &st.writers_q)),
        (
            "num_acceptors",
            requests(&st.current_acceptor, &st.acceptors_q),
        ),
    ]))
}

pub(super) fn global_info() -> O {
    let totals = totals();
    let counters = map(&[
        ("num_cnt_bits", O::Int(64)),
        ("num_sockets", O::Int(totals.sockets as i64)),
        ("num_dinet", O::Int(totals.dom_inet as i64)),
        ("num_dinet6", O::Int(totals.dom_inet6 as i64)),
        ("num_dlocal", O::Int(totals.dom_local as i64)),
        ("num_tstreams", O::Int(totals.streams as i64)),
        ("num_tdgrams", O::Int(totals.dgrams as i64)),
        ("num_tseqpkgs", O::Int(totals.seqpkgs as i64)),
        ("num_ptcp", O::Int(totals.proto_tcp as i64)),
        ("num_pudp", O::Int(totals.proto_udp as i64)),
        ("num_pip", O::Int(totals.proto_ip as i64)),
        ("num_psctp", O::Int(totals.proto_sctp as i64)),
    ]);
    map(&[
        ("counters", counters),
        ("debug", bool_atom(DEBUG.load(Ordering::Relaxed))),
        (
            "socket_debug",
            bool_atom(SOCKET_DEBUG.load(Ordering::Relaxed)),
        ),
        (
            "use_registry",
            bool_atom(USE_REGISTRY.load(Ordering::Relaxed)),
        ),
        ("iow", atom("false")),
        ("eei", atom("true")),
        ("iov_max", O::Int(1024)),
        (
            "io_backend",
            map(&[("name", atom("unix_essio")), ("sctp", atom("undefined"))]),
        ),
    ])
}

pub(super) fn bool_atom(value: bool) -> O {
    atom(if value { "true" } else { "false" })
}

/// `esock_command`: `debug`, `socket_debug` and `use_registry` take a boolean.
pub(super) fn command(value: &O) -> Result<O, BifError> {
    let command = field(value, "command").ok_or(BifError::BADARG)?;
    let data = field(value, "data").ok_or(BifError::BADARG)?;
    let target = match name(command) {
        Some("debug") => &DEBUG,
        Some("socket_debug") => &SOCKET_DEBUG,
        Some("use_registry") => &USE_REGISTRY,
        _ => {
            return Err(crate::raise(pair(
                atom("invalid"),
                pair(atom("command"), command.clone()),
            )));
        }
    };
    let Some(flag) = decode_bool(data) else {
        return Err(crate::raise(pair(
            atom("invalid"),
            pair(atom("data"), data.clone()),
        )));
    };
    target.store(flag, Ordering::Relaxed);
    Ok(atom("ok"))
}
