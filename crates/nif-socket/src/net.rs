use std::collections::HashSet;
use std::ffi::{CStr, CString};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::ptr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use arinsal_bifs::BifError;
use arinsal_etf::OwnedTerm as O;

use crate::socket::{from_addr, to_addr};
use crate::{atom, error, last_error, list, map, name, number, ok, pair, string};

static SERVICE_DB: Mutex<()> = Mutex::new(());
static DEBUG: AtomicBool = AtomicBool::new(false);

fn cstring(value: &O) -> Result<Option<CString>, BifError> {
    if name(value) == Some("undefined") {
        return Ok(None);
    }
    let text = string(value).ok_or(BifError::BADARG)?;
    CString::new(text).map(Some).map_err(|_| BifError::BADARG)
}
fn sockaddr(addr: *const libc::sockaddr) -> Option<O> {
    if addr.is_null() {
        return None;
    }
    // SAFETY: callers only pass addresses owned by getaddrinfo/getifaddrs while live.
    let family = unsafe { (*addr).sa_family as i32 };
    match family {
        libc::AF_INET => {
            // SAFETY: AF_INET identifies a sockaddr_in.
            let a = unsafe { &*(addr as *const libc::sockaddr_in) };
            Some(from_addr(SocketAddr::new(
                Ipv4Addr::from(a.sin_addr.s_addr.to_ne_bytes()).into(),
                u16::from_be(a.sin_port),
            )))
        }
        libc::AF_INET6 => {
            // SAFETY: AF_INET6 identifies a sockaddr_in6.
            let a = unsafe { &*(addr as *const libc::sockaddr_in6) };
            Some(from_addr(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(a.sin6_addr.s6_addr),
                u16::from_be(a.sin6_port),
                a.sin6_flowinfo,
                a.sin6_scope_id,
            ))))
        }
        #[cfg(target_os = "linux")]
        libc::AF_PACKET => {
            // Port of erts/emulator/nifs/common/socket_util.c (esock_encode_sockaddr_ll and
            // the esock_encode_packet_* helpers), OTP-29.1.1.
            // SAFETY: AF_PACKET identifies a sockaddr_ll from getifaddrs.
            let a = unsafe { &*(addr as *const libc::sockaddr_ll) };
            let hatype = match a.sll_hatype {
                libc::ARPHRD_NETROM => atom("netrom"),
                libc::ARPHRD_ETHER => atom("ether"),
                libc::ARPHRD_EETHER => atom("eether"),
                libc::ARPHRD_AX25 => atom("ax25"),
                libc::ARPHRD_PRONET => atom("pronet"),
                libc::ARPHRD_CHAOS => atom("chaos"),
                libc::ARPHRD_IEEE802 => atom("ieee802"),
                libc::ARPHRD_ARCNET => atom("arcnet"),
                libc::ARPHRD_APPLETLK => atom("appletlk"),
                libc::ARPHRD_DLCI => atom("dlci"),
                libc::ARPHRD_ATM => atom("atm"),
                libc::ARPHRD_METRICOM => atom("metricom"),
                libc::ARPHRD_IEEE1394 => atom("ieee1394"),
                libc::ARPHRD_EUI64 => atom("eui64"),
                libc::ARPHRD_INFINIBAND => atom("infiniband"),
                libc::ARPHRD_TUNNEL => atom("tunnel"),
                libc::ARPHRD_TUNNEL6 => atom("tunnel6"),
                libc::ARPHRD_LOOPBACK => atom("loopback"),
                libc::ARPHRD_LOCALTLK => atom("localtlk"),
                libc::ARPHRD_NONE => atom("none"),
                libc::ARPHRD_VOID => atom("void"),
                n => O::Int(n.into()),
            };
            let pkttype = match a.sll_pkttype {
                0 => atom("host"),
                1 => atom("broadcast"),
                2 => atom("multicast"),
                3 => atom("otherhost"),
                4 => atom("outgoing"),
                5 => atom("loopback"),
                6 => atom("user"),
                7 => atom("kernel"),
                n => O::Int(n.into()),
            };
            let halen = usize::from(a.sll_halen).min(a.sll_addr.len());
            Some(map(&[
                ("family", atom("packet")),
                ("protocol", O::Int(u16::from_be(a.sll_protocol).into())),
                ("ifindex", O::Int(a.sll_ifindex.into())),
                ("hatype", hatype),
                ("pkttype", pkttype),
                ("addr", O::Binary(a.sll_addr[..halen].to_vec())),
            ]))
        }
        #[cfg(target_os = "macos")]
        libc::AF_LINK => {
            // Port of erts/emulator/nifs/common/socket_util.c:1599 (esock_encode_sockaddr_dl), OTP-29.1.1.
            let offset = std::mem::offset_of!(libc::sockaddr_dl, sdl_data);
            // SAFETY: the OS-owned sockaddr begins with its allocation length.
            let len = unsafe { *addr.cast::<u8>() } as usize;
            if len < offset {
                return None;
            }
            // SAFETY: the OS-supplied length bounds this live sockaddr.
            let bytes = unsafe { std::slice::from_raw_parts(addr.cast::<u8>(), len) };
            let index = u16::from_ne_bytes([bytes[2], bytes[3]]);
            let kind = match bytes[4] {
                1 => atom("other"),
                6 => atom("ether"),
                0x17 => atom("ppp"),
                0x18 => atom("loop"),
                0x37 => atom("gif"),
                0x38 => atom("faith"),
                0x39 => atom("stf"),
                0xd1 => atom("bridge"),
                n => O::Int(n.into()),
            };
            Some(map(&[
                ("family", atom("link")),
                ("index", O::Int(index.into())),
                ("type", kind),
                ("nlen", O::Int(bytes[5].into())),
                ("alen", O::Int(bytes[6].into())),
                ("slen", O::Int(bytes[7].into())),
                ("data", O::Binary(bytes[offset..].to_vec())),
            ]))
        }
        _ => None,
    }
}
// <netdb.h> values; the libc crate does not export EAI_ADDRFAMILY.
#[cfg(target_os = "linux")]
const EAI_ADDRFAMILY: i32 = -9;
#[cfg(not(target_os = "linux"))]
const EAI_ADDRFAMILY: i32 = 1; // Darwin <netdb.h>

// Port of erts/emulator/nifs/common/prim_net_nif.c (enet_getaddrinfo), OTP-29.1.1.
fn gai_error(code: i32) -> O {
    error(match code {
        EAI_ADDRFAMILY => "eaddrfamily",
        libc::EAI_AGAIN => "eagain",
        libc::EAI_BADFLAGS => "ebadflags",
        libc::EAI_FAIL => "efail",
        libc::EAI_FAMILY => "efamily",
        libc::EAI_MEMORY => "emem",
        libc::EAI_NODATA => "enodata",
        libc::EAI_NONAME => "enoname",
        libc::EAI_SERVICE => "eservice",
        libc::EAI_SOCKTYPE => "esocktype",
        libc::EAI_SYSTEM => "esystem",
        _ => "einval",
    })
}
// Port of erts/emulator/nifs/common/prim_net_nif.c (enet_getnameinfo), OTP-29.1.1.
fn gni_error(code: i32) -> O {
    error(match code {
        libc::EAI_AGAIN => "eagain",
        libc::EAI_BADFLAGS => "ebadflags",
        libc::EAI_FAIL => "efail",
        libc::EAI_FAMILY => "efamily",
        libc::EAI_MEMORY => "emem",
        libc::EAI_NONAME => "enoname",
        libc::EAI_OVERFLOW => "eoverflow",
        libc::EAI_SYSTEM => return last_error(),
        _ => "einval",
    })
}
fn getaddrinfo(args: &[O]) -> Result<O, BifError> {
    let host = cstring(&args[0])?;
    let service = cstring(&args[1])?;
    if host.is_none() && service.is_none() {
        return Err(BifError::BADARG);
    }
    let mut result = ptr::null_mut::<libc::addrinfo>();
    // Port of erts/emulator/nifs/common/prim_net_nif.c:1260 (enet_getaddrinfo), OTP-29.1.1.
    // SAFETY: C strings are alive and result is writable; freeaddrinfo releases the list.
    let status = unsafe {
        libc::getaddrinfo(
            host.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
            service.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
            ptr::null(),
            &mut result,
        )
    };
    if status != 0 {
        return Ok(gai_error(status));
    }
    let mut rows = Vec::new();
    let mut current = result;
    while !current.is_null() {
        // SAFETY: current belongs to the live getaddrinfo linked list.
        let ai = unsafe { &*current };
        if let Some(addr) = sockaddr(ai.ai_addr) {
            let family = if ai.ai_family == libc::AF_INET {
                "inet"
            } else {
                "inet6"
            };
            let kind = match ai.ai_socktype {
                libc::SOCK_STREAM => "stream",
                libc::SOCK_DGRAM => "dgram",
                libc::SOCK_RAW => "raw",
                _ => "unknown",
            };
            // The protocol name is added by prim_net:getaddrinfo/2 from the protocols table.
            let proto = O::Int(ai.ai_protocol.into());
            rows.push(map(&[
                ("family", atom(family)),
                ("socktype", atom(kind)),
                ("protocol", proto),
                ("addr", addr),
            ]));
        }
        current = ai.ai_next;
    }
    // SAFETY: result was returned by getaddrinfo and has not been freed.
    unsafe { libc::freeaddrinfo(result) };
    Ok(ok(O::list(rows)))
}
fn getnameinfo(args: &[O]) -> Result<O, BifError> {
    let Some(addr) = to_addr(&args[0]) else {
        return Ok(error("einval"));
    };
    let flags = if name(&args[1]) == Some("undefined") {
        0
    } else {
        let mut bits = 0;
        for flag in list(&args[1]).ok_or(BifError::BADARG)? {
            bits |= match name(flag) {
                Some("numerichost") => libc::NI_NUMERICHOST,
                Some("numericserv") => libc::NI_NUMERICSERV,
                Some("namereqd") => libc::NI_NAMEREQD,
                Some("dgram") => libc::NI_DGRAM,
                Some("nofqdn") => libc::NI_NOFQDN,
                _ => return Err(BifError::BADARG),
            };
        }
        bits
    };
    let a = socket2::SockAddr::from(addr);
    let mut host = [0 as libc::c_char; 1025];
    let mut service = [0 as libc::c_char; 64];
    // SAFETY: a, host, and service are live; lengths are their actual capacities.
    let code = unsafe {
        libc::getnameinfo(
            a.as_ptr().cast(),
            a.len(),
            host.as_mut_ptr(),
            host.len() as libc::socklen_t,
            service.as_mut_ptr(),
            service.len() as libc::socklen_t,
            flags,
        )
    };
    if code != 0 {
        return Ok(gni_error(code));
    }
    // SAFETY: successful getnameinfo null-terminates both buffers.
    let (host, service) = unsafe {
        (
            CStr::from_ptr(host.as_ptr()),
            CStr::from_ptr(service.as_ptr()),
        )
    };
    Ok(ok(map(&[
        ("host", O::charlist(&host.to_string_lossy())),
        ("service", O::charlist(&service.to_string_lossy())),
    ])))
}
// Linux names the broadcast/destination union member ifa_ifu.
#[cfg(target_os = "linux")]
fn ifa_dstaddr(item: &libc::ifaddrs) -> *mut libc::sockaddr {
    item.ifa_ifu
}
#[cfg(not(target_os = "linux"))]
fn ifa_dstaddr(item: &libc::ifaddrs) -> *mut libc::sockaddr {
    item.ifa_dstaddr
}
fn ifaddrs() -> O {
    let mut first = ptr::null_mut::<libc::ifaddrs>();
    // SAFETY: first is a writable out-pointer released by freeifaddrs.
    if unsafe { libc::getifaddrs(&mut first) } != 0 {
        return last_error();
    }
    let mut rows = Vec::new();
    let mut current = first;
    while !current.is_null() {
        // SAFETY: current is within the live getifaddrs linked list.
        let item = unsafe { &*current };
        // SAFETY: ifa_name is a null-terminated string for each record.
        let label = unsafe { CStr::from_ptr(item.ifa_name) }.to_string_lossy();
        let flags = flags(item.ifa_flags as i32);
        let mut entries = vec![
            (atom("name"), O::charlist(&label)),
            (atom("flags"), O::list(flags)),
        ];
        if let Some(addr) = sockaddr(item.ifa_addr) {
            entries.push((atom("addr"), addr));
        }
        if let Some(mask) = sockaddr(item.ifa_netmask) {
            entries.push((atom("netmask"), mask));
        }
        if item.ifa_flags as i32 & libc::IFF_BROADCAST != 0 {
            if let Some(addr) = sockaddr(ifa_dstaddr(item)) {
                entries.push((atom("broadaddr"), addr));
            }
        } else if item.ifa_flags as i32 & libc::IFF_POINTOPOINT != 0
            && let Some(addr) = sockaddr(ifa_dstaddr(item))
        {
            entries.push((atom("dstaddr"), addr));
        }
        rows.push(O::Map(entries));
        current = item.ifa_next;
    }
    // SAFETY: first was returned by getifaddrs and remains allocated.
    unsafe { libc::freeifaddrs(first) };
    ok(O::list(rows))
}
fn flags(bits: i32) -> Vec<O> {
    let mut options = vec![
        (libc::IFF_UP, "up"),
        (libc::IFF_BROADCAST, "broadcast"),
        (libc::IFF_DEBUG, "debug"),
        (libc::IFF_LOOPBACK, "loopback"),
        (libc::IFF_POINTOPOINT, "pointopoint"),
    ];
    #[cfg(target_os = "macos")]
    options.push((libc::IFF_NOTRAILERS, "notrailers"));
    options.extend([
        (libc::IFF_RUNNING, "running"),
        (libc::IFF_NOARP, "noarp"),
        (libc::IFF_PROMISC, "promisc"),
    ]);
    #[cfg(target_os = "linux")]
    options.extend([(libc::IFF_MASTER, "master"), (libc::IFF_SLAVE, "slave")]);
    options.push((libc::IFF_MULTICAST, "multicast"));
    options
        .into_iter()
        .filter(|(mask, _)| bits & mask != 0)
        .map(|(_, label)| atom(label))
        .collect()
}
fn if_names() -> O {
    let mut first = ptr::null_mut::<libc::ifaddrs>();
    // SAFETY: first is a writable out-pointer released below.
    if unsafe { libc::getifaddrs(&mut first) } != 0 {
        return last_error();
    }
    let mut rows = Vec::new();
    let mut seen = HashSet::new();
    let mut current = first;
    while !current.is_null() {
        // SAFETY: current belongs to the live getifaddrs list.
        let item = unsafe { &*current };
        // SAFETY: ifa_name is a valid null-terminated interface name.
        let label = unsafe { CStr::from_ptr(item.ifa_name) };
        // SAFETY: label remains valid through this call.
        let index = unsafe { libc::if_nametoindex(item.ifa_name) };
        if index > 0 && seen.insert(index) {
            rows.push(pair(
                O::Int(index.into()),
                O::charlist(&label.to_string_lossy()),
            ));
        }
        current = item.ifa_next;
    }
    // SAFETY: first was returned by getifaddrs and remains allocated.
    unsafe { libc::freeifaddrs(first) };
    ok(O::list(rows))
}
/// Port number of service `name` under `protocol` (`getservbyname`).
pub fn servbyname(name: &CString, protocol: &CString) -> Option<u16> {
    let _lock = SERVICE_DB.lock().unwrap();
    // SAFETY: both strings remain live; the returned static servent is read under SERVICE_DB.
    let entry = unsafe { libc::getservbyname(name.as_ptr(), protocol.as_ptr()) };
    if entry.is_null() {
        return None;
    }
    // SAFETY: entry remains valid while SERVICE_DB is held.
    Some(unsafe { u16::from_be((*entry).s_port as u16) })
}

/// Name of the service on `port` under `protocol` (`getservbyport`).
pub fn servbyport(port: u16, protocol: &CString) -> Option<String> {
    let _lock = SERVICE_DB.lock().unwrap();
    // SAFETY: protocol remains live; returned static servent is read under SERVICE_DB.
    let entry = unsafe { libc::getservbyport(port.to_be() as i32, protocol.as_ptr()) };
    if entry.is_null() {
        return None;
    }
    // SAFETY: entry and s_name remain valid while SERVICE_DB is held.
    let value = unsafe { CStr::from_ptr((*entry).s_name) };
    Some(value.to_string_lossy().into_owned())
}

fn service(args: &[O], by_name: bool) -> Result<O, BifError> {
    let protocol = cstring(&args[1])?.ok_or(BifError::BADARG)?;
    if by_name {
        let service = cstring(&args[0])?.ok_or(BifError::BADARG)?;
        Ok(servbyname(&service, &protocol)
            .map_or_else(|| error("einval"), |p| ok(O::Int(p.into()))))
    } else {
        let port = number(&args[0])
            .and_then(|n| u16::try_from(n).ok())
            .ok_or(BifError::BADARG)?;
        Ok(servbyport(port, &protocol).map_or_else(|| error("einval"), |n| ok(O::charlist(&n))))
    }
}
pub(super) fn dispatch(name: &str, args: &[O]) -> Result<O, BifError> {
    match (name, args.len()) {
        ("nif_getaddrinfo", 3) => getaddrinfo(args),
        ("nif_getnameinfo", 2) => getnameinfo(args),
        ("nif_getifaddrs", 1) => {
            if !matches!(args[0], O::Map(_)) {
                return Err(BifError::BADARG);
            }
            Ok(ifaddrs())
        }
        ("nif_gethostname", 0) => {
            let mut buf = [0 as libc::c_char; 256];
            // SAFETY: buf is writable with capacity passed to gethostname.
            let status = unsafe { libc::gethostname(buf.as_mut_ptr(), buf.len()) };
            if status < 0 {
                Ok(last_error())
            } else {
                // SAFETY: successful gethostname produces a null-terminated string on macOS.
                Ok(ok(O::charlist(
                    &unsafe { CStr::from_ptr(buf.as_ptr()) }.to_string_lossy(),
                )))
            }
        }
        ("nif_if_names", 0) => Ok(if_names()),
        ("nif_if_name2index", 1) => {
            let label = cstring(&args[0])?.ok_or(BifError::BADARG)?;
            // SAFETY: label is a live null-terminated string.
            let value = unsafe { libc::if_nametoindex(label.as_ptr()) };
            Ok(if value == 0 {
                last_error()
            } else {
                ok(O::Int(value.into()))
            })
        }
        ("nif_if_index2name", 1) => {
            let index = number(&args[0])
                .and_then(|n| u32::try_from(n).ok())
                .ok_or(BifError::BADARG)?;
            let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
            // SAFETY: buf has IF_NAMESIZE bytes, as required by if_indextoname.
            let result = unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) };
            if result.is_null() {
                Ok(last_error())
            } else {
                // SAFETY: successful if_indextoname null-terminates buf.
                Ok(ok(O::charlist(
                    &unsafe { CStr::from_ptr(buf.as_ptr()) }.to_string_lossy(),
                )))
            }
        }
        ("nif_info", 0) => Ok(map(&[
            (
                "debug",
                atom(if DEBUG.load(Ordering::Relaxed) {
                    "true"
                } else {
                    "false"
                }),
            ),
            ("netns", atom("false")),
        ])),
        ("nif_command", 1) => {
            let cmd = crate::name(crate::field(&args[0], "command").ok_or(BifError::BADARG)?);
            let data = crate::name(crate::field(&args[0], "data").ok_or(BifError::BADARG)?);
            match (cmd, data) {
                (Some("debug"), Some("true")) => {
                    DEBUG.store(true, Ordering::Relaxed);
                    Ok(atom("ok"))
                }
                (Some("debug"), Some("false")) => {
                    DEBUG.store(false, Ordering::Relaxed);
                    Ok(atom("ok"))
                }
                _ => Ok(error("einval")),
            }
        }
        (
            "nif_get_adapters_addresses"
            | "nif_get_if_entry"
            | "nif_get_interface_info"
            | "nif_get_ip_address_table",
            _,
        ) => Err(crate::notsup()),
        ("nif_getservbyname", 2) => service(args, true),
        ("nif_getservbyport", 2) => service(args, false),
        _ => Err(BifError::BADARG),
    }
}

/// The `prim_net` NIF table: name, arity and whether the entry is flagged
/// `ERL_NIF_DIRTY_JOB_IO_BOUND`, in the order erts declares them.
pub(crate) const NIF_FUNCS: [(&str, u8, bool); 15] = [
    ("nif_info", 0, false),
    ("nif_command", 1, false),
    ("nif_gethostname", 0, false),
    ("nif_getnameinfo", 2, false),
    ("nif_getaddrinfo", 3, false),
    ("nif_getifaddrs", 1, true),
    ("nif_get_adapters_addresses", 1, true),
    ("nif_get_if_entry", 1, true),
    ("nif_get_interface_info", 1, true),
    ("nif_get_ip_address_table", 1, true),
    ("nif_getservbyname", 2, true),
    ("nif_getservbyport", 2, true),
    ("nif_if_name2index", 1, false),
    ("nif_if_index2name", 1, false),
    ("nif_if_names", 0, false),
];

/// Whether the `prim_net` NIF `name/arity` runs on a dirty IO scheduler.
pub(crate) fn dirty_io(name: &str, arity: u8) -> bool {
    NIF_FUNCS
        .iter()
        .any(|(entry, entry_arity, dirty)| *dirty && *entry == name && *entry_arity == arity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field;
    use std::process::Command;

    fn unwrap_ok(value: O) -> O {
        let O::Tuple(parts) = &value else {
            panic!("expected ok tuple: {value:?}")
        };
        assert_eq!(parts[0], atom("ok"), "{value:?}");
        parts[1].clone()
    }
    #[test]
    fn resolver_and_interface_shapes() {
        for host in ["localhost", "127.0.0.1", "::1"] {
            let rows = unwrap_ok(
                dispatch(
                    "nif_getaddrinfo",
                    &[O::charlist(host), atom("undefined"), atom("undefined")],
                )
                .unwrap(),
            );
            let rows = list(&rows).unwrap();
            assert!(!rows.is_empty());
            for row in rows {
                assert!(field(row, "family").is_some());
                assert!(field(row, "addr").is_some());
                assert!(field(row, "socktype").is_some());
                assert!(field(row, "protocol").is_some());
            }
        }
        let rows = unwrap_ok(dispatch("nif_getifaddrs", &[O::Map(vec![])]).unwrap());
        let rows = list(&rows).unwrap();
        assert!(!rows.is_empty());
        for row in rows {
            assert!(field(row, "name").is_some());
            assert!(field(row, "flags").is_some());
        }
        #[cfg(target_os = "macos")]
        assert!(rows.iter().any(|row| {
            string(field(row, "name").unwrap()).as_deref() == Some("lo0")
                && field(row, "addr")
                    .and_then(|addr| field(addr, "family"))
                    .and_then(name)
                    == Some("link")
        }));
        let names = unwrap_ok(dispatch("nif_if_names", &[]).unwrap());
        assert!(!list(&names).unwrap().is_empty());
        #[cfg(target_os = "macos")]
        {
            let index = unwrap_ok(dispatch("nif_if_name2index", &[O::charlist("lo0")]).unwrap());
            assert_eq!(index, O::Int(1));
            let label = unwrap_ok(dispatch("nif_if_index2name", &[index]).unwrap());
            assert_eq!(label, O::charlist("lo0"));
        }
    }
    #[test]
    fn numeric_nameinfo() {
        let addr = map(&[
            ("family", atom("inet")),
            (
                "addr",
                O::tuple(vec![O::Int(127), O::Int(0), O::Int(0), O::Int(1)]),
            ),
            ("port", O::Int(80)),
        ]);
        let result = unwrap_ok(
            dispatch(
                "nif_getnameinfo",
                &[
                    addr,
                    O::list(vec![atom("numerichost"), atom("numericserv")]),
                ],
            )
            .unwrap(),
        );
        assert_eq!(
            string(field(&result, "host").unwrap()).as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(
            string(field(&result, "service").unwrap()).as_deref(),
            Some("80")
        );
        assert_eq!(
            dispatch(
                "nif_getservbyname",
                &[O::charlist("http"), O::charlist("tcp")]
            )
            .unwrap(),
            ok(O::Int(80))
        );
        assert_eq!(
            dispatch("nif_getservbyport", &[O::Int(80), O::charlist("tcp")]).unwrap(),
            ok(O::charlist("http"))
        );
    }
    /// The protocol as `prim_net:getaddrinfo/2` presents it: the first name of the number.
    fn protocol_name(protocol: Option<&O>) -> Option<O> {
        let protocol = protocol?;
        let O::Int(number) = protocol else {
            return Some(protocol.clone());
        };
        let table = crate::socket::supports(Some(&atom("protocols")));
        list(&table)
            .unwrap()
            .iter()
            .find_map(|row| {
                let O::Tuple(row) = row else { return None };
                (row[1] == O::Int(*number)).then(|| list(&row[0]).and_then(|n| n.first().cloned()))
            })
            .flatten()
            .or_else(|| Some(protocol.clone()))
    }
    fn addrinfo_key(row: &O) -> String {
        let addr = field(row, "addr").unwrap();
        format!(
            "{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}",
            field(row, "family"),
            field(row, "socktype"),
            protocol_name(field(row, "protocol")),
            field(addr, "family"),
            field(addr, "addr"),
            field(addr, "port"),
            field(addr, "flowinfo"),
            field(addr, "scope_id")
        )
    }
    #[test]
    fn addrinfo_matches_otp() {
        let path =
            std::env::temp_dir().join(format!("arinsal_addrinfo_{}.etf", std::process::id()));
        let expression = format!(
            "ok=file:write_file(\"{}\",term_to_binary([net:getaddrinfo(H) || H <- [\"localhost\",\"127.0.0.1\",\"::1\"]])),halt().",
            path.display()
        );
        let Ok(output) = Command::new("erl")
            .args(["-noshell", "-eval", &expression])
            .output()
        else {
            eprintln!("skipping OTP differential: erl not installed");
            return;
        };
        assert!(
            output.status.success(),
            "{:?}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected = arinsal_etf::decode(&std::fs::read(&path).unwrap()).unwrap();
        std::fs::remove_file(path).unwrap();
        let expected = list(&expected).unwrap();
        for (host, reference) in ["localhost", "127.0.0.1", "::1"].into_iter().zip(expected) {
            let actual = dispatch(
                "nif_getaddrinfo",
                &[O::charlist(host), atom("undefined"), atom("undefined")],
            )
            .unwrap();
            let actual = unwrap_ok(actual);
            let reference = unwrap_ok(reference.clone());
            let actual: Vec<_> = list(&actual).unwrap().iter().map(addrinfo_key).collect();
            let reference: Vec<_> = list(&reference).unwrap().iter().map(addrinfo_key).collect();
            assert_eq!(actual, reference, "host {host}");
        }
    }
}
