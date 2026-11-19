// Port of erts/epmd/src/epmd.c, epmd_srv.c, and epmd_cli.c, OTP-29.1.1.

#[path = "epmd/raw.rs"]
mod raw;

use std::ffi::OsString;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::process::ExitCode;
use std::ptr::NonNull;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_PORT: i32 = 4369;
const MAX_LISTEN_SOCKETS: usize = 16;
const MAX_UNREG_COUNT: usize = 1000;
const DEBUG_MAX_UNREG_COUNT: usize = 5;
const MAX_SYMLEN: usize = 255 * 4;
const INBUF_SIZE: usize = 3 * MAX_SYMLEN;
const OUTBUF_SIZE: usize = 3 * MAX_SYMLEN;
const IDLE_TIMEOUT: u32 = 5;
const CLOSE_TIMEOUT: u32 = 60;

const ALIVE2_REQ: u8 = b'x';
const PORT2_REQ: u8 = b'z';
const ALIVE2_RESP: u8 = b'y';
const ALIVE2_X_RESP: u8 = b'v';
const PORT2_RESP: u8 = b'w';
const NAMES_REQ: u8 = b'n';
const DUMP_REQ: u8 = b'd';
const KILL_REQ: u8 = b'k';
const STOP_REQ: u8 = b's';

struct Node {
    next: Option<Box<Node>>,
    fd: RawFd,
    port: u16,
    symname: [u8; MAX_SYMLEN + 1],
    cr_counter: u32,
    nodetype: u8,
    protocol: u8,
    highvsn: u16,
    lowvsn: u16,
    extralen: usize,
    extra: [u8; MAX_SYMLEN + 1],
}

impl Default for Node {
    // erts equivalent: field initialization in epmd_srv.c:node_reg2.
    fn default() -> Self {
        Self {
            next: None,
            fd: -1,
            port: 0,
            symname: [0; MAX_SYMLEN + 1],
            cr_counter: 0,
            nodetype: 0,
            protocol: 0,
            highvsn: 0,
            lowvsn: 0,
            extralen: 0,
            extra: [0; MAX_SYMLEN + 1],
        }
    }
}

struct NodeList {
    head: Option<Box<Node>>,
    tail: Option<NonNull<Node>>,
    count: usize,
}

impl NodeList {
    // erts equivalent: empty queue fields in epmd_srv.c:node_init.
    fn new() -> Self {
        Self {
            head: None,
            tail: None,
            count: 0,
        }
    }

    // erts equivalent: FIFO tail insertion in epmd_srv.c:node_unreg.
    fn append(&mut self, node: Box<Node>) {
        raw::append_node(&mut self.head, &mut self.tail, node);
        self.count += 1;
    }
}

struct Nodes {
    reg: Option<Box<Node>>,
    unreg: NodeList,
}

impl Nodes {
    // erts equivalent: epmd_srv.c:node_init.
    fn new() -> Self {
        Self {
            reg: None,
            unreg: NodeList::new(),
        }
    }
}

struct Connection {
    fd: RawFd,
    open: bool,
    keep: bool,
    local_peer: bool,
    got: usize,
    want: usize,
    buf: Option<Vec<u8>>,
    mod_time: u64,
}

impl Default for Connection {
    // erts equivalent: zeroed Connection slots in epmd_srv.c:conn_init.
    fn default() -> Self {
        Self {
            fd: -1,
            open: false,
            keep: false,
            local_peer: false,
            got: 0,
            want: 0,
            buf: None,
            mod_time: 0,
        }
    }
}

struct Epmd {
    port: i32,
    addresses: Option<Vec<u8>>,
    debug: i32,
    silent: bool,
    daemon: bool,
    relaxed: bool,
    packet_timeout: u32,
    delay_accept: u32,
    delay_write: u32,
    max_conn: i32,
    active_conn: i32,
    select_fd_top: i32,
    orig_read_mask: raw::FdSet,
    listenfd: [RawFd; MAX_LISTEN_SOCKETS],
    conn: Vec<Connection>,
    nodes: Nodes,
    systemd: bool,
}

impl Epmd {
    // erts equivalent: EpmdVars initialization in epmd.c:main.
    fn new() -> Self {
        Self {
            port: std::env::var_os("ERL_EPMD_PORT")
                .map(|value| c_atoi(value.as_bytes()))
                .unwrap_or(DEFAULT_PORT),
            addresses: std::env::var_os("ERL_EPMD_ADDRESS").map(|value| value.as_bytes().to_vec()),
            debug: 0,
            silent: false,
            daemon: false,
            relaxed: std::env::var_os("ERL_EPMD_RELAXED_COMMAND_CHECK").is_some(),
            packet_timeout: CLOSE_TIMEOUT,
            delay_accept: 0,
            delay_write: 0,
            max_conn: 0,
            active_conn: 0,
            select_fd_top: 0,
            orig_read_mask: raw::FdSet::empty(),
            listenfd: [-1; MAX_LISTEN_SOCKETS],
            conn: Vec::new(),
            nodes: Nodes::new(),
            systemd: false,
        }
    }

    // Port of erts/epmd/src/epmd.c:usage, OTP-29.1.1.
    fn usage(&self) -> ! {
        eprintln!("usage: epmd [-d|-debug] [DbgExtra...] [-address List]");
        eprintln!("            [-port No] [-daemon] [-relaxed_command_check]");
        eprintln!("       epmd [-d|-debug] [-port No] [-names|-kill|-stop name]\n");
        eprintln!("See the Erlang epmd manual page for info about the usage.\n");
        eprintln!("Regular options");
        eprintln!("    -address List");
        eprintln!("        Let epmd listen only on the comma-separated list of IP");
        eprintln!("        addresses (and on the loopback interface).");
        eprintln!("    -port No");
        eprintln!("        Let epmd listen to another port than default {DEFAULT_PORT}");
        eprintln!("    -d");
        eprintln!("    -debug");
        eprintln!("        Enable debugging. This will give a log to");
        eprintln!("        the standard error stream. It will shorten");
        eprintln!("        the number of saved used node names to 5.\n");
        eprintln!("        If you give more than one debug flag you may");
        eprintln!("        get more debugging information.");
        eprintln!("    -daemon");
        eprintln!("        Start epmd detached (as a daemon)");
        eprintln!("    -relaxed_command_check");
        eprintln!("        Allow this instance of epmd to be killed with");
        eprintln!("        epmd -kill even if there are registered nodes.");
        eprintln!("        Also allows forced unregister (epmd -stop).");
        eprintln!("\nDbgExtra options");
        eprintln!("    -packet_timeout Seconds");
        eprintln!("        Set the number of seconds a connection can be");
        eprintln!("        inactive before epmd times out and closes the");
        eprintln!("        connection (default 60).\n");
        eprintln!("    -delay_accept Seconds");
        eprintln!("        To simulate a busy server you can insert a");
        eprintln!("        delay between epmd gets notified about that");
        eprintln!("        a new connection is requested and when the");
        eprintln!("        connections gets accepted.\n");
        eprintln!("    -delay_write Seconds");
        eprintln!("        Also a simulation of a busy server. Inserts");
        eprintln!("        a delay before a reply is sent.");
        eprintln!("\nInteractive options");
        eprintln!("    -names");
        eprintln!("        List names registered with the currently running epmd");
        eprintln!("    -kill");
        eprintln!("        Kill the currently running epmd");
        eprintln!("        (only allowed if -names show empty database or");
        eprintln!("        -relaxed_command_check was given when epmd was started).");
        eprintln!("    -stop Name");
        eprintln!("        Forcibly unregisters a name with epmd");
        eprintln!("        (only allowed if -relaxed_command_check was given when ");
        eprintln!("        epmd was started).");
        self.notify_exit(1);
        std::process::exit(1)
    }

    // Port of erts/epmd/src/epmd.c:epmd_main argument loop, OTP-29.1.1.
    fn parse_args(&mut self, args: &[OsString]) -> Result<Option<i32>, ()> {
        let mut index = 1;
        while index < args.len() {
            let arg = args[index].as_bytes();
            match arg {
                b"-debug" | b"-d" => {
                    self.debug += 1;
                    index += 1;
                }
                b"-packet_timeout" | b"-delay_accept" | b"-delay_write" => {
                    if index + 1 >= args.len() {
                        return Err(());
                    }
                    let value = c_atoi(args[index + 1].as_bytes());
                    if value == 0 {
                        return Err(());
                    }
                    match arg {
                        b"-packet_timeout" => self.packet_timeout = value as u32,
                        b"-delay_accept" => self.delay_accept = value as u32,
                        _ => self.delay_write = value as u32,
                    }
                    index += 2;
                }
                b"-daemon" => {
                    self.daemon = true;
                    index += 1;
                }
                b"-relaxed_command_check" => {
                    self.relaxed = true;
                    index += 1;
                }
                b"-kill" => {
                    if index + 1 != args.len() {
                        return Err(());
                    }
                    return Ok(Some(client_status(self.kill_epmd())));
                }
                b"-address" | b"-port" => {
                    if index + 1 >= args.len() {
                        return Err(());
                    }
                    let value = args[index + 1].as_bytes();
                    if arg == b"-address" {
                        self.addresses = Some(value.to_vec());
                    } else {
                        self.port = c_atoi(value);
                        if self.port == 0 {
                            return Err(());
                        }
                    }
                    index += 2;
                }
                b"-names" => {
                    if index + 1 != args.len() {
                        return Err(());
                    }
                    return Ok(Some(client_status(self.epmd_call(NAMES_REQ))));
                }
                b"-started" => {
                    self.silent = true;
                    if index + 1 != args.len() {
                        return Err(());
                    }
                    return Ok(Some(client_status(self.epmd_call(NAMES_REQ))));
                }
                b"-dump" => {
                    if index + 1 != args.len() {
                        return Err(());
                    }
                    return Ok(Some(client_status(self.epmd_call(DUMP_REQ))));
                }
                b"-stop" => {
                    if index + 2 != args.len() {
                        return Err(());
                    }
                    let result = self.stop_cli(args[index + 1].as_bytes());
                    return Ok(Some(client_status(result)));
                }
                b"-systemd" => {
                    self.systemd = true;
                    index += 1;
                }
                _ => return Err(()),
            }
        }
        Ok(None)
    }

    // Port of erts/epmd/src/epmd.c:run_daemon, OTP-29.1.1.
    // Port of erts/epmd/src/epmd.c:run_daemon, OTP-29.1.1.
    fn daemonize(&self) -> Result<bool, io::Error> {
        raw::daemonize(self.max_conn)
    }

    // Port of erts/epmd/src/epmd.c:main and epmd_srv.c:run, OTP-29.1.1.
    fn serve(&mut self) -> i32 {
        self.dbg_printf(1, &format!("epmd running - daemon = {}", self.daemon as u8));
        self.max_conn = raw::max_open_files();
        if self.daemon {
            match self.daemonize() {
                Ok(true) => {
                    self.notify_exit(0);
                    return 0;
                }
                Ok(false) => {}
                Err(error) => {
                    self.dbg_perror("epmd: daemon setup failed", &error);
                    self.notify_exit(1);
                    return 1;
                }
            }
        }
        let status = match self.run() {
            Ok(()) => 0,
            Err(status) => status,
        };
        self.notify_exit(status);
        status
    }

    // erts equivalent: systemd status in epmd.c:epmd_cleanup_exit.
    fn notify_exit(&self, status: i32) {
        if self.systemd {
            raw::systemd_notify(&format!("STATUS=Exited.\nERRNO={status}"));
        }
    }

    // Port of erts/epmd/src/epmd_srv.c:run, OTP-29.1.1.
    fn run(&mut self) -> Result<(), i32> {
        self.nodes = Nodes::new();
        let allocated = self.max_conn.max(0) as usize;
        self.conn = (0..allocated).map(|_| Connection::default()).collect();

        let (addresses, systemd_count) = if self.systemd {
            let count = match raw::systemd_fds() {
                Ok(count) => count,
                Err(error) => {
                    self.dbg_perror("cannot obtain sockets from systemd", &error);
                    return Err(1);
                }
            };
            if count == 0 {
                self.dbg_tty_printf(0, "systemd provides no sockets");
                return Err(1);
            }
            if count > MAX_LISTEN_SOCKETS {
                self.dbg_tty_printf(
                    0,
                    &format!("cannot listen on more than {MAX_LISTEN_SOCKETS} IP addresses"),
                );
                return Err(1);
            }
            (Vec::new(), count)
        } else {
            (self.listener_addresses()?, 0)
        };

        raw::ignore_sigpipe();
        let candidate_sockets = if self.systemd {
            systemd_count
        } else {
            addresses.len()
        };
        self.active_conn = 3 + candidate_sockets as i32;
        self.max_conn -= candidate_sockets as i32;
        self.orig_read_mask = raw::FdSet::empty();
        self.select_fd_top = 0;

        let num_sockets = if self.systemd {
            for index in 0..systemd_count {
                let fd = 3 + index as RawFd;
                self.listenfd[index] = fd;
                self.select_fd_set(fd)?;
            }
            systemd_count
        } else {
            let mut bound = 0usize;
            for (address, nonfatal) in addresses {
                self.dbg_printf(2, &format!("bind epmd listener to {address}"));
                match raw::listener(address) {
                    Ok(fd) => {
                        self.listenfd[bound] = fd;
                        self.select_fd_set(fd)?;
                        bound += 1;
                    }
                    Err(error)
                        if error.phase == raw::ListenerPhase::Socket
                            && (error.error.raw_os_error() == Some(libc::EAFNOSUPPORT)
                                || error.error.raw_os_error() == Some(libc::EPROTONOSUPPORT)) =>
                    {
                        continue;
                    }
                    Err(error)
                        if error.phase == raw::ListenerPhase::Bind
                            && error.error.raw_os_error() == Some(libc::EADDRINUSE) =>
                    {
                        self.dbg_tty_printf(
                            1,
                            &format!(
                                "there is already a epmd running at port {} on ipaddr {}",
                                self.port,
                                address.ip()
                            ),
                        );
                        return Ok(());
                    }
                    Err(error) if nonfatal && error.phase == raw::ListenerPhase::Bind => {
                        self.dbg_perror(
                            &format!("failed to bind on ipaddr {}", address.ip()),
                            &error.error,
                        );
                    }
                    Err(error) => {
                        self.dbg_perror(
                            &format!("failed to bind on ipaddr {}", address.ip()),
                            &error.error,
                        );
                        return Err(1);
                    }
                }
            }
            if bound == 0 {
                self.dbg_tty_printf(0, "unable to bind any address");
                return Err(1);
            }
            bound
        };

        if self.systemd {
            raw::systemd_notify(&format!(
                "READY=1\nSTATUS=Processing port mapping requests...\nMAINPID={}",
                std::process::id()
            ));
        }
        self.dbg_tty_printf(2, "entering the main select() loop");
        self.select_loop(num_sockets)
    }

    // Port of erts/epmd/src/epmd_srv.c:run address construction, OTP-29.1.1.
    fn listener_addresses(&self) -> Result<Vec<(SocketAddr, bool)>, i32> {
        let port = self.port as u16;
        let Some(addresses) = self.addresses.as_deref() else {
            return Ok(vec![
                (
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
                    false,
                ),
                (
                    SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
                    false,
                ),
            ]);
        };
        if addresses.iter().all(|byte| matches!(byte, b' ' | b',')) {
            return Ok(vec![
                (
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
                    false,
                ),
                (
                    SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
                    false,
                ),
            ]);
        }

        let mut result = Vec::new();
        let mut v4_loop = false;
        let mut v4_any = false;
        let mut v6_loop = false;
        let mut v6_any = false;
        for token in addresses
            .split(|byte| matches!(byte, b',' | b' '))
            .filter(|part| !part.is_empty())
        {
            let parsed = std::str::from_utf8(token)
                .ok()
                .and_then(|part| part.parse::<IpAddr>().ok());
            let Some(address) = parsed else {
                self.dbg_tty_printf(
                    0,
                    &format!(
                        "cannot parse IP address \"{}\"",
                        String::from_utf8_lossy(token)
                    ),
                );
                return Err(1);
            };
            match address {
                IpAddr::V4(address) => {
                    v4_loop |= address == Ipv4Addr::LOCALHOST;
                    v4_any |= address.is_unspecified();
                }
                IpAddr::V6(address) => {
                    v6_loop |= address.is_loopback();
                    v6_any |= address.is_unspecified();
                }
            }
            result.push((SocketAddr::new(address, port), false));
            if result.len() >= MAX_LISTEN_SOCKETS - 2 {
                self.dbg_tty_printf(
                    0,
                    &format!(
                        "cannot listen on more than {} IP addresses",
                        MAX_LISTEN_SOCKETS - 2
                    ),
                );
                return Err(1);
            }
        }
        if !(v4_loop || v4_any) {
            result.push((SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port), true));
        }
        if !(v6_loop || v6_any) {
            result.push((SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port), true));
        }
        Ok(result)
    }

    // Port of erts/epmd/src/epmd_srv.c:select_fd_set, OTP-29.1.1.
    fn select_fd_set(&mut self, fd: RawFd) -> Result<(), i32> {
        if fd < 0 || fd as usize >= raw::FD_SETSIZE {
            self.dbg_tty_printf(
                0,
                &format!(
                    "fd does not fit in fd_set fd={fd}, FD_SETSIZE={}",
                    raw::FD_SETSIZE
                ),
            );
            return Err(1);
        }
        if self.orig_read_mask.set(fd).is_err() {
            return Err(1);
        }
        self.select_fd_top = self.select_fd_top.max(fd + 1);
        Ok(())
    }

    // Port of erts/epmd/src/epmd_srv.c:run select loop, OTP-29.1.1.
    fn select_loop(&mut self, num_sockets: usize) -> Result<(), i32> {
        'select_again: loop {
            let mut read_mask = self.orig_read_mask.duplicate();
            let timeout = if self.packet_timeout < IDLE_TIMEOUT {
                1
            } else {
                IDLE_TIMEOUT
            };
            let selected = match raw::select(self.select_fd_top, &mut read_mask, timeout as i64) {
                Ok(selected) => selected,
                Err(error)
                    if error.kind() == io::ErrorKind::Interrupted
                        || error.kind() == io::ErrorKind::WouldBlock =>
                {
                    continue;
                }
                Err(error) => {
                    self.dbg_perror("error in select ", &error);
                    return Err(1);
                }
            };
            if selected == 0 {
                read_mask = raw::FdSet::empty();
            }
            if self.delay_accept != 0 {
                raw::sleep_seconds(self.delay_accept);
            }

            for index in 0..num_sockets {
                let fd = self.listenfd[index];
                if read_mask.contains(fd) {
                    match self.do_accept(fd) {
                        Ok(true) if self.active_conn < self.max_conn => {
                            continue 'select_again;
                        }
                        Ok(_) => {}
                        Err(status) => return Err(status),
                    }
                }
            }

            let now = self.current_time() as u64;
            for index in 0..(self.max_conn.max(0) as usize).min(self.conn.len()) {
                if !self.conn[index].open {
                    continue;
                }
                let fd = self.conn[index].fd;
                if read_mask.contains(fd) {
                    self.do_read(index);
                } else if !self.conn[index].keep
                    && self.conn[index].mod_time + (self.packet_timeout as u64) < now
                {
                    self.dbg_tty_printf(1, "closing because timed out on receive");
                    self.conn_close(index);
                }
            }
        }
    }

    // Port of erts/epmd/src/epmd_srv.c:do_accept and conn_open, OTP-29.1.1.
    fn do_accept(&mut self, listen_fd: RawFd) -> Result<bool, i32> {
        let fd = match raw::accept(listen_fd) {
            Ok(fd) => fd,
            Err(error)
                if error.raw_os_error().is_some_and(|code| {
                    code == libc::EAGAIN
                        || code == libc::EWOULDBLOCK
                        || code == libc::ECONNABORTED
                        || code == libc::EINTR
                        || code == libc::EMFILE
                        || code == libc::ENFILE
                }) =>
            {
                self.dbg_perror("error in accept", &error);
                return Ok(false);
            }
            Err(error) => {
                self.dbg_perror("error in accept", &error);
                return Err(1);
            }
        };
        if fd as usize >= raw::FD_SETSIZE {
            self.dbg_tty_printf(
                0,
                &format!(
                    "fd does not fit in fd_set fd={fd}, FD_SETSIZE={}",
                    raw::FD_SETSIZE
                ),
            );
            raw::close(fd);
            return Ok(false);
        }

        for index in 0..(self.max_conn.max(0) as usize).min(self.conn.len()) {
            if !self.conn[index].open {
                self.active_conn += 1;
                if self.select_fd_set(fd).is_err() {
                    raw::close(fd);
                    return Ok(false);
                }
                self.conn[index] = Connection {
                    fd,
                    open: true,
                    keep: false,
                    local_peer: raw::is_local_peer(fd),
                    got: 0,
                    want: 0,
                    buf: Some(vec![0; INBUF_SIZE]),
                    mod_time: self.current_time() as u64,
                };
                self.dbg_tty_printf(
                    2,
                    if self.conn[index].local_peer {
                        "Local peer connected"
                    } else {
                        "Non-local peer connected"
                    },
                );
                self.dbg_tty_printf(2, &format!("opening connection on file descriptor {fd}"));
                return Ok(true);
            }
        }
        self.dbg_tty_printf(
            0,
            &format!("failed opening connection on file descriptor {fd}"),
        );
        raw::close(fd);
        Ok(false)
    }

    // Port of erts/epmd/src/epmd_srv.c:current_time, OTP-29.1.1.
    fn current_time(&self) -> u32 {
        let now = raw::current_time();
        self.dbg_printf(3, &format!("time in seconds: {now}"));
        now
    }

    // Port of erts/epmd/src/epmd_srv.c:do_read, OTP-29.1.1.
    fn do_read(&mut self, index: usize) {
        if !self.conn[index].open {
            self.dbg_printf(0, "read on unknown socket");
            return;
        }
        let fd = self.conn[index].fd;
        let keep = self.conn[index].keep;
        let mut buffer = self.conn[index].buf.take().unwrap_or_default();
        if keep {
            match raw::read(fd, &mut buffer) {
                Ok(0) => {
                    self.node_unreg_sock(fd);
                    self.conn_close(index);
                }
                Err(error) => {
                    self.dbg_tty_printf(
                        1,
                        &format!(
                            "error on ALIVE socket {fd} (-1; errno=0x{:x})",
                            error.raw_os_error().unwrap_or(0)
                        ),
                    );
                    self.node_unreg_sock(fd);
                    self.conn_close(index);
                }
                Ok(count) => {
                    self.dbg_tty_printf(
                        1,
                        &format!("got more than expected on ALIVE socket {fd} ({count})"),
                    );
                    self.dbg_print_buf(&buffer, count);
                    self.node_unreg_sock(fd);
                    self.conn_close(index);
                }
            }
            return;
        }

        let got = self.conn[index].got;
        let want = self.conn[index].want;
        let packet_size = if want == 0 { INBUF_SIZE - 1 } else { want };
        let count = match raw::read(fd, &mut buffer[got..packet_size]) {
            Ok(0) => {
                self.dbg_printf(
                    0,
                    &format!("got partial packet only on file descriptor {fd} ({got})"),
                );
                self.conn[index].buf = Some(buffer);
                self.conn_close(index);
                return;
            }
            Ok(count) => count,
            Err(error) => {
                self.dbg_perror("error in read", &error);
                self.conn[index].buf = Some(buffer);
                self.conn_close(index);
                return;
            }
        };
        self.dbg_print_buf(&buffer[got..got + count], count);
        let got = got + count;
        self.conn[index].got = got;
        if self.conn[index].want == 0 && got >= 2 {
            let packet_want = u16::from_be_bytes([buffer[0], buffer[1]]) as usize + 2;
            self.conn[index].want = packet_want;
            if !(3..INBUF_SIZE).contains(&packet_want) {
                self.dbg_printf(0, &format!("invalid packet size ({})", packet_want - 2));
                self.conn[index].buf = Some(buffer);
                self.conn_close(index);
                return;
            }
            if got > packet_want {
                self.dbg_printf(
                    0,
                    &format!("got {got} bytes in packet, expected {}", packet_want - 2),
                );
                self.conn[index].buf = Some(buffer);
                self.conn_close(index);
                return;
            }
        }
        if self.conn[index].want == got {
            self.conn[index].mod_time = self.current_time() as u64;
            self.do_request(index, fd, &mut buffer, got - 2);
            if self.conn[index].open && !self.conn[index].keep {
                self.conn[index].buf = Some(buffer);
                self.conn_close(index);
            } else if self.conn[index].open {
                self.conn[index].buf = Some(buffer);
            }
        } else {
            self.conn[index].buf = Some(buffer);
        }
    }

    // Port of erts/epmd/src/epmd_srv.c:do_request, OTP-29.1.1.
    fn do_request(&mut self, index: usize, fd: RawFd, buffer: &mut [u8], bsize: usize) {
        buffer[2 + bsize] = 0;
        let request = &mut buffer[2..2 + bsize + 1];
        match request[0] {
            ALIVE2_REQ => self.alive2(index, fd, request, bsize),
            PORT2_REQ => self.port2(fd, request, bsize),
            NAMES_REQ => self.names(fd),
            DUMP_REQ => {
                if !self.conn[index].local_peer {
                    self.dbg_printf(0, "EPMD_DUMP_REQ from non local address");
                } else {
                    self.dump(fd);
                }
            }
            KILL_REQ => {
                if !self.conn[index].local_peer {
                    self.dbg_printf(0, "EPMD_KILL_REQ from non local address");
                    return;
                }
                self.dbg_printf(1, "** got EPMD_KILL_REQ");
                if !self.relaxed && self.nodes.reg.is_some() {
                    self.dbg_printf(0, "Disallowed EPMD_KILL_REQ, live nodes");
                    if !self.reply(fd, b"NO") {
                        self.dbg_printf(0, "failed to send reply to EPMD_KILL_REQ");
                    }
                    return;
                }
                if !self.reply(fd, b"OK") {
                    self.dbg_printf(0, "failed to send reply to EPMD_KILL_REQ");
                }
                self.dbg_tty_printf(1, "epmd killed");
                self.conn_close_fd(fd);
                self.dbg_printf(0, "got EPMD_KILL_REQ - terminates normal");
                self.notify_exit(0);
                std::process::exit(0);
            }
            STOP_REQ => self.stop_request(index, fd, request, bsize),
            _ => self.dbg_printf(0, "got garbage "),
        }
    }

    // Port of erts/epmd/src/epmd_srv.c:alive2 request branch, OTP-29.1.1.
    fn alive2(&mut self, index: usize, fd: RawFd, request: &mut [u8], bsize: usize) {
        self.dbg_printf(1, "** got ALIVE2_REQ");
        if !self.conn[index].local_peer {
            self.dbg_printf(0, "ALIVE2_REQ from non local address");
            return;
        }
        if bsize <= 13 {
            self.dbg_printf(
                0,
                &format!("packet to small for request ALIVE2_REQ ({bsize})"),
            );
            return;
        }
        let port = u16::from_be_bytes([request[1], request[2]]);
        let nodetype = request[3];
        let protocol = request[4];
        let highvsn = u16::from_be_bytes([request[5], request[6]]);
        let lowvsn = u16::from_be_bytes([request[7], request[8]]);
        let namelen = u16::from_be_bytes([request[9], request[10]]) as usize;
        if namelen + 13 > bsize {
            self.dbg_printf(0, "Node name size error in ALIVE2_REQ");
            return;
        }
        let extralen_index = 11 + namelen;
        let extralen =
            u16::from_be_bytes([request[extralen_index], request[extralen_index + 1]]) as usize;
        if extralen + namelen + 13 > bsize {
            self.dbg_printf(0, "Extra info size error in ALIVE2_REQ");
            return;
        }
        let name = &request[11..11 + namelen];
        if name.contains(&0) {
            self.dbg_printf(0, "node name contains ascii 0 in ALIVE2_REQ");
            return;
        }
        let extra = &request[extralen_index + 2..extralen_index + 2 + extralen];
        let registered = self.node_reg2(name, fd, port, nodetype, protocol, highvsn, lowvsn, extra);
        let creation = registered.unwrap_or(99);
        let mut response = [0u8; 6];
        response[1] = u8::from(registered.is_none());
        let response_len = if highvsn >= 6 {
            response[0] = ALIVE2_X_RESP;
            response[2..6].copy_from_slice(&creation.to_be_bytes());
            6
        } else {
            response[0] = ALIVE2_RESP;
            response[2..4].copy_from_slice(&(creation as u16).to_be_bytes());
            4
        };
        if !self.reply(fd, &response[..response_len]) {
            if registered.is_some() {
                self.node_unreg_name(&request[11..11 + namelen]);
            }
            self.dbg_tty_printf(1, "** failed to send EPMD_ALIVE2_RESP");
            return;
        }
        self.dbg_tty_printf(1, "** sent EPMD_ALIVE2_RESP");
        self.conn[index].keep = true;
    }

    // Port of erts/epmd/src/epmd_srv.c:PORT2_REQ branch, OTP-29.1.1.
    fn port2(&mut self, fd: RawFd, request: &[u8], mut bsize: usize) {
        self.dbg_printf(1, "** got PORT2_REQ");
        if request[bsize - 1] == 0 {
            bsize -= 1;
        }
        if bsize <= 1 {
            self.dbg_printf(
                0,
                &format!("packet too small for request PORT2_REQ ({bsize})"),
            );
            return;
        }
        if request[1..bsize].contains(&0) {
            self.dbg_printf(0, "node name contains ascii 0 in PORT2_REQ");
            return;
        }
        let name = &request[1..bsize];
        let utf8_size = verify_utf8(&request[1..=bsize]);
        if !(1..=255).contains(&utf8_size) {
            self.dbg_printf(0, "invalid node name in PORT2_REQ");
            return;
        }
        let Some(node) = find_node(&self.nodes.reg, name) else {
            let response = [PORT2_RESP, 1];
            if !self.reply(fd, &response) {
                self.dbg_tty_printf(1, "** failed to send EPMD_PORT2_RESP (error)");
            } else {
                self.dbg_tty_printf(1, "** sent EPMD_PORT2_RESP (error)");
            }
            return;
        };
        let mut response = [0u8; OUTBUF_SIZE];
        response[0] = PORT2_RESP;
        response[1] = 0;
        response[2..4].copy_from_slice(&node.port.to_be_bytes());
        response[4] = node.nodetype;
        response[5] = node.protocol;
        response[6..8].copy_from_slice(&node.highvsn.to_be_bytes());
        response[8..10].copy_from_slice(&node.lowvsn.to_be_bytes());
        let name_len = node_name_len(node);
        response[10..12].copy_from_slice(&(name_len as u16).to_be_bytes());
        response[12..12 + name_len].copy_from_slice(&node.symname[..name_len]);
        let extra_len_offset = 12 + name_len;
        response[extra_len_offset..extra_len_offset + 2]
            .copy_from_slice(&(node.extralen as u16).to_be_bytes());
        let extra_offset = extra_len_offset + 2;
        response[extra_offset..extra_offset + node.extralen]
            .copy_from_slice(&node.extra[..node.extralen]);
        if !self.reply(fd, &response[..extra_offset + node.extralen]) {
            self.dbg_tty_printf(1, "** failed to send EPMD_PORT2_RESP (ok)");
        } else {
            self.dbg_tty_printf(1, "** sent EPMD_PORT2_RESP (ok)");
        }
    }

    // Port of erts/epmd/src/epmd_srv.c:NAMES_REQ branch, OTP-29.1.1.
    fn names(&mut self, fd: RawFd) {
        self.dbg_printf(1, "** got EPMD_NAMES_REQ");
        let port = (self.port as u32).to_be_bytes();
        if !self.reply(fd, &port) {
            self.dbg_tty_printf(1, "failed to send NAMES_RESP");
            return;
        }
        let mut node = self.nodes.reg.as_deref();
        while let Some(active) = node {
            let name = &active.symname[..node_name_len(active)];
            let mut response = [0u8; OUTBUF_SIZE];
            response[..5].copy_from_slice(b"name ");
            response[5..5 + name.len()].copy_from_slice(name);
            let mut response_len = 5 + name.len();
            if append_format(
                &mut response,
                &mut response_len,
                format_args!(" at port {}\n", active.port),
            )
            .is_err()
                || !self.reply(fd, &response[..response_len])
            {
                self.dbg_tty_printf(1, "failed to send NAMES_RESP");
                return;
            }
            node = active.next.as_deref();
        }
        self.dbg_tty_printf(1, "** sent NAMES_RESP");
    }

    // Port of erts/epmd/src/epmd_srv.c:DUMP_REQ branch, OTP-29.1.1.
    fn dump(&mut self, fd: RawFd) {
        self.dbg_printf(1, "** got EPMD_DUMP_REQ");
        let port = (self.port as u32).to_be_bytes();
        if !self.reply(fd, &port) {
            self.dbg_tty_printf(1, "failed to send DUMP_RESP");
            return;
        }
        let mut node = self.nodes.reg.as_deref();
        while let Some(active) = node {
            let mut response = [0u8; OUTBUF_SIZE];
            let prefix = b"active name     <";
            response[..prefix.len()].copy_from_slice(prefix);
            let name_len = node_name_len(active);
            response[prefix.len()..prefix.len() + name_len]
                .copy_from_slice(&active.symname[..name_len]);
            let mut response_len = prefix.len() + name_len;
            if append_format(
                &mut response,
                &mut response_len,
                format_args!("> at port {}, fd = {}\n\0", active.port, active.fd),
            )
            .is_err()
                || !self.reply(fd, &response[..response_len])
            {
                self.dbg_tty_printf(1, "failed to send DUMP_RESP");
                return;
            }
            node = active.next.as_deref();
        }
        let mut node = self.nodes.unreg.head.as_deref();
        while let Some(old) = node {
            let mut response = [0u8; OUTBUF_SIZE];
            let prefix = b"old/unused name <";
            response[..prefix.len()].copy_from_slice(prefix);
            let name_len = node_name_len(old);
            response[prefix.len()..prefix.len() + name_len]
                .copy_from_slice(&old.symname[..name_len]);
            let mut response_len = prefix.len() + name_len;
            if append_format(
                &mut response,
                &mut response_len,
                format_args!(">, port = {}, fd = {} \n\0", old.port, old.fd),
            )
            .is_err()
                || !self.reply(fd, &response[..response_len])
            {
                self.dbg_tty_printf(1, "failed to send DUMP_RESP");
                return;
            }
            node = old.next.as_deref();
        }
        self.dbg_tty_printf(1, "** sent DUMP_RESP");
    }

    // Port of erts/epmd/src/epmd_srv.c:STOP_REQ branch, OTP-29.1.1.
    fn stop_request(&mut self, index: usize, fd: RawFd, request: &[u8], bsize: usize) {
        self.dbg_printf(1, "** got EPMD_STOP_REQ");
        if !self.conn[index].local_peer {
            self.dbg_printf(0, "EPMD_STOP_REQ from non local address");
            return;
        }
        if !self.relaxed {
            self.dbg_printf(0, "Disallowed EPMD_STOP_REQ, no relaxed_command_check");
            return;
        }
        if bsize <= 1 {
            self.dbg_printf(
                0,
                &format!("packet too small for request EPMD_STOP_REQ ({bsize})"),
            );
            return;
        }
        let name_end = request[1..bsize]
            .iter()
            .position(|byte| *byte == 0)
            .map_or(bsize, |offset| offset + 1);
        let name = &request[1..name_end];
        if let Some(node_fd) = self.node_unreg_name(name) {
            self.conn_close_fd(node_fd);
            self.dbg_tty_printf(1, "epmd connection stopped");
        } else {
            if !self.reply(fd, b"NOEXIST") {
                self.dbg_tty_printf(1, "failed to send STOP_RESP NOEXIST");
                return;
            }
            self.dbg_tty_printf(1, "** sent STOP_RESP NOEXIST");
        }
        if !self.reply(fd, b"STOPPED") {
            self.dbg_tty_printf(1, "failed to send STOP_RESP STOPPED");
        } else {
            self.dbg_tty_printf(1, "** sent STOP_RESP STOPPED");
        }
    }

    // Port of erts/epmd/src/epmd_srv.c:conn_close_fd and epmd_conn_close.
    fn conn_close_fd(&mut self, fd: RawFd) -> bool {
        for index in 0..(self.max_conn.max(0) as usize).min(self.conn.len()) {
            if self.conn[index].fd == fd && self.conn[index].open {
                self.conn_close(index);
                return true;
            }
        }
        false
    }

    fn conn_close(&mut self, index: usize) {
        let fd = self.conn[index].fd;
        self.dbg_tty_printf(2, &format!("closing connection on file descriptor {fd}"));
        self.orig_read_mask.clear(fd);
        raw::close(fd);
        self.conn[index].open = false;
        self.conn[index].buf = None;
        self.active_conn -= 1;
    }

    // Port of erts/epmd/src/epmd_srv.c:reply, OTP-29.1.1.
    fn reply(&self, fd: RawFd, buffer: &[u8]) -> bool {
        if self.delay_write != 0 {
            raw::sleep_seconds(self.delay_write);
        }
        let mut sent = 0;
        while sent < buffer.len() {
            match raw::write(fd, &buffer[sent..]) {
                Ok(count) if count == buffer.len() - sent => {
                    sent += count;
                }
                Ok(count) => {
                    self.dbg_printf(
                        0,
                        &format!(
                            "could only send {count} bytes out of {} to fd {fd}",
                            buffer.len()
                        ),
                    );
                    sent += count;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    self.dbg_perror(
                        &format!(
                            "error in write, errno={}",
                            error.raw_os_error().unwrap_or(0)
                        ),
                        &error,
                    );
                    return false;
                }
            }
        }
        self.dbg_print_buf(buffer, buffer.len());
        true
    }

    // Port of erts/epmd/src/epmd_srv.c:node_reg2, OTP-29.1.1.
    #[allow(clippy::too_many_arguments)]
    fn node_reg2(
        &mut self,
        name: &[u8],
        fd: RawFd,
        port: u16,
        nodetype: u8,
        protocol: u8,
        highvsn: u16,
        lowvsn: u16,
        extra: &[u8],
    ) -> Option<u32> {
        let displayed_name = String::from_utf8_lossy(name);
        let name_size = verify_utf8(name);
        if name.len() > MAX_SYMLEN || name_size > 255 {
            self.dbg_printf(
                0,
                &format!("node name is too long ({}) {displayed_name}", name.len()),
            );
            return None;
        }
        if name_size < 0 {
            self.dbg_printf(0, "invalid node name encoding");
            return None;
        }
        if extra.len() > MAX_SYMLEN {
            self.dbg_printf(
                0,
                &format!(
                    "extra data is too long ({}) {}",
                    extra.len(),
                    String::from_utf8_lossy(extra)
                ),
            );
            return None;
        }
        if find_node(&self.nodes.reg, name).is_some() {
            self.dbg_printf(0, &format!("node name already occupied {displayed_name}"));
            return None;
        }

        let mut previous = None;
        let mut link = &mut self.nodes.unreg.head;
        let mut selected = None;
        while link.is_some() {
            let is_match = link
                .as_ref()
                .is_some_and(|current| current.symname[..node_name_len(current)] == name[..]);
            if is_match {
                let current_pointer = NonNull::from(link.as_mut().expect("node exists").as_mut());
                let selected_tail = self.nodes.unreg.tail == Some(current_pointer);
                let mut reused = link.take().expect("node exists");
                *link = reused.next.take();
                self.nodes.unreg.count -= 1;
                if selected_tail {
                    self.nodes.unreg.tail = previous;
                }
                bump_creation(&mut reused);
                selected = Some(reused);
                self.dbg_tty_printf(
                    1,
                    &format!(
                        "reusing slot with same name '{}'",
                        display_name(selected.as_deref().expect("selected old node"))
                    ),
                );
                break;
            }
            let current = link.as_mut().expect("node exists");
            previous = Some(NonNull::from(&mut **current));
            link = &mut current.next;
        }

        let mut node = selected.unwrap_or_else(|| {
            if self.nodes.unreg.count > MAX_UNREG_COUNT
                || (self.debug != 0 && self.nodes.unreg.count > DEBUG_MAX_UNREG_COUNT)
            {
                let mut oldest = self
                    .nodes
                    .unreg
                    .head
                    .take()
                    .expect("old name queue is nonempty");
                self.nodes.unreg.head = oldest.next.take();
                self.nodes.unreg.count -= 1;
                if self.nodes.unreg.head.is_none() {
                    self.nodes.unreg.tail = None;
                }
                oldest
            } else {
                let mut fresh = Box::new(Node::default());
                fresh.cr_counter = self.current_time();
                bump_creation(&mut fresh);
                fresh
            }
        });
        node.next = self.nodes.reg.take();
        node.fd = fd;
        node.port = port;
        node.nodetype = nodetype;
        node.protocol = protocol;
        node.highvsn = highvsn;
        node.lowvsn = lowvsn;
        node.extralen = extra.len();
        node.extra[..extra.len()].copy_from_slice(extra);
        node.symname[..name.len()].copy_from_slice(name);
        node.symname[name.len()] = 0;
        if node.highvsn == 0 {
            self.dbg_tty_printf(
                1,
                &format!(
                    "registering '{}:{}', port {}",
                    displayed_name,
                    get_creation(&node),
                    port
                ),
            );
        } else {
            self.dbg_tty_printf(
                1,
                &format!(
                    "registering '{}:{}', port {}",
                    displayed_name,
                    get_creation(&node),
                    port
                ),
            );
            self.dbg_tty_printf(
                1,
                &format!("type {nodetype} proto {protocol} highvsn {highvsn} lowvsn {lowvsn}"),
            );
        }
        self.nodes.reg = Some(node);
        if self.select_fd_set(fd).is_err() {
            return None;
        }
        self.print_names();
        find_node(&self.nodes.reg, name).map(get_creation)
    }

    // Port of erts/epmd/src/epmd_srv.c:node_unreg and node_unreg_sock.
    fn node_unreg_name(&mut self, name: &[u8]) -> Option<RawFd> {
        let mut link = &mut self.nodes.reg;
        while link.is_some() {
            let is_match = link
                .as_ref()
                .is_some_and(|current| current.symname[..node_name_len(current)] == name[..]);
            if is_match {
                let mut node = link.take().expect("node exists");
                *link = node.next.take();
                let fd = node.fd;
                self.dbg_tty_printf(
                    1,
                    &format!(
                        "unregistering '{}:{}', port {}",
                        display_name(&node),
                        get_creation(&node),
                        node.port
                    ),
                );
                self.nodes.unreg.append(node);
                self.print_names();
                return Some(fd);
            }
            let current = link.as_mut().expect("node exists");
            link = &mut current.next;
        }
        self.dbg_tty_printf(
            1,
            &format!(
                "trying to unregister node with unknown name {}",
                String::from_utf8_lossy(name)
            ),
        );
        None
    }

    fn node_unreg_sock(&mut self, fd: RawFd) -> Option<RawFd> {
        let mut link = &mut self.nodes.reg;
        while link.is_some() {
            let is_match = link.as_ref().is_some_and(|current| current.fd == fd);
            if is_match {
                let mut node = link.take().expect("node exists");
                *link = node.next.take();
                let result = node.fd;
                self.dbg_tty_printf(
                    1,
                    &format!(
                        "unregistering '{}:{}', port {}",
                        display_name(&node),
                        get_creation(&node),
                        node.port
                    ),
                );
                self.nodes.unreg.append(node);
                self.print_names();
                return Some(result);
            }
            let current = link.as_mut().expect("node exists");
            link = &mut current.next;
        }
        self.dbg_tty_printf(
            1,
            &format!("trying to unregister node with unknown file descriptor {fd}"),
        );
        None
    }

    // Port of erts/epmd/src/epmd_srv.c:print_names.
    fn print_names(&self) {
        if self.daemon || self.debug < 3 {
            return;
        }
        let mut count = 0;
        let mut node = self.nodes.reg.as_deref();
        while let Some(active) = node {
            eprintln!(
                "*****     active name     \"{}#{}\" at port {}, fd = {}\r",
                display_name(active),
                get_creation(active),
                active.port,
                active.fd
            );
            count += 1;
            node = active.next.as_deref();
        }
        eprintln!("*****     reg calculated count  : {count}\r");
        let mut node = self.nodes.unreg.head.as_deref();
        let mut count = 0;
        while let Some(old) = node {
            eprintln!(
                "*****     old/unused name \"{}#{}\"\r",
                display_name(old),
                get_creation(old)
            );
            count += 1;
            node = old.next.as_deref();
        }
        eprintln!(
            "*****     unreg counter         : {}\r",
            self.nodes.unreg.count
        );
        eprintln!("*****     unreg calculated count: {count}\r");
    }

    // Port of erts/epmd/src/epmd_srv.c:dbg_print_buf.
    fn dbg_print_buf(&self, buffer: &[u8], length: usize) {
        if self.daemon || self.debug < 2 {
            return;
        }
        self.dbg_tty_printf(1, &format!("got {length} bytes"));
        let original_length = length;
        let length = length.min(1024);
        let mut row_start = 0;
        while row_start < length {
            eprint!("***** {row_start:08x}");
            for (index, byte) in (row_start..row_start + 16).map(|index| (index, buffer.get(index)))
            {
                if index % 8 == 0 {
                    eprint!(" ");
                }
                match byte {
                    Some(byte) if index < length => eprint!(" {byte:02x}"),
                    _ => eprint!("   "),
                }
            }
            eprint!("  |");
            for byte in &buffer[row_start..(row_start + 16).min(length)] {
                eprint!(
                    "{}",
                    if (32..=126).contains(byte) {
                        *byte as char
                    } else {
                        '.'
                    }
                );
            }
            eprintln!("|\r");
            row_start += 16;
        }
        if original_length != length {
            eprintln!("***** ......and more\r");
        }
    }

    // Port of erts/epmd/src/epmd.c:dbg_printf and dbg_tty_printf.
    fn dbg_printf(&self, level: i32, message: &str) {
        if self.debug >= level {
            if self.daemon {
                raw::syslog(message);
            } else {
                self.debug_message(message, None);
            }
        }
    }

    fn dbg_tty_printf(&self, level: i32, message: &str) {
        if self.debug >= level && !self.daemon {
            self.debug_message(message, None);
        }
    }

    fn dbg_perror(&self, message: &str, error: &io::Error) {
        if self.daemon {
            raw::syslog(&format!("{message}: {error}"));
        } else {
            self.debug_message(message, Some(error));
        }
    }

    fn debug_message(&self, message: &str, error: Option<&io::Error>) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |time| time.as_secs() as u32);
        let prefix = raw::ctime(now);
        if let Some(error) = error {
            eprintln!("epmd: {prefix}: {message}: {}\r", error);
        } else {
            eprintln!("epmd: {prefix}: {message}\r");
        }
    }

    // Port of erts/epmd/src/epmd_cli.c:kill_epmd.
    fn kill_epmd(&self) -> Result<(), i32> {
        let fd = self.connect_cli()?;
        let _guard = FdGuard(fd);
        let request = [0, 1, KILL_REQ];
        self.client_write(fd, &request)?;
        let mut response = [0u8; 2];
        match read_fill(fd, &mut response) {
            Ok(2) if &response == b"OK" => {
                println!("Killed");
                Err(0)
            }
            Ok(2) => {
                println!("Killing not allowed - living nodes in database.");
                Err(1)
            }
            Err(error) => {
                println!("epmd: failed to read answer from local epmd");
                let _ = error;
                Err(1)
            }
            Ok(count) => {
                let response = String::from_utf8_lossy(&response[..count]);
                println!("epmd: local epmd responded with <{response}>");
                Err(1)
            }
        }
    }

    // Port of erts/epmd/src/epmd_cli.c:stop_cli.
    fn stop_cli(&self, name: &[u8]) -> Result<(), i32> {
        if name.len() > 1000 {
            print!("epmd: Name too long!");
            return Err(1);
        }
        let fd = self.connect_cli()?;
        let _guard = FdGuard(fd);
        let mut request = [0u8; 1024];
        request[..2].copy_from_slice(&((name.len() + 1) as u16).to_be_bytes());
        request[2] = STOP_REQ;
        request[3..3 + name.len()].copy_from_slice(name);
        request[3 + name.len()] = 0;
        self.client_write(fd, &request[..name.len() + 3])?;
        let mut response = [0u8; 7];
        match read_fill(fd, &mut response) {
            Ok(7) => {
                println!("{}", String::from_utf8_lossy(&response));
                Err(0)
            }
            Err(_) => {
                println!("epmd: failed to read answer from local epmd");
                Err(1)
            }
            Ok(count) => {
                println!(
                    "epmd: local epmd responded with <{}>",
                    String::from_utf8_lossy(&response[..count])
                );
                Err(1)
            }
        }
    }

    // Port of erts/epmd/src/epmd_cli.c:epmd_call.
    fn epmd_call(&self, what: u8) -> Result<(), i32> {
        let fd = self.connect_cli()?;
        let _guard = FdGuard(fd);
        self.client_write(fd, &[0, 1, what])?;
        let mut port = [0u8; 4];
        match raw::read(fd, &mut port) {
            Ok(4) => {}
            _ => {
                if !self.silent {
                    println!("epmd: no response from local epmd");
                }
                return Err(1);
            }
        }
        if !self.silent {
            println!(
                "epmd: up and running on port {} with data:",
                u32::from_be_bytes(port)
            );
            let _ = io::stdout().flush();
        }
        let mut buffer = [0u8; OUTBUF_SIZE];
        loop {
            match raw::read(fd, &mut buffer) {
                Ok(0) => return Err(0),
                Err(_) => return Err(0),
                Ok(count) if !self.silent => {
                    let _ = io::stdout().write_all(&buffer[..count]);
                }
                Ok(_) => {}
            }
        }
    }

    fn connect_cli(&self) -> Result<RawFd, i32> {
        raw::connect_loopback(self.port as u16).map_err(|_| {
            if !self.silent {
                eprintln!("epmd: Cannot connect to local epmd");
            }
            1
        })
    }

    fn client_write(&self, fd: RawFd, request: &[u8]) -> Result<(), i32> {
        match raw::write(fd, request) {
            Ok(count) if count == request.len() => Ok(()),
            _ => {
                println!("epmd: Can't write to epmd");
                Err(1)
            }
        }
    }
}

struct FdGuard(RawFd);

impl Drop for FdGuard {
    // erts equivalent: client descriptor closure at process exit in epmd_cli.c.
    fn drop(&mut self) {
        raw::close(self.0);
    }
}

fn main() -> ExitCode {
    let arguments: Vec<OsString> = std::env::args_os().collect();
    let mut epmd = Epmd::new();
    match epmd.parse_args(&arguments) {
        Ok(Some(status)) => {
            epmd.notify_exit(status);
            ExitCode::from(status as u8)
        }
        Ok(None) => ExitCode::from(epmd.serve() as u8),
        Err(()) => epmd.usage(),
    }
}

// erts equivalent: epmd_cleanup_exit status returned by epmd_cli.c commands.
fn client_status(result: Result<(), i32>) -> i32 {
    result.err().unwrap_or(0)
}

// erts equivalent: atoi calls in epmd.c:epmd_main and get_port_no.
fn c_atoi(bytes: &[u8]) -> i32 {
    let mut index = 0;
    while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
        index += 1;
    }
    let negative = match bytes.get(index) {
        Some(b'-') => {
            index += 1;
            true
        }
        Some(b'+') => {
            index += 1;
            false
        }
        _ => false,
    };
    let start = index;
    let mut number = 0i64;
    while let Some(byte @ b'0'..=b'9') = bytes.get(index) {
        number = number
            .saturating_mul(10)
            .saturating_add((byte - b'0') as i64);
        index += 1;
    }
    if start == index {
        return 0;
    }
    let signed = if negative { -number } else { number };
    signed.clamp(i32::MIN as i64, i32::MAX as i64) as i32
}

// Port of erts/epmd/src/epmd_srv.c:verify_utf8, OTP-29.1.1.
fn verify_utf8(source: &[u8]) -> i32 {
    let mut size = source.len();
    let mut index = 0;
    let mut chars = 0;
    while size != 0 {
        let first = source[index];
        if first & 0x80 == 0 {
            index += 1;
            size -= 1;
        } else if first & 0xe0 == 0xc0 {
            if size < 2 || source[index + 1] & 0xc0 != 0x80 || first < 0xc2 {
                return -1;
            }
            index += 2;
            size -= 2;
        } else if first & 0xf0 == 0xe0 {
            if size < 3
                || source[index + 1] & 0xc0 != 0x80
                || source[index + 2] & 0xc0 != 0x80
                || (first == 0xe0 && source[index + 1] < 0xa0)
                || (first & 0x0f == 0x0d && source[index + 1] & 0x20 != 0)
            {
                return -1;
            }
            index += 3;
            size -= 3;
        } else if first & 0xf8 == 0xf0 {
            if size < 4
                || source[index + 1] & 0xc0 != 0x80
                || source[index + 2] & 0xc0 != 0x80
                || source[index + 3] & 0xc0 != 0x80
                || (first == 0xf0 && source[index + 1] < 0x90)
                || (first & 0x07 > 0x04)
                || (first & 0x07 == 0x04 && source[index + 1] & 0x3f > 0x0f)
            {
                return -1;
            }
            index += 4;
            size -= 4;
        } else {
            return -1;
        }
        chars += 1;
    }
    chars
}

// erts equivalent: epmd_srv.c:length_str.
fn node_name_len(node: &Node) -> usize {
    node.symname
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(MAX_SYMLEN)
}

// erts equivalent: C-string formatting of Node.symname in epmd_srv.c.
fn display_name(node: &Node) -> String {
    String::from_utf8_lossy(&node.symname[..node_name_len(node)]).into_owned()
}

// erts equivalent: is_same_str walks in epmd_srv.c:node_reg2 and do_request.
fn find_node<'a>(head: &'a Option<Box<Node>>, name: &[u8]) -> Option<&'a Node> {
    let mut node = head.as_deref();
    while let Some(current) = node {
        if current.symname[..node_name_len(current)] == name[..] {
            return Some(current);
        }
        node = current.next.as_deref();
    }
    None
}

// Port of erts/epmd/src/epmd_srv.c:bump_creation, OTP-29.1.1.
fn bump_creation(node: &mut Node) {
    node.cr_counter = node.cr_counter.wrapping_add(1);
    if node.cr_counter < 4 {
        node.cr_counter = 4;
    }
}

// Port of erts/epmd/src/epmd_srv.c:get_creation, OTP-29.1.1.
fn get_creation(node: &Node) -> u32 {
    if node.highvsn >= 6 {
        node.cr_counter
    } else {
        node.cr_counter % 3 + 1
    }
}

// Port of erts/epmd/src/epmd_cli.c:read_fill, OTP-29.1.1.
fn read_fill(fd: RawFd, buffer: &mut [u8]) -> io::Result<usize> {
    let mut got = 0;
    while got < buffer.len() {
        match raw::read(fd, &mut buffer[got..]) {
            Ok(0) => return Ok(0),
            Ok(count) => got += count,
            Err(error) => return Err(error),
        }
    }
    Ok(got)
}

// erts equivalent: erts_snprintf writes in epmd_srv.c:do_request.
fn append_format(
    buffer: &mut [u8],
    offset: &mut usize,
    arguments: std::fmt::Arguments<'_>,
) -> io::Result<()> {
    let mut cursor = io::Cursor::new(&mut buffer[*offset..]);
    cursor.write_fmt(arguments)?;
    *offset += cursor.position() as usize;
    Ok(())
}
