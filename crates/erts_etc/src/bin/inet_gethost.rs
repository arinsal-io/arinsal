// Port of erts/etc/common/inet_gethost.c, OTP-29.1.1.

#[path = "inet_gethost/raw.rs"]
mod raw;

use raw::{ForkResult, HostEntry, Queue};
use std::ffi::OsString;
use std::os::fd::RawFd;
use std::process;

const PACKET_BYTES: usize = 4;
const OP_GETHOSTBYNAME: u8 = 1;
const OP_GETHOSTBYADDR: u8 = 2;
const OP_CANCEL_REQUEST: u8 = 3;
const OP_CONTROL: u8 = 4;
const PROTO_IPV4: u8 = 1;
const PROTO_IPV6: u8 = 2;
const SETOPT_DEBUG_LEVEL: u8 = 0;
const UNIT_IPV4: usize = 4;
const UNIT_IPV6: usize = 16;
const DOMAINNAME_MAX: usize = 258;
const CHILDWAIT_TMO: u64 = 1;

const ERRCODE_NOTSUP: i32 = 1;
const ERRCODE_HOST_NOT_FOUND: i32 = 2;
const ERRCODE_TRY_AGAIN: i32 = 3;
const ERRCODE_NO_RECOVERY: i32 = 4;
const ERRCODE_NO_DATA: i32 = 5;
const ERRCODE_NETDB_INTERNAL: i32 = 7;
const HOST_NOT_FOUND: i32 = 1;
const TRY_AGAIN: i32 = 2;
const NO_RECOVERY: i32 = 3;
const NO_DATA: i32 = 4;

#[derive(Clone, Copy, PartialEq, Eq)]
enum WorkerState {
    Empty,
    Free,
    Busy,
    Stalled,
}

struct Worker {
    state: WorkerState,
    pid: libc::pid_t,
    writeto: RawFd,
    readfrom: RawFd,
    serial: i32,
    domain: [u8; DOMAINNAME_MAX],
    queue: Queue,
}

struct Parent {
    program_name: String,
    debug_level: i32,
    greedy_threshold: i32,
    max_workers: usize,
    busy: Vec<Worker>,
    free: Vec<Worker>,
    stalled: Vec<Worker>,
    queue: Queue,
}

fn main() {
    let mut args = std::env::args_os();
    let program_name = args
        .next()
        .unwrap_or_else(|| OsString::from("inet_gethost"));
    let program_name = program_name.to_string_lossy().into_owned();
    let mut parent = Parent::new(program_name, args.collect());
    if let Err(message) = parent.run() {
        parent.fatal(&message);
    }
    parent.kill_all_workers();
}

impl Parent {
    fn new(program_name: String, args: Vec<OsString>) -> Self {
        let mut num_workers = 1usize;
        let mut greedy_threshold = 0i32;
        let mut disable_greedy = false;
        let mut index = 0;
        while index < args.len() {
            let arg = args[index].to_string_lossy();
            if arg == "-d" {
                // Initialized below from ERL_INET_GETHOST_DEBUG.
                index += 1;
                continue;
            }
            if arg == "-g" && index + 1 < args.len() {
                index += 1;
                let value = c_atoi(&args[index].to_string_lossy());
                if value == 0 {
                    usage(&program_name, &args[index].to_string_lossy());
                } else {
                    greedy_threshold = value;
                }
            } else if arg == "-ng" {
                disable_greedy = true;
            } else {
                let value = c_atoi(&arg);
                if value == 0 {
                    usage(&program_name, &arg);
                } else {
                    num_workers = value as usize;
                }
            }
            index += 1;
        }

        if greedy_threshold == 0 {
            greedy_threshold = ((3 * num_workers) / 4) as i32;
            if greedy_threshold == 0 {
                greedy_threshold = num_workers as i32;
            }
        }
        if disable_greedy {
            greedy_threshold = num_workers as i32 + 1;
        }
        let mut debug_level = std::env::var("ERL_INET_GETHOST_DEBUG")
            .map(|value| c_atoi(&value))
            .unwrap_or(0);
        for arg in args {
            if arg == "-d" {
                debug_level += 1;
            }
        }

        Self {
            program_name,
            debug_level,
            greedy_threshold,
            max_workers: num_workers,
            busy: Vec::with_capacity(num_workers),
            free: Vec::with_capacity(num_workers),
            stalled: Vec::with_capacity(num_workers),
            queue: Queue::new(),
        }
    }

    fn run(&mut self) -> Result<(), String> {
        raw::init_signals();
        self.main_loop()
    }

    // Port of erts/etc/common/inet_gethost.c (main_loop), OTP-29.1.1.
    fn main_loop(&mut self) -> Result<(), String> {
        let mut input = Vec::new();
        loop {
            let mut descriptors = vec![0];
            descriptors.extend(self.free.iter().map(|worker| worker.readfrom));
            descriptors.extend(self.busy.iter().map(|worker| worker.readfrom));
            descriptors.extend(self.stalled.iter().map(|worker| worker.readfrom));
            let ready = raw::select_read(&descriptors, None).map_err(|error| {
                format!("Select failed (invalid internal structures?), errno = {error}.")
            })?;

            let mut index = 0;
            while index < self.free.len() {
                if ready.contains(&self.free[index].readfrom) {
                    self.handle_io_free(index);
                } else {
                    index += 1;
                }
            }
            index = 0;
            while index < self.busy.len() {
                if ready.contains(&self.busy[index].readfrom) {
                    match self.handle_io_busy(index)? {
                        IoBusyResult::Advance => index += 1,
                        IoBusyResult::Removed => {}
                        IoBusyResult::Closed => return Ok(()),
                    }
                } else {
                    index += 1;
                }
            }
            index = 0;
            while index < self.stalled.len() {
                if ready.contains(&self.stalled[index].readfrom) {
                    self.handle_io_stalled(index);
                } else {
                    index += 1;
                }
            }

            self.check_queue()?;
            if ready.contains(&0) {
                if !read_request(&mut input)? {
                    return Ok(());
                }
                self.handle_request(&input)?;
            }
        }
    }

    // Port of erts/etc/common/inet_gethost.c (main_loop request dispatch), OTP-29.1.1.
    fn handle_request(&mut self, request: &[u8]) -> Result<(), String> {
        match request[4] {
            OP_CANCEL_REQUEST => {
                let serial = get_i32(&request[0..4]);
                if !self.clean_queue_of(serial)
                    && let Some(index) = self.busy.iter().position(|worker| worker.serial == serial)
                {
                    if self.busy[index].queue.size() != 0 {
                        self.restart_worker(index)?;
                        self.start_queue_request(index)?;
                    } else {
                        self.stall_worker(index);
                        self.check_queue()?;
                    }
                }
            }
            OP_CONTROL => {
                if get_i32(&request[0..4]) != -1 {
                    return Err(format!("Invalid serial: {}.", get_i32(&request[0..4])));
                }
                let control = request[5];
                if control == SETOPT_DEBUG_LEVEL {
                    self.debug_level = get_i32(&request[6..10]);
                    for kind in 0..3 {
                        let mut index = 0;
                        loop {
                            let result = {
                                let workers = self.workers_mut(kind);
                                if index >= workers.len() {
                                    None
                                } else {
                                    Some(send_request(request, &workers[index]))
                                }
                            };
                            let Some(result) = result else {
                                break;
                            };
                            if result.is_err() {
                                self.warning("Unable to write to child process.");
                                self.kill_worker_at(kind, index);
                            } else {
                                index += 1;
                            }
                        }
                    }
                } else {
                    self.warning(&format!(
                        "Unknown control requested from erlang ({}), message discarded.",
                        control
                    ));
                }
            }
            OP_GETHOSTBYNAME | OP_GETHOSTBYADDR => {
                let proto = request[5];
                if proto != PROTO_IPV4 && proto != PROTO_IPV6 {
                    self.warning(&format!(
                        "Unknown protocol requested from erlang ({}), message discarded.",
                        proto
                    ));
                    return Ok(());
                }
                let Some(domain) = get_domainname(request) else {
                    self.warning(
                        "Malformed message sent from erlang, no domain, message discarded.",
                    );
                    return Ok(());
                };
                if (self.busy.len() as i32) >= self.greedy_threshold
                    && let Some(index) = self.pick_worker_greedy(&domain)
                {
                    self.busy[index].queue.push(request);
                    return Ok(());
                }
                let serial = get_i32(&request[0..4]);
                loop {
                    let Some(index) = self.pick_worker()? else {
                        self.queue.push(request);
                        break;
                    };
                    if self.send_worker_request(request, &self.busy[index]).is_ok() {
                        self.busy[index].serial = serial;
                        self.busy[index].domain = domain;
                        break;
                    }
                    self.kill_last_picked_worker();
                }
            }
            op => self.warning(&format!(
                "Unknown operation requested from erlang ({}), message discarded.",
                op
            )),
        }
        Ok(())
    }

    fn handle_io_busy(&mut self, index: usize) -> Result<IoBusyResult, String> {
        let reply = match read_packet(self.busy[index].readfrom) {
            Ok(reply) => reply,
            Err(_) => {
                if self.busy[index].queue.size() != 0 {
                    self.restart_worker(index)?;
                    self.start_queue_request(index)?;
                    return Ok(IoBusyResult::Advance);
                }
                self.kill_worker_at(1, index);
                return Ok(IoBusyResult::Removed);
            }
        };
        match write_exact(1, &reply) {
            Ok(_) => {}
            Err(0) => return Ok(IoBusyResult::Closed),
            Err(errno) => {
                return Err(format!(
                    "Cannot write reply to erlang process, errno = {errno}."
                ));
            }
        }
        if self.busy[index].queue.size() != 0 {
            self.start_queue_request(index)?;
            Ok(IoBusyResult::Advance)
        } else {
            let mut worker = self.busy.swap_remove(index);
            worker.state = WorkerState::Free;
            self.free.push(worker);
            Ok(IoBusyResult::Removed)
        }
    }

    fn handle_io_free(&mut self, index: usize) {
        self.debug(
            1,
            &format!("Free worker[{}] spontaneously died.", self.free[index].pid),
        );
        self.kill_worker_at(0, index);
    }

    fn handle_io_stalled(&mut self, index: usize) {
        match read_packet(self.stalled[index].readfrom) {
            Err(_) => self.kill_worker_at(2, index),
            Ok(_) => {
                let mut worker = self.stalled.swap_remove(index);
                worker.state = WorkerState::Free;
                self.free.push(worker);
            }
        }
    }

    fn check_queue(&mut self) -> Result<(), String> {
        while self.queue.size() != 0 {
            let Some(index) = self.pick_worker()? else {
                break;
            };
            let (result, serial) = {
                let request = self
                    .queue
                    .front()
                    .expect("queue count matches first pointer");
                (
                    self.send_worker_request(request, &self.busy[index]),
                    get_i32(&request[0..4]),
                )
            };
            if result.is_err() {
                self.kill_last_picked_worker();
                continue;
            }
            self.busy[index].serial = serial;
            let _ = self.queue.pop();
        }
        Ok(())
    }

    fn clean_queue_of(&mut self, serial: i32) -> bool {
        if self.queue.remove_serial(serial) {
            return true;
        }
        self.busy
            .iter_mut()
            .any(|worker| worker.queue.remove_serial(serial))
    }

    // Port of erts/etc/common/inet_gethost.c (pick_worker), OTP-29.1.1.
    fn pick_worker(&mut self) -> Result<Option<usize>, String> {
        let worker = if let Some(worker) = self.free.pop() {
            worker
        } else if let Some(worker) = self.stalled.pop() {
            self.kill_worker(&worker);
            match self.create_worker(false)? {
                Some(worker) => worker,
                None => {
                    self.warning("Unable to create worker process, insufficient resources");
                    return Ok(None);
                }
            }
        } else {
            if self.busy.len() == self.max_workers {
                return Ok(None);
            }
            match self.create_worker(false)? {
                Some(worker) => worker,
                None => {
                    self.warning("Unable to create worker process, insufficient resources");
                    return Ok(None);
                }
            }
        };
        let mut worker = worker;
        worker.state = WorkerState::Busy;
        self.busy.push(worker);
        Ok(Some(self.busy.len() - 1))
    }

    // Port of erts/etc/common/inet_gethost.c (pick_worker_greedy), OTP-29.1.1.
    fn pick_worker_greedy(&self, domain: &[u8; DOMAINNAME_MAX]) -> Option<usize> {
        self.busy
            .iter()
            .enumerate()
            .filter(|(_, worker)| domain_equal(&worker.domain, domain))
            .min_by_key(|(_, worker)| worker.queue.size())
            .map(|(index, _)| index)
    }

    fn send_worker_request(&self, request: &[u8], worker: &Worker) -> Result<(), i32> {
        let result = send_request(request, worker);
        if result.is_err() {
            self.warning("Unable to write to child process.");
        }
        result
    }

    // Port of erts/etc/common/inet_gethost.c (create_worker), OTP-29.1.1.
    fn create_worker(&mut self, _save_queue: bool) -> Result<Option<Worker>, String> {
        let (p0_read, p0_write) = match raw::pipe() {
            Ok(pipe) => pipe,
            Err(errno) => {
                self.warning(&format!(
                    "Could not create, pipes for subprocess, errno = {errno}"
                ));
                return Ok(None);
            }
        };
        let (p1_read, p1_write) = match raw::pipe() {
            Ok(pipe) => pipe,
            Err(errno) => {
                let _ = raw::close(p0_read);
                let _ = raw::close(p0_write);
                self.warning(&format!(
                    "Could not create, pipes for subprocess, errno = {errno}"
                ));
                return Ok(None);
            }
        };
        match raw::fork() {
            Err(errno) => {
                self.warning(&format!("Could not fork(), errno = {errno}"));
                for fd in [p0_read, p0_write, p1_read, p1_write] {
                    let _ = raw::close(fd);
                }
                Ok(None)
            }
            Ok(ForkResult::Parent(pid)) => {
                let _ = raw::close(p0_write);
                let _ = raw::close(p1_read);
                Ok(Some(Worker {
                    state: WorkerState::Free,
                    pid,
                    writeto: p1_write,
                    readfrom: p0_read,
                    serial: -1,
                    domain: [0; DOMAINNAME_MAX],
                    queue: Queue::new(),
                }))
            }
            Ok(ForkResult::Child) => {
                let _ = raw::close(p1_write);
                let _ = raw::close(p0_read);
                for worker in self.free.iter().chain(&self.busy).chain(&self.stalled) {
                    if worker.state != WorkerState::Empty {
                        let _ = raw::close(worker.readfrom);
                        let _ = raw::close(worker.writeto);
                    }
                }
                self.busy.clear();
                self.free.clear();
                self.stalled.clear();
                if raw::dup2(p1_read, 0).is_err() || raw::dup2(p0_write, 1).is_err() {
                    self.fatal("Worker could not dup2().");
                }
                let _ = raw::close(p1_read);
                let _ = raw::close(p0_write);
                raw::ignore_sigchld();
                let code = worker_loop(self.debug_level, &self.program_name);
                process::exit(code);
            }
        }
    }

    // Port of erts/etc/common/inet_gethost.c (restart_worker), OTP-29.1.1.
    fn restart_worker(&mut self, index: usize) -> Result<(), String> {
        let empty = Worker {
            state: WorkerState::Empty,
            pid: -1,
            writeto: -1,
            readfrom: -1,
            serial: -1,
            domain: [0; DOMAINNAME_MAX],
            queue: Queue::new(),
        };
        let mut worker = std::mem::replace(&mut self.busy[index], empty);
        let queue = std::mem::replace(&mut worker.queue, Queue::new());
        self.kill_worker(&worker);
        worker.state = WorkerState::Empty;
        match self.create_worker(false)? {
            Some(mut replacement) => {
                replacement.queue = queue;
                self.busy[index] = replacement;
                Ok(())
            }
            None => {
                worker.queue = queue;
                self.busy[index] = worker;
                Err("Unable to create worker process, insufficient resources".into())
            }
        }
    }

    fn start_queue_request(&mut self, index: usize) -> Result<(), String> {
        let queued = self.busy[index].queue.pop().ok_or_else(|| {
            "Expected que'd requests but found none, internal datastructure corrupted!".to_string()
        })?;
        let request = queued.request();
        let serial = get_i32(&request[0..4]);
        loop {
            if self.send_worker_request(request, &self.busy[index]).is_ok() {
                self.busy[index].serial = serial;
                self.busy[index].domain = get_domainname(request).unwrap_or([0; DOMAINNAME_MAX]);
                return Ok(());
            }
            self.restart_worker(index)?;
        }
    }

    fn stall_worker(&mut self, index: usize) {
        let mut worker = self.busy.swap_remove(index);
        worker.state = WorkerState::Stalled;
        self.stalled.push(worker);
    }

    fn kill_last_picked_worker(&mut self) {
        if let Some(worker) = self.busy.pop() {
            self.kill_worker(&worker);
        }
    }

    fn kill_worker_at(&mut self, kind: usize, index: usize) {
        let worker = self.workers_mut(kind).swap_remove(index);
        self.kill_worker(&worker);
    }

    fn kill_worker(&self, worker: &Worker) {
        self.debug(
            3,
            &format!(
                "Killing worker[{}] with fd {}, serial {}",
                worker.pid, worker.readfrom, worker.serial
            ),
        );
        let _ = raw::kill(worker.pid, libc::SIGUSR1);
        loop {
            match raw::select_read(&[worker.readfrom], Some(CHILDWAIT_TMO)) {
                Err(errno) if errno == libc::EINTR => continue,
                Err(errno) => {
                    self.warning(&format!(
                        "Unable to select on dying child file descriptor, errno = {errno}."
                    ));
                    break;
                }
                Ok(ready) if ready.is_empty() => {
                    self.warning(&format!(
                        "Timeout waiting for child process to die, ignoring child (pid = {}).",
                        worker.pid
                    ));
                    break;
                }
                Ok(_) => match raw::read(worker.readfrom, &mut [0; 1024]) {
                    Ok(0) => break,
                    Ok(_) => continue,
                    Err(errno) if errno == libc::EINTR => continue,
                    Err(errno) => {
                        self.warning(&format!(
                            "Child file descriptor not closed properly, errno = {errno}"
                        ));
                        break;
                    }
                },
            }
        }
        let _ = raw::close(worker.readfrom);
        let _ = raw::close(worker.writeto);
    }

    fn kill_all_workers(&self) {
        for worker in self.busy.iter().chain(&self.free).chain(&self.stalled) {
            let _ = raw::kill(worker.pid, libc::SIGUSR1);
        }
    }

    fn workers_mut(&mut self, kind: usize) -> &mut Vec<Worker> {
        match kind {
            0 => &mut self.free,
            1 => &mut self.busy,
            _ => &mut self.stalled,
        }
    }

    fn debug(&self, level: i32, message: &str) {
        if self.debug_level >= level {
            raw::write_stderr(&format!(
                "{}[{}] (DEBUG):{}\r\n",
                self.program_name,
                raw::pid(),
                message
            ));
        }
    }

    fn warning(&self, message: &str) {
        raw::write_stderr(&format!(
            "{}[{}]: WARNING:{}\r\n",
            self.program_name,
            raw::pid(),
            message
        ));
    }

    fn fatal(&self, message: &str) -> ! {
        raw::write_stderr(&format!(
            "{}[{}]: FATAL ERROR:{}\r\n",
            self.program_name,
            raw::pid(),
            message
        ));
        self.kill_all_workers();
        process::exit(1)
    }
}

enum IoBusyResult {
    Advance,
    Removed,
    Closed,
}

fn usage(program_name: &str, unknown: &str) {
    raw::write_stderr(&format!(
        "{program_name}: Unknown option \"{unknown}\"\nUsage: {program_name} [-d [-d ...]] [-g <greedy threshold>] [<number of workers>]\n"
    ));
}

fn c_atoi(value: &str) -> i32 {
    let bytes = value.as_bytes();
    let mut index = 0;
    while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
        index += 1;
    }
    let mut sign = 1i64;
    if bytes.get(index) == Some(&b'-') {
        sign = -1;
        index += 1;
    } else if bytes.get(index) == Some(&b'+') {
        index += 1;
    }
    let mut result = 0i64;
    while let Some(byte @ b'0'..=b'9') = bytes.get(index).copied() {
        result = result
            .saturating_mul(10)
            .saturating_add(i64::from(byte - b'0'));
        index += 1;
    }
    result.saturating_mul(sign) as i32
}

fn read_request(buffer: &mut Vec<u8>) -> Result<bool, String> {
    let mut header = [0; PACKET_BYTES];
    match read_exact(0, &mut header)? {
        0 => return Ok(false),
        PACKET_BYTES => {}
        _ => return Err("Unexpected end of file on main input, errno = 0".into()),
    }
    let size = u32::from_be_bytes(header) as usize;
    if size > buffer.capacity() {
        buffer.reserve(size - buffer.capacity());
    }
    buffer.resize(size, 0);
    if read_exact(0, buffer)? != size {
        return Err("Unexpected end of file on main input, errno = 0".into());
    }
    if size < 5 {
        return Err(format!(
            "Unexpected message on main input, message size {size} less than minimum."
        ));
    }
    Ok(true)
}

fn read_packet(fd: RawFd) -> Result<Vec<u8>, i32> {
    let mut header = [0; PACKET_BYTES];
    if read_exact(fd, &mut header).map_err(|_| raw::last_errno())? != PACKET_BYTES {
        return Err(raw::last_errno());
    }
    let size = u32::from_be_bytes(header) as usize;
    let mut packet = vec![0; size + PACKET_BYTES];
    packet[..PACKET_BYTES].copy_from_slice(&header);
    if read_exact(fd, &mut packet[PACKET_BYTES..]).map_err(|_| raw::last_errno())? != size {
        return Err(raw::last_errno());
    }
    Ok(packet)
}

fn read_exact(fd: RawFd, output: &mut [u8]) -> Result<usize, String> {
    let mut read = 0;
    while read < output.len() {
        match raw::read(fd, &mut output[read..]) {
            Ok(0) => {
                return if read == 0 {
                    Ok(0)
                } else {
                    Err("Unexpected end of file".into())
                };
            }
            Ok(count) => read += count,
            Err(errno) if errno == libc::EINTR => continue,
            Err(errno) => return Err(format!("read failed: {errno}")),
        }
    }
    Ok(read)
}

fn write_exact(fd: RawFd, bytes: &[u8]) -> Result<usize, i32> {
    let mut written = 0;
    while written < bytes.len() {
        match raw::write(fd, &bytes[written..]) {
            Ok(0) => return Ok(0),
            Ok(count) => written += count,
            Err(errno) if errno == libc::EINTR => continue,
            Err(errno) if errno == libc::EPIPE => return Ok(0),
            Err(errno) => return Err(errno),
        }
    }
    Ok(written)
}

fn frame(request: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(PACKET_BYTES + request.len());
    packet.extend_from_slice(&(request.len() as u32).to_be_bytes());
    packet.extend_from_slice(request);
    packet
}

fn send_request(request: &[u8], worker: &Worker) -> Result<(), i32> {
    let header = (request.len() as u32).to_be_bytes();
    write_exact(worker.writeto, &header)?;
    write_exact(worker.writeto, request)?;
    Ok(())
}

fn get_i32(bytes: &[u8]) -> i32 {
    i32::from_be_bytes(bytes[..4].try_into().unwrap())
}

fn get_domainname(request: &[u8]) -> Option<[u8; DOMAINNAME_MAX]> {
    let op = request[4];
    let proto = request[5];
    let data = &request[6..];
    let mut domain = [0; DOMAINNAME_MAX];
    domain[0] = op;
    domain[1] = proto;
    match op {
        OP_GETHOSTBYNAME => {
            if !data.contains(&0) {
                return None;
            }
            let name = data.split(|byte| *byte == 0).next().unwrap_or_default();
            let dot = name
                .iter()
                .position(|byte| *byte == b'.')
                .unwrap_or(name.len());
            let suffix = &name[dot..];
            let count = suffix.len().min(DOMAINNAME_MAX - 2);
            domain[2..2 + count].copy_from_slice(&suffix[..count]);
            domain[DOMAINNAME_MAX - 1] = 0;
            Some(domain)
        }
        OP_GETHOSTBYADDR => {
            let unit = if proto == PROTO_IPV4 {
                UNIT_IPV4
            } else {
                UNIT_IPV6
            };
            if data.len() != unit {
                return None;
            }
            domain[2..2 + unit - 1].copy_from_slice(&data[..unit - 1]);
            Some(domain)
        }
        _ => None,
    }
}

fn domain_equal(left: &[u8; DOMAINNAME_MAX], right: &[u8; DOMAINNAME_MAX]) -> bool {
    if left[..2] != right[..2] {
        return false;
    }
    match left[0] {
        OP_GETHOSTBYNAME => left[2..] == right[2..],
        OP_GETHOSTBYADDR => {
            let len = if left[1] == PROTO_IPV4 {
                UNIT_IPV4
            } else {
                UNIT_IPV6
            };
            left[2..1 + len] == right[2..1 + len]
        }
        _ => false,
    }
}

// Port of erts/etc/common/inet_gethost.c (worker_loop), OTP-29.1.1.
fn worker_loop(mut debug_level: i32, program_name: &str) -> i32 {
    let mut request = Vec::new();
    loop {
        match read_request_worker(&mut request) {
            Ok(true) => {}
            Ok(false) => process::exit(0),
            Err(_) => process::exit(0),
        }
        let serial = get_i32(&request[0..4]);
        let op = request[4];
        if op == OP_CONTROL {
            if serial != -1 {
                process::exit(0);
            }
            if request[5] == SETOPT_DEBUG_LEVEL {
                debug_level = get_i32(&request[6..10]);
                if debug_level >= 1 {
                    raw::write_stderr(&format!(
                        "{program_name}[{}] (DEBUG):Worker debug_level = {debug_level}.\r\n",
                        raw::pid()
                    ));
                }
            }
            continue;
        }
        if debug_level >= 4 {
            let data = String::from_utf8_lossy(&request[6..]);
            raw::write_stderr(&format!(
                "{program_name}[{}] (DEBUG):Worker got request, op = {op}, proto = {}, data = {data}.\r\n",
                raw::pid(),
                request[5]
            ));
        }
        let reply = match op {
            OP_GETHOSTBYNAME => resolve_by_name(serial, request[5], &request[6..]),
            OP_GETHOSTBYADDR => resolve_by_address(serial, request[5], &request[6..]),
            _ => error_reply(serial, ERRCODE_NOTSUP),
        };
        if raw::write(1, &reply).is_err() {
            return 1;
        }
    }
}

fn read_request_worker(buffer: &mut Vec<u8>) -> Result<bool, String> {
    let mut header = [0; PACKET_BYTES];
    match read_exact(0, &mut header)? {
        0 => return Ok(false),
        PACKET_BYTES => {}
        _ => return Err("EOF while reading size".into()),
    }
    let size = u32::from_be_bytes(header) as usize;
    buffer.resize(size, 0);
    if read_exact(0, buffer)? != size {
        return Err("EOF while reading data".into());
    }
    Ok(true)
}

// Port of erts/etc/common/inet_gethost.c (worker_loop OP_GETHOSTBYNAME), OTP-29.1.1.
fn resolve_by_name(serial: i32, proto: u8, name: &[u8]) -> Vec<u8> {
    let name = name.split(|byte| *byte == 0).next().unwrap_or_default();
    match proto {
        PROTO_IPV4 => match raw::gethostbyname(name) {
            Ok(entry) => host_reply(serial, entry),
            Err(code) => error_reply(serial, map_h_errno(code)),
        },
        PROTO_IPV6 => match raw::getaddrinfo(name, libc::AF_INET6) {
            Ok(entries) => ai_reply(serial, libc::AF_INET6, UNIT_IPV6, entries),
            Err(code) => error_reply(serial, map_resolver_error(code)),
        },
        _ => error_reply(serial, ERRCODE_NOTSUP),
    }
}

// Port of erts/etc/common/inet_gethost.c (worker_loop OP_GETHOSTBYADDR), OTP-29.1.1.
fn resolve_by_address(serial: i32, proto: u8, address: &[u8]) -> Vec<u8> {
    match proto {
        PROTO_IPV4 if address.len() == UNIT_IPV4 => {
            match raw::gethostbyaddr(address, libc::AF_INET) {
                Ok(entry) => host_reply(serial, entry),
                Err(code) => error_reply(serial, map_h_errno(code)),
            }
        }
        PROTO_IPV6 if address.len() == UNIT_IPV6 => match raw::getnameinfo(address) {
            Ok(name) => ai_reply(
                serial,
                libc::AF_INET6,
                UNIT_IPV6,
                vec![raw::AiEntry {
                    family: libc::AF_INET6,
                    address: Some(address.to_vec()),
                    canonname: Some(name),
                }],
            ),
            Err(code) => error_reply(serial, map_resolver_error(code)),
        },
        _ => error_reply(serial, ERRCODE_NOTSUP),
    }
}

fn host_reply(serial: i32, entry: HostEntry) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&serial.to_be_bytes());
    payload.push(entry.unit as u8);
    put_u32(&mut payload, entry.addresses.len() as u32);
    for address in entry.addresses {
        payload.extend_from_slice(&address);
    }
    put_u32(&mut payload, entry.names.len() as u32);
    for name in entry.names {
        payload.extend_from_slice(&name);
        payload.push(0);
    }
    frame(&payload)
}

fn ai_reply(
    serial: i32,
    family: libc::c_int,
    addrlen: usize,
    entries: Vec<raw::AiEntry>,
) -> Vec<u8> {
    let matching_addresses: Vec<_> = entries
        .iter()
        .filter(|entry| entry.address.is_some() && entry.family == family)
        .collect();
    let matching_names: Vec<_> = entries
        .iter()
        .filter(|entry| entry.canonname.is_some() && entry.family == family)
        .collect();
    let mut payload = Vec::new();
    payload.extend_from_slice(&serial.to_be_bytes());
    payload.push(addrlen as u8);
    put_u32(&mut payload, matching_addresses.len() as u32);
    for entry in matching_addresses {
        payload.extend_from_slice(entry.address.as_ref().unwrap());
    }
    put_u32(&mut payload, matching_names.len() as u32);
    for entry in matching_names {
        payload.extend_from_slice(entry.canonname.as_ref().unwrap());
        payload.push(0);
    }
    frame(&payload)
}

fn error_reply(serial: i32, error: i32) -> Vec<u8> {
    let message = match error {
        ERRCODE_NOTSUP => b"enotsup".as_slice(),
        ERRCODE_HOST_NOT_FOUND => b"notfound".as_slice(),
        ERRCODE_TRY_AGAIN => b"try_again".as_slice(),
        ERRCODE_NO_RECOVERY => b"no_recovery".as_slice(),
        ERRCODE_NO_DATA => b"no_data".as_slice(),
        _ => b"netdb_internal".as_slice(),
    };
    let mut payload = Vec::new();
    payload.extend_from_slice(&serial.to_be_bytes());
    payload.push(0);
    payload.extend_from_slice(message);
    payload.push(0);
    frame(&payload)
}

fn map_h_errno(code: i32) -> i32 {
    #[cfg(target_os = "linux")]
    {
        match code {
            HOST_NOT_FOUND => ERRCODE_HOST_NOT_FOUND,
            TRY_AGAIN => ERRCODE_TRY_AGAIN,
            NO_RECOVERY => ERRCODE_NO_RECOVERY,
            NO_DATA => ERRCODE_NO_DATA,
            _ => ERRCODE_NETDB_INTERNAL,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = code;
        match code {
            HOST_NOT_FOUND => ERRCODE_HOST_NOT_FOUND,
            TRY_AGAIN => ERRCODE_TRY_AGAIN,
            NO_RECOVERY => ERRCODE_NO_RECOVERY,
            NO_DATA => ERRCODE_NO_DATA,
            _ => ERRCODE_NETDB_INTERNAL,
        }
    }
}

fn map_resolver_error(code: i32) -> i32 {
    if code == libc::EAI_AGAIN {
        ERRCODE_TRY_AGAIN
    } else if code == libc::EAI_FAIL || code == libc::EAI_NONAME || is_eai_nodata(code) {
        ERRCODE_HOST_NOT_FOUND
    } else {
        ERRCODE_NETDB_INTERNAL
    }
}

#[cfg(target_os = "macos")]
fn is_eai_nodata(code: i32) -> bool {
    code == libc::EAI_NODATA
}

#[cfg(not(target_os = "macos"))]
fn is_eai_nodata(_: i32) -> bool {
    false
}

fn put_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}
