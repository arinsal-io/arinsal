use similar_asserts::assert_eq;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

struct PortProcess {
    child: Child,
    input: Option<ChildStdin>,
    output: ChildStdout,
}

impl PortProcess {
    fn spawn(program: &Path, resolver_shim: &Path) -> Self {
        let mut command = Command::new(program);
        command
            .arg("4")
            .env("ERL_INET_GETHOST_DEBUG", "0")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(target_os = "macos")]
        command
            .env("DYLD_INSERT_LIBRARIES", resolver_shim)
            .env("DYLD_FORCE_FLAT_NAMESPACE", "1");
        #[cfg(not(target_os = "macos"))]
        command.env("LD_PRELOAD", resolver_shim);
        let mut child = command
            .spawn()
            .unwrap_or_else(|error| panic!("could not start {}: {error}", program.display()));
        Self {
            input: child.stdin.take(),
            output: child.stdout.take().unwrap(),
            child,
        }
    }

    fn request(&mut self, payload: &[u8]) -> Vec<u8> {
        self.send(payload);
        self.reply()
    }

    fn send(&mut self, payload: &[u8]) {
        let input = self.input.as_mut().unwrap();
        input
            .write_all(&(payload.len() as u32).to_be_bytes())
            .unwrap();
        input.write_all(payload).unwrap();
    }

    fn reply(&mut self) -> Vec<u8> {
        let mut header = [0; 4];
        self.output.read_exact(&mut header).unwrap();
        let size = u32::from_be_bytes(header) as usize;
        let mut reply = Vec::with_capacity(4 + size);
        reply.extend_from_slice(&header);
        reply.resize(4 + size, 0);
        self.output.read_exact(&mut reply[4..]).unwrap();
        reply
    }

    fn control_debug_zero(&mut self) {
        let payload = [
            0xff, 0xff, 0xff, 0xff, // invalid serial
            4, 0, // OP_CONTROL, SETOPT_DEBUG_LEVEL
            0, 0, 0, 0, // level
        ];
        let input = self.input.as_mut().unwrap();
        input
            .write_all(&(payload.len() as u32).to_be_bytes())
            .unwrap();
        input.write_all(&payload).unwrap();
    }

    fn finish(mut self) {
        drop(self.input.take());
        let status = self.child.wait().unwrap();
        assert!(status.success(), "port program exited with {status}");
    }
}

impl Drop for PortProcess {
    fn drop(&mut self) {
        drop(self.input.take());
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

#[test]
fn request_packets_match_otp_byte_for_byte_without_external_dns() {
    let temporary = temporary_directory();
    let resolver_shim = compile_resolver_shim(&temporary);
    let reference = reference_inet_gethost();
    let arinsal = PathBuf::from(env!("CARGO_BIN_EXE_arinsal_inet_gethost"));
    let mut otp = PortProcess::spawn(&reference, &resolver_shim);
    let mut port = PortProcess::spawn(&arinsal, &resolver_shim);

    let localhost_v4 = request_name(1, 1, 1, b"localhost");
    assert_same_reply(&mut otp, &mut port, &localhost_v4);
    otp.control_debug_zero();
    port.control_debug_zero();

    let localhost_v6 = request_name(2, 1, 2, b"localhost");
    assert_same_reply(&mut otp, &mut port, &localhost_v6);
    let ipv4_loopback = request_address(3, 2, 1, &[127, 0, 0, 1]);
    assert_same_reply(&mut otp, &mut port, &ipv4_loopback);
    let ipv6_loopback = request_address(4, 2, 2, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    assert_same_reply(&mut otp, &mut port, &ipv6_loopback);
    let missing = request_name(5, 1, 1, b"nonexistent.invalid");
    let reply = assert_same_reply(&mut otp, &mut port, &missing);
    assert!(reply.windows(8).any(|bytes| bytes == b"notfound"));

    let parallel: Vec<_> = (10..22)
        .map(|serial| request_name(serial, 1, 1, b"localhost"))
        .collect();
    for request in &parallel {
        otp.send(request);
        port.send(request);
    }
    let otp_replies: std::collections::HashMap<_, _> = (0..parallel.len())
        .map(|_| {
            let reply = otp.reply();
            (u32::from_be_bytes(reply[4..8].try_into().unwrap()), reply)
        })
        .collect();
    let port_replies: std::collections::HashMap<_, _> = (0..parallel.len())
        .map(|_| {
            let reply = port.reply();
            (u32::from_be_bytes(reply[4..8].try_into().unwrap()), reply)
        })
        .collect();
    assert_eq!(port_replies, otp_replies);

    otp.finish();
    port.finish();
    fs::remove_dir_all(temporary).unwrap();
}

fn assert_same_reply(otp: &mut PortProcess, port: &mut PortProcess, request: &[u8]) -> Vec<u8> {
    let expected = otp.request(request);
    let actual = port.request(request);
    assert_eq!(actual, expected, "request body {request:?}");
    actual
}

fn request_name(serial: u32, op: u8, protocol: u8, name: &[u8]) -> Vec<u8> {
    let mut request = serial.to_be_bytes().to_vec();
    request.extend_from_slice(&[op, protocol]);
    request.extend_from_slice(name);
    request.push(0);
    request
}

fn request_address(serial: u32, op: u8, protocol: u8, address: &[u8]) -> Vec<u8> {
    let mut request = serial.to_be_bytes().to_vec();
    request.extend_from_slice(&[op, protocol]);
    request.extend_from_slice(address);
    request
}

fn reference_inet_gethost() -> PathBuf {
    if let Some(root) = std::env::var_os("ERLANG_ROOT") {
        let path = PathBuf::from(root).join("erts-17.1/bin/inet_gethost");
        if path.is_file() {
            return path;
        }
    }
    [
        PathBuf::from("$HOME/.asdf/installs/erlang/29.1.1/erts-17.1/bin/inet_gethost"),
        PathBuf::from("/home/ubuntu/.asdf/installs/erlang/29.1.1/erts-17.1/bin/inet_gethost"),
    ]
    .into_iter()
    .find(|path| path.is_file())
    .expect("OTP 29.1.1 erts-17.1/bin/inet_gethost is required for differential tests")
}

fn temporary_directory() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("inet-gethost-{}-{nonce}", std::process::id()));
    fs::create_dir(&path).unwrap();
    path
}

fn compile_resolver_shim(directory: &Path) -> PathBuf {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/no_external_dns.c");
    #[cfg(target_os = "macos")]
    let output = directory.join("no_external_dns.dylib");
    #[cfg(not(target_os = "macos"))]
    let output = directory.join("no_external_dns.so");
    let mut command = Command::new("cc");
    command.arg("-fPIC");
    #[cfg(target_os = "macos")]
    command.args(["-dynamiclib", "-undefined", "dynamic_lookup"]);
    #[cfg(not(target_os = "macos"))]
    command.arg("-shared");
    let result = command.arg(source).arg("-o").arg(&output).output().unwrap();
    assert!(
        result.status.success(),
        "resolver shim compile failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    output
}
