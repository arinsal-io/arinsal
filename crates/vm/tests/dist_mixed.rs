use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static NEXT_CASE: AtomicUsize = AtomicUsize::new(1);
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn serial_test() -> MutexGuard<'static, ()> {
    TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner())
}

fn short_hostname() -> String {
    "localhost".to_owned()
}

fn otp_root() -> std::ffi::OsString {
    std::env::var_os("ARINSAL_OTP_ROOT").unwrap_or_else(|| {
        let output = std::process::Command::new("erl")
            .args([
                "-noshell",
                "-eval",
                "io:format(\"~s\",[code:root_dir()]),halt().",
            ])
            .output()
            .expect("OTP 29.1.1 root: set ARINSAL_OTP_ROOT or put erl on PATH");
        String::from_utf8_lossy(&output.stdout).trim().into()
    })
}

fn epmd_names() -> Option<String> {
    let address = SocketAddr::from(([127, 0, 0, 1], 4369));
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .ok()?;
    stream.write_all(&[0, 1, b'n']).ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    Some(response)
}

fn epmd_has_name(node: &str) -> bool {
    epmd_names().is_some_and(|names| {
        names
            .split("name ")
            .any(|entry| entry.starts_with(&format!("{node} at port ")))
    })
}

fn unique_suffix(id: usize) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{}{:x}{id:04x}", std::process::id(), nanos)
}

struct ErlNode {
    child: Child,
    stdin: Option<ChildStdin>,
}

struct ArinsalNode {
    child: Child,
    stdin: Option<ChildStdin>,
    node: String,
}

impl Drop for ArinsalNode {
    fn drop(&mut self) {
        drop(self.stdin.take());
        for _ in 0..20 {
            if self.child.try_wait().ok().flatten().is_some() {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        stop_process_group(&mut self.child);
    }
}

impl Drop for ErlNode {
    fn drop(&mut self) {
        drop(self.stdin.take());
        for _ in 0..20 {
            if self.child.try_wait().ok().flatten().is_some() {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        stop_process_group(&mut self.child);
    }
}

fn stop_process_group(child: &mut Child) {
    if child.try_wait().ok().flatten().is_some() {
        return;
    }
    let pid = child.id();
    let _ = Command::new("/bin/kill")
        .args(["-KILL", &format!("-{pid}")])
        .status();
    let _ = child.kill();
    let _ = child.wait();
}

fn start_erl() -> (ErlNode, String, String, String) {
    let id = NEXT_CASE.fetch_add(1, Ordering::Relaxed);
    let suffix = unique_suffix(id);
    let node = format!("dm_e{suffix}");
    let cookie = format!("dm_cookie_{suffix}");
    let host = short_hostname();
    let local_node = format!("{node}@{host}");
    let expression = "Port=open_port({fd,0,1},[eof]), register(echo,self()), Loop=fun Again() -> receive {Port,eof} -> halt(0); {get_alias,From} -> From ! {remote_alias,erlang:alias()}, Again(); {alias_roundtrip,From,Msg} -> From ! {alias_ack,Msg}, Again(); {From,Msg,Alias} -> Reply={self(),Msg,Port,make_ref()}, From ! {pid,Reply}, {mixed_receiver,node(From)} ! {name,Reply}, Alias ! {alias,Reply}, Again() end end, Loop().";
    let mut child = Command::new("timeout")
        .args([
            "--kill-after=3",
            "300",
            "erl",
            "-noshell",
            "-sname",
            &local_node,
            "-setcookie",
            &cookie,
            "-eval",
            expression,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .process_group(0)
        .spawn()
        .expect("start timeout-supervised OTP node");
    let stdin = child.stdin.take().expect("Erlang stdin pipe");
    let child = ErlNode {
        child,
        stdin: Some(stdin),
    };
    let remote_node = format!("{node}@{host}");
    for _ in 0..100 {
        if epmd_has_name(&node) {
            thread::sleep(Duration::from_secs(4));
            return (child, remote_node, cookie, host);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("OTP node {node} did not register with epmd");
}

fn arinsal_eval(cookie: &str, host: &str, expression: &str) -> String {
    arinsal_eval_with_dist_buffer(cookie, host, expression, None)
}

fn arinsal_eval_with_dist_buffer(
    cookie: &str,
    host: &str,
    expression: &str,
    busy_limit_kb: Option<&str>,
) -> String {
    let id = NEXT_CASE.fetch_add(1, Ordering::Relaxed);
    let node = format!("dm_a{}", unique_suffix(id));
    let local_node = format!("{node}@{host}");
    let binary = std::env::current_exe()
        .expect("current test executable")
        .parent()
        .and_then(std::path::Path::parent)
        .and_then(std::path::Path::parent)
        .expect("target directory")
        .join("release/arinsal");
    let mut command = Command::new("timeout");
    command.env("ARINSAL_OTP_ROOT", otp_root());
    command.args([
        "--kill-after=3",
        "30",
        binary.to_str().expect("UTF-8 arinsal path"),
        "-noshell",
    ]);
    if let Some(limit) = busy_limit_kb {
        command.args(["+zdbbl", limit]);
    }
    let output = command
        .args([
            "-sname",
            &local_node,
            "-setcookie",
            cookie,
            "-eval",
            &format!("{expression}, halt()."),
        ])
        .process_group(0)
        .output()
        .expect("run timeout-supervised Arinsal node");
    assert!(
        output.status.success(),
        "Arinsal failed with {}: stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(stdout.contains("DIST_MIXED_OK"), "{stdout}");
    let _ = host;
    stdout
}

fn start_arinsal_server(cookie: &str, host: &str) -> (ArinsalNode, String) {
    let id = NEXT_CASE.fetch_add(1, Ordering::Relaxed);
    let node = format!("dm_s{}", unique_suffix(id));
    let local_node = format!("{node}@{host}");
    let binary = std::env::current_exe()
        .expect("current test executable")
        .parent()
        .and_then(std::path::Path::parent)
        .and_then(std::path::Path::parent)
        .expect("target directory")
        .join("release/arinsal");
    let server = "Run=fun() -> Port=open_port({fd,0,1},[eof]), true=register(mixed_receiver,self()), Alias=erlang:alias(), Loop=fun Again() -> receive {Port,eof} -> halt(0); {get_handles,Caller} -> Caller ! {handles,self(),Alias}, Again(); {pid,Caller,Msg} -> Caller ! {pid_reply,self(),Msg}, Again(); {name,Caller,Msg} -> Caller ! {name_reply,self(),Msg}, Again(); {alias,Caller,Msg} -> Caller ! {alias_reply,self(),Msg}, Again() end end, Loop() end, try Run() catch Class:Reason:Stack -> io:format(standard_error,\"DIST_SERVER_ERROR ~p:~p~n~p~n\",[Class,Reason,Stack]), erlang:raise(Class,Reason,Stack) end.";
    let mut command = Command::new("timeout");
    command.env("ARINSAL_OTP_ROOT", otp_root());
    let mut child = command
        .args([
            "--kill-after=3",
            "300",
            binary.to_str().expect("UTF-8 arinsal path"),
            "-noshell",
            "-sname",
            &local_node,
            "-setcookie",
            cookie,
            "-eval",
            server,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .process_group(0)
        .spawn()
        .expect("start timeout-supervised Arinsal server");
    let stdin = child.stdin.take().expect("Arinsal stdin pipe");
    let child = ArinsalNode {
        child,
        stdin: Some(stdin),
        node: format!("{node}@{host}"),
    };
    let remote_node = child.node.clone();
    for _ in 0..100 {
        if epmd_has_name(&node) {
            thread::sleep(Duration::from_secs(4));
            return (child, remote_node);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("Arinsal node {node} did not register with epmd");
}

fn otp_eval(cookie: &str, expression: &str) -> String {
    let id = NEXT_CASE.fetch_add(1, Ordering::Relaxed);
    let node = format!("dm_o{}", unique_suffix(id));
    let local_node = format!("{node}@localhost");
    let output = Command::new("timeout")
        .args([
            "--kill-after=3",
            "30",
            "erl",
            "-noshell",
            "-sname",
            &local_node,
            "-setcookie",
            cookie,
            "-eval",
            &format!("{expression}, halt()."),
        ])
        .process_group(0)
        .stdin(Stdio::null())
        .output()
        .expect("run timeout-supervised OTP client");
    assert!(
        output.status.success(),
        "OTP failed with {}: stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn node_literal(node: &str) -> String {
    format!("'{}'", node.replace('\'', "\\'"))
}

#[test]
fn dist_mixed_connect_ping_and_reconnect() {
    let _serial = serial_test();
    let (_erl, node, cookie, host) = start_erl();
    let n = node_literal(&node);
    arinsal_eval(
        &cookie,
        &host,
        &format!(
            "N={n}, ok=net_kernel:monitor_nodes(true, #{{connection_id=>true,node_type=>visible}}), pong=net_adm:ping(N), receive {{nodeup,N,#{{connection_id:=Cid,node_type:=visible}}}} when is_integer(Cid) -> ok after 10000 -> exit(no_nodeup) end, io:format(\"PING_OK~n\"), io:format(\"DISCONNECT ~p~n\",[erlang:disconnect_node(N)]), pong=net_adm:ping(N), receive {{nodeup,N,#{{connection_id:=ReconnectCid,node_type:=visible}}}} when is_integer(ReconnectCid) -> ok after 10000 -> exit(no_reconnect_up) end, ok=net_kernel:monitor_nodes(false, #{{connection_id=>true,node_type=>visible}}), io:format(\"DIST_MIXED_OK connect~n\")"
        ),
    );
}

#[test]
fn dist_mixed_pid_name_alias_and_rich_payload() {
    let _serial = serial_test();
    let (_erl, node, cookie, host) = start_erl();
    let n = node_literal(&node);
    arinsal_eval(
        &cookie,
        &host,
        &format!(
            "N={n}, pong=net_adm:ping(N), register(mixed_receiver,self()), Big=binary:copy(<<7>>,300000), Ref=make_ref(), Map=#{{a => [1.5,1 bsl 100,<<\"x\">>]}}, ExportFun=fun lists:reverse/1, Msg={{self(),Ref,Map,ExportFun,Big}}, Alias=erlang:alias(), {{echo,N}} ! {{self(),Msg,Alias}}, {{RemotePid,RemotePort,RemoteRef,EchoedMsg}}=receive {{pid,{{RemotePid1,EchoedMsg1,RemotePort1,RemoteRef1}}}} -> {{RemotePid1,RemotePort1,RemoteRef1,EchoedMsg1}} after 10000 -> exit(no_pid_reply) end, {{RemotePid2,RemotePort2,RemoteRef2,EchoedNameMsg}}=receive {{name,{{RemotePid3,EchoedNameMsg1,RemotePort3,RemoteRef3}}}} -> {{RemotePid3,RemotePort3,RemoteRef3,EchoedNameMsg1}} after 10000 -> exit(no_name_reply) end, {{RemotePid4,RemotePort4,RemoteRef4,EchoedAliasMsg}}=receive {{alias,{{RemotePid5,EchoedAliasMsg1,RemotePort5,RemoteRef5}}}} -> {{RemotePid5,RemotePort5,RemoteRef5,EchoedAliasMsg1}} after 10000 -> exit(no_alias_reply) end, true=(EchoedMsg=:=Msg), true=(EchoedNameMsg=:=Msg), true=(EchoedAliasMsg=:=Msg), true=is_pid(RemotePid), true=is_port(RemotePort), true=is_reference(RemoteRef), true=is_pid(RemotePid2), true=is_port(RemotePort2), true=is_reference(RemoteRef2), true=is_pid(RemotePid4), true=is_port(RemotePort4), true=is_reference(RemoteRef4), true=erlang:unalias(Alias), io:format(\"DIST_MIXED_OK payload~n\")"
        ),
    );
}

#[test]
fn dist_mixed_arinsal_fragmented_alias_send() {
    let _serial = serial_test();
    let (_erl, node, cookie, host) = start_erl();
    let n = node_literal(&node);
    arinsal_eval_with_dist_buffer(
        &cookie,
        &host,
        &format!(
            "erlang:system_monitor(self(),[{{busy_dist_port,true}}]), N={n}, pong=net_adm:ping(N), {{echo,N}} ! {{get_alias,self()}}, Alias=receive {{remote_alias,A}} -> A after 10000 -> exit(no_alias) end, Big=binary:copy(<<11>>,30000000), Alias ! {{alias_roundtrip,self(),Big}}, receive {{alias_ack,Big}} -> ok after 10000 -> exit(no_alias_reply) end, receive {{monitor,_,busy_dist_port,_}} -> ok after 10000 -> exit(no_busy_dist_port) end, io:format(\"DIST_MIXED_OK fragmented_alias~n\")"
        ),
        Some("1"),
    );
}

#[test]
fn dist_mixed_otp_node_monitor_disconnect_reconnect() {
    let _serial = serial_test();
    let id = NEXT_CASE.fetch_add(1, Ordering::Relaxed);
    let cookie = format!("dm_cookie_{}_{id:04x}", std::process::id() % 100_000);
    let host = short_hostname();
    let (_arinsal, node) = start_arinsal_server(&cookie, &host);
    let n = node_literal(&node);
    let output = otp_eval(
        &cookie,
        &format!(
            "ok=net_kernel:monitor_nodes(true, #{{connection_id=>true,node_type=>all,nodedown_reason=>true}}), pong=net_adm:ping({n}), receive {{nodeup,{n},#{{connection_id:=UpCid,node_type:=visible}}}} when is_integer(UpCid) -> ok after 10000 -> exit(no_up) end, RemotePid=erpc:call({n},erlang,spawn,[timer,sleep,[60000]]), Monitor=monitor(process,RemotePid), true=erlang:disconnect_node({n}), receive {{'DOWN',Monitor,process,RemotePid,noconnection}} -> ok after 10000 -> exit(no_process_down) end, receive {{nodedown,{n},#{{connection_id:=DownCid,node_type:=visible,nodedown_reason:=disconnect}}}} when is_integer(DownCid) -> ok after 10000 -> exit(no_down) end, pong=net_adm:ping({n}), receive {{nodeup,{n},#{{connection_id:=ReconnectCid,node_type:=visible}}}} when is_integer(ReconnectCid) -> ok after 10000 -> exit(no_reconnect_up) end, ok=net_kernel:monitor_nodes(false, #{{connection_id=>true,node_type=>all,nodedown_reason=>true}}), io:format(\"DIST_MIXED_OK otp_node_monitor~n\")"
        ),
    );
    assert!(output.contains("DIST_MIXED_OK"), "{output}");
}

#[test]
fn dist_mixed_otp_to_arinsal_pid_name_alias_and_rich_payload() {
    let _serial = serial_test();
    let id = NEXT_CASE.fetch_add(1, Ordering::Relaxed);
    let cookie = format!("dm_cookie_{}_{id:04x}", std::process::id() % 100_000);
    let host = short_hostname();
    let (_arinsal, node) = start_arinsal_server(&cookie, &host);
    let n = node_literal(&node);
    let expression = format!(
        concat!(
            "N={n}, ok=net_kernel:monitor_nodes(true, #{{connection_id=>true,node_type=>all,nodedown_reason=>true}}), pong=net_adm:ping(N), receive {{nodeup,N,#{{connection_id:=UpCid,node_type:=visible}}}} when is_integer(UpCid) -> ok after 10000 -> exit(no_nodeup) end, ",
            "[{{ok,N}}]=erpc:multicall([N],erlang,node,[]), ",
            "{{[N],[]}}=rpc:multicall([N],erlang,node,[]), ",
            "yes=global:register_name(dist_mixed_global,self()), ok=global:sync(), ",
            "WaitGlobal=fun Again(0) -> false; Again(Count) -> case rpc:call(N,global,whereis_name,[dist_mixed_global]) of P when is_pid(P) -> P; _ -> timer:sleep(50), Again(Count-1) end end, ",
            "true=is_pid(WaitGlobal(100)), ",
            "ok=erpc:cast(N,erlang,send,[self(),cast_message]), ",
            "receive cast_message -> ok after 10000 -> exit(no_cast) end, ",
            "SpawnRef=erlang:spawn_request(N,erlang,node,[]), ",
            "receive {{spawn_reply,SpawnRef,ok,SpawnPid}} when is_pid(SpawnPid) -> ok ",
            "after 10000 -> exit(no_spawn_reply) end, ",
            "{{MonitorPid,MonitorRef}}=spawn_monitor(N,erlang,exit,[mixed_exit]), ",
            "receive {{'DOWN',MonitorRef,process,MonitorPid,mixed_exit}} -> ok ",
            "after 10000 -> exit(no_down) end, ",
            "process_flag(trap_exit,true), LinkRef=erlang:spawn_request(N,erlang,exit,[linked_exit],[link]), ",
            "LinkPid=receive {{spawn_reply,LinkRef,ok,LPid}} when is_pid(LPid) -> LPid after 10000 -> exit(no_link_spawn_reply) end, ",
            "receive {{'EXIT',LinkPid,linked_exit}} -> ok after 10000 -> exit(no_link_exit) end, ",
            "{{mixed_receiver,N}} ! {{get_handles,self()}}, ",
            "{{Pid,Alias}}=receive {{handles,P,A}} -> {{P,A}} ",
            "after 10000 -> exit(no_handles) end, ",
            "Big=binary:copy(<<9>>,300000), Big=erpc:call(N,erlang,binary_part,[Big,0,300000]), Ref=make_ref(), ",
            "Map=#{{b => [3.25,1 bsl 130,<<\"mixed\">>]}}, ",
            "LocalFun=fun(Value) -> {{local,Value}} end, ",
            "Msg={{self(),Ref,Map,fun lists:reverse/1,LocalFun,Big,file:read_file_info(\"Cargo.toml\")}}, ",
            "Pid ! {{pid,self(),Msg}}, ",
            "{{pid_reply,Pid,Msg}}=receive Reply1 -> Reply1 ",
            "after 10000 -> exit(no_pid_reply) end, ",
            "{{mixed_receiver,N}} ! {{name,self(),Msg}}, ",
            "{{name_reply,Pid,Msg}}=receive Reply2 -> Reply2 ",
            "after 10000 -> exit(no_name_reply) end, ",
            "Alias ! {{alias,self(),Msg}}, ",
            "{{alias_reply,Pid,Msg}}=receive Reply3 -> Reply3 ",
            "after 10000 -> exit(no_alias_reply) end, ",
            "ok=global:unregister_name(dist_mixed_global), ",
            "io:format(\"DIST_MIXED_OK otp_to_arinsal~n\")"
        ),
        n = n
    );
    let output = otp_eval(&cookie, &expression);
    assert!(output.contains("DIST_MIXED_OK"), "{output}");
}

#[test]
fn dist_mixed_erpc_rpc_both_directions() {
    let _serial = serial_test();
    let (_erl, node, cookie, host) = start_erl();
    let n = node_literal(&node);
    arinsal_eval(
        &cookie,
        &host,
        &format!(
            "N={n}, pong=net_adm:ping(N), N=erpc:call(N,erlang,node,[]), N=rpc:call(N,erlang,node,[]), yes=global:register_name(dist_mixed_arinsal_global,self()), ok=global:sync(), true=is_pid(rpc:call(N,global,whereis_name,[dist_mixed_arinsal_global])), ok=global:unregister_name(dist_mixed_arinsal_global), io:format(\"DIST_MIXED_OK calls~n\")"
        ),
    );
}

#[test]
fn dist_mixed_spawn_and_monitor() {
    let _serial = serial_test();
    let (_erl, node, cookie, host) = start_erl();
    let n = node_literal(&node);
    arinsal_eval(
        &cookie,
        &host,
        &format!(
            "N={n}, pong=net_adm:ping(N), {{Pid,Ref}}=spawn_monitor(N,erlang,exit,[mixed_exit]), receive {{'DOWN',Ref,process,Pid,mixed_exit}} -> ok after 10000 -> exit(no_down) end, true=erlang:disconnect_node(N), ReconnectRef=erlang:spawn_request(N,erlang,exit,[reconnected_exit],[monitor]), ReconnectPid=receive {{spawn_reply,ReconnectRef,ok,RPid}} when is_pid(RPid) -> RPid after 10000 -> exit(no_reconnect_spawn_reply) end, receive {{'DOWN',ReconnectRef,process,ReconnectPid,reconnected_exit}} -> ok after 10000 -> exit(no_reconnect_spawn_down) end, process_flag(trap_exit,true), SpawnRef=erlang:spawn_request(N,erlang,exit,[linked_exit],[link,monitor]), LinkedPid=receive {{spawn_reply,SpawnRef,ok,LPid}} when is_pid(LPid) -> LPid after 10000 -> exit(no_spawn_reply) end, receive {{'EXIT',LinkedPid,linked_exit}} -> ok after 10000 -> exit(no_link_exit) end, io:format(\"DIST_MIXED_OK monitor~n\")"
        ),
    );
}

#[test]
fn dist_mixed_distributed_term_identity_and_node_monitor() {
    let _serial = serial_test();
    let (_erl, node, cookie, host) = start_erl();
    let n = node_literal(&node);
    arinsal_eval(
        &cookie,
        &host,
        &format!(
            "N={n}, pong=net_adm:ping(N), monitor_node(N,true), Ref=make_ref(), P=self(), Alias=erlang:alias(), {{echo,N}} ! {{self(),{{P,Ref,node()}},Alias}}, receive {{pid,{{Remote,{{P,Ref,LocalNode}},Port,RemoteRef}}}} when LocalNode=:=node(), node(Remote)=:=N, is_port(Port), is_reference(RemoteRef) -> true=erlang:unalias(Alias), ok after 10000 -> exit(identity_roundtrip) end, io:format(\"DIST_MIXED_OK identities~n\")"
        ),
    );
}
