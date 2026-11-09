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
            "-kernel",
            "inet_dist_use_interface",
            "{127,0,0,1}",
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
        // The call sequence can approach 30 seconds when the host is CPU-loaded.
        "60",
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
            "-kernel",
            "inet_dist_use_interface",
            "{127,0,0,1}",
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
            "-kernel",
            "inet_dist_use_interface",
            "{127,0,0,1}",
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
            "-kernel",
            "inet_dist_use_interface",
            "{127,0,0,1}",
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
fn dist_mixed_get_dflags_matches_otp_peer() {
    let _serial = serial_test();
    let (_erl, node, cookie, host) = start_erl();
    let n = node_literal(&node);
    arinsal_eval(
        &cookie,
        &host,
        &format!(
            "N={n}, pong=net_adm:ping(N), Local=erts_internal:get_dflags(), Remote=rpc:call(N,erts_internal,get_dflags,[]), true=(Local=:=Remote), io:format(\"DIST_MIXED_OK dflags ~p~n\",[Local])"
        ),
    );
}

#[test]
fn dist_mixed_get_dflags_named_arinsal_handshake() {
    let _serial = serial_test();
    let id = NEXT_CASE.fetch_add(1, Ordering::Relaxed);
    let cookie = format!("dm_cookie_{}_{id:04x}", std::process::id() % 100_000);
    let host = short_hostname();
    let (_server, node) = start_arinsal_server(&cookie, &host);
    let n = node_literal(&node);
    arinsal_eval(
        &cookie,
        &host,
        &format!(
            "N={n}, pong=net_adm:ping(N), Local=erts_internal:get_dflags(), Remote=rpc:call(N,erts_internal,get_dflags,[]), true=(Local=:=Remote), io:format(\"DIST_MIXED_OK arinsal_dflags ~p~n\",[Local])"
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
            "{{module,timer}}=erpc:call(N,code,ensure_loaded,[timer]), ParentRef=erlang:spawn_request(N,timer,sleep,[60000]), ",
            "ParentPid=receive {{spawn_reply,ParentRef,ok,PPid}} when is_pid(PPid) -> PPid after 10000 -> exit(no_parent_spawn_reply) end, ",
            "Me=self(), {{parent,Me}}=erpc:call(N,erlang,process_info,[ParentPid,parent]), ",
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

/// A parent that exits while its remote `spawn_request(..., [link])` is pending waits for the
/// reply and sends the child its exit reason (erl_process.c:13647
/// proc_exit_handle_pend_spawn_monitors); the remote children do not leak.
#[test]
fn dist_mixed_pending_spawn_link_parent_exit_waits_for_reply() {
    let _serial = serial_test();
    let (_erl, node, cookie, host) = start_erl();
    let n = node_literal(&node);
    arinsal_eval(
        &cookie,
        &host,
        &format!(
            concat!(
                "N={n}, pong=net_adm:ping(N), {{module,timer}}=erpc:call(N,code,ensure_loaded,[timer]), ",
                "Before=erpc:call(N,erlang,system_info,[process_count]), ParentRefs=[begin {{_,R}}=spawn_opt(fun() -> erlang:spawn_request(N,timer,sleep,[60000],[link]), exit(parent_exit) end,[monitor]), R end || _ <- lists:seq(1,24)], ",
                "[receive {{'DOWN',R,process,_,parent_exit}} -> ok after 10000 -> exit(parent_exit_timeout) end || R <- ParentRefs], ",
                "Wait=fun Again(0) -> erpc:call(N,erlang,system_info,[process_count]) =< Before+3; Again(Count) -> case erpc:call(N,erlang,system_info,[process_count]) =< Before+3 of true -> true; false -> timer:sleep(50), Again(Count-1) end end, ",
                "true=Wait(200), io:format(\"DIST_MIXED_OK pending_spawn_exit~n\")"
            ),
            n = n
        ),
    );
}

/// A linked remote child of a parent that exits around the time the spawn reply arrives gets
/// the parent's actual exit reason, whether the reply was queued before the exit
/// (erl_proc_sig_queue.c:5927 handle_dist_spawn_reply_exiting) or saved after it
/// (dist.c:552 dist_pend_spawn_exit_save_child_result).
#[test]
fn dist_mixed_spawn_reply_exiting_parent_sends_real_reason() {
    let _serial = serial_test();
    let (_erl, node, cookie, host) = start_erl();
    let n = node_literal(&node);
    arinsal_eval(
        &cookie,
        &host,
        &format!(
            concat!(
                "N={n}, pong=net_adm:ping(N), Self=self(), ",
                "F=fun() -> process_flag(trap_exit,true), receive {{'EXIT',_,Why}} -> Self ! {{why,Why}} after 20000 -> Self ! {{why,timeout}} end end, ",
                "Spin=fun Spin(0) -> ok; Spin(K) -> erlang:yield(), Spin(K-1) end, ",
                "[spawn(fun() -> erlang:spawn_request(N,erlang,apply,[F,[]],[link]), case K rem 3 of 0 -> ok; 1 -> Spin(K); 2 -> receive {{spawn_reply,_,ok,_}} -> ok after 10000 -> ok end end, exit({{real_reason,K}}) end) || K <- lists:seq(1,24)], ",
                "Got=lists:sort([receive {{why,W}} -> W after 20000 -> exit(no_child_exit) end || _ <- lists:seq(1,24)]), ",
                "Expected=lists:sort([{{real_reason,K}} || K <- lists:seq(1,24)]), ",
                "case Got of Expected -> ok; _ -> exit({{wrong_reasons,Got}}) end, ",
                "io:format(\"DIST_MIXED_OK spawn_reply_exiting~n\")"
            ),
            n = n
        ),
    );
}

/// `spawn_request_abandon/1` of a pending remote request with link: the reply is dropped and
/// the child gets an `abandoned` exit (bif.c:1166, erl_proc_sig_queue.c:5786). A request to
/// a node that cannot be reached is answered `noconnection` when the pending connection is
/// aborted, unless error replies are off (erl_proc_sig_queue.c:4864).
#[test]
fn dist_mixed_spawn_request_abandon_link() {
    let _serial = serial_test();
    let (_erl, node, cookie, host) = start_erl();
    let n = node_literal(&node);
    arinsal_eval(
        &cookie,
        &host,
        &format!(
            concat!(
                "N={n}, pong=net_adm:ping(N), Self=self(), ",
                "F=fun() -> process_flag(trap_exit,true), receive {{'EXIT',_,Why}} -> Self ! {{why,Why}} after 20000 -> Self ! {{why,timeout}} end end, ",
                "R=erlang:spawn_request(N,erlang,apply,[F,[]],[link]), true=erlang:spawn_request_abandon(R), false=erlang:spawn_request_abandon(R), ",
                "receive {{why,abandoned}} -> ok after 20000 -> exit(no_abandoned_exit) end, ",
                "receive {{spawn_reply,R,_,_}}=Unexpected -> exit({{unexpected,Unexpected}}) after 200 -> ok end, ",
                "{{links,[Init]}}=process_info(self(),links), Init=whereis(init), ",
                "R2=erlang:spawn_request(N,erlang,node,[],[{{reply,no}}]), true=erlang:spawn_request_abandon(R2), ",
                "receive {{spawn_reply,R2,_,_}}=Unexpected2 -> exit({{unexpected,Unexpected2}}) after 500 -> ok end, ",
                "[_,Host]=string:split(atom_to_list(node()),\"@\"), Bad=list_to_atom(\"dm_nosuch@\" ++ Host), ",
                "R4=erlang:spawn_request(Bad,erlang,node,[]), receive {{spawn_reply,R4,error,noconnection}} -> ok after 20000 -> exit(no_noconnection) end, ",
                "R5=erlang:spawn_request(Bad,erlang,node,[],[{{reply,success_only}}]), receive {{spawn_reply,R5,_,_}}=Unexpected5 -> exit({{unexpected,Unexpected5}}) after 3000 -> ok end, ",
                "io:format(\"DIST_MIXED_OK spawn_request_abandon~n\")"
            ),
            n = n
        ),
    );
}

#[test]
fn dist_mixed_remote_tagged_monitor_down() {
    let _serial = serial_test();
    let (_erl, node, cookie, host) = start_erl();
    let n = node_literal(&node);
    arinsal_eval(
        &cookie,
        &host,
        &format!(
            "N={n}, pong=net_adm:ping(N), RemotePid=rpc:call(N,erlang,spawn,[timer,sleep,[60000]]), Tag={{tagged,make_ref()}}, Ref=monitor(process,RemotePid,[{{tag,Tag}}]), rpc:call(N,erlang,exit,[RemotePid,tagged_done]), receive {{Tag,Ref,process,RemotePid,tagged_done}} -> io:format(\"DIST_MIXED_OK tagged_monitor~n\") after 10000 -> exit(no_tagged_down) end"
        ),
    );
}

#[test]
fn dist_mixed_remote_tagged_monitor_connection_down() {
    let _serial = serial_test();
    let (_erl, node, cookie, host) = start_erl();
    let n = node_literal(&node);
    arinsal_eval(
        &cookie,
        &host,
        &format!(
            "N={n}, pong=net_adm:ping(N), RemotePid=rpc:call(N,erlang,spawn,[timer,sleep,[60000]]), Tag={{node_down,make_ref()}}, Ref=monitor(process,RemotePid,[{{tag,Tag}}]), true=erlang:disconnect_node(N), receive {{Tag,Ref,process,RemotePid,noconnection}} -> io:format(\"DIST_MIXED_OK tagged_noconnection~n\") after 10000 -> exit(no_tagged_noconnection) end"
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

/// Links made by a remote process to processes on the tested node, and by those processes to
/// the remote one: remote exits with trap_exit on and off, `{'EXIT', Pid, _}` carrying the very
/// pid the remote sent, local exits reaching the remote end, `process_info(links)` listing the
/// external pid, and unlink from both sides. Run from an OTP client against an OTP node and
/// against an Arinsal node; the results must be equal.
const ELINK_CLIENT: &str = concat!(
    "Me=self(), ",
    "Srv=fun(Trap) -> spawn(N,fun() -> process_flag(trap_exit,Trap), Me ! {ready,self()}, (fun L() -> receive {do,F} -> F(), L(); M -> Me ! {got,self(),M}, L() end end)() end) end, ",
    "Ready=fun(S) -> receive {ready,S} -> ok after 10000 -> exit(no_ready) end end, ",
    "Links=fun(S) -> {links,L} = erpc:call(N,erlang,process_info,[S,links]), L end, ",
    "Quiet=fun(S) -> receive {got,S,M} -> {unexpected,M} after 500 -> quiet end end, ",
    "SA=Srv(true), Ready(SA), ",
    "CA=spawn(fun() -> link(SA), Me ! {linked,self()}, receive go -> exit(r1) end end), ",
    "receive {linked,CA} -> ok end, timer:sleep(300), LA=Links(SA), CA ! go, ",
    "A=receive {got,SA,{'EXIT',PA,RA}} -> {LA=:=[CA],PA=:=CA,node(PA)=:=node(),RA} after 10000 -> no_exit end, ",
    "SB=Srv(false), Ready(SB), MB=monitor(process,SB), ",
    "CB=spawn(fun() -> link(SB), Me ! {linked,self()}, receive go -> exit(r2) end end), ",
    "receive {linked,CB} -> ok end, timer:sleep(300), CB ! go, ",
    "B=receive {'DOWN',MB,process,SB,RB} -> RB after 10000 -> no_down end, ",
    "SC=Srv(true), Ready(SC), ",
    "CC=spawn(fun() -> process_flag(trap_exit,true), link(SC), Me ! {linked,self()}, receive {'EXIT',P,R} -> Me ! {c_exit,P=:=SC,R} end end), ",
    "receive {linked,CC} -> ok end, timer:sleep(300), SC ! {do,fun() -> exit(r3) end}, ",
    "C=receive {c_exit,PC,RC} -> {PC,RC} after 10000 -> no_exit end, ",
    "SD=Srv(true), Ready(SD), ",
    "CD=spawn(fun() -> link(SD), Me ! {linked,self()}, receive unlink -> true=unlink(SD), Me ! unlinked end, receive go -> exit(r4) end end), ",
    "receive {linked,CD} -> ok end, timer:sleep(300), LD1=Links(SD), CD ! unlink, receive unlinked -> ok end, timer:sleep(300), LD2=Links(SD), CD ! go, ",
    "D={LD1=:=[CD],LD2,Quiet(SD)}, ",
    "SE=Srv(true), Ready(SE), ",
    "CE=spawn(fun() -> process_flag(trap_exit,true), link(SE), Me ! {linked,self()}, receive M -> Me ! {e_got,M} end end), ",
    "receive {linked,CE} -> ok end, timer:sleep(300), SE ! {do,fun() -> true=unlink(CE) end}, timer:sleep(300), ",
    "{links,LE} = process_info(CE,links), LE2=Links(SE), SE ! {do,fun() -> exit(r5) end}, ",
    "E={LE,LE2,receive {e_got,ME} -> {unexpected,ME} after 500 -> quiet end}, ",
    "SF=Srv(true), Ready(SF), ",
    "CF=spawn(fun() -> process_flag(trap_exit,true), Me ! {ready_f,self()}, receive go -> exit(r6) end end), ",
    "receive {ready_f,CF} -> ok end, SF ! {do,fun() -> true=link(CF) end}, timer:sleep(300), ",
    "{links,LF} = process_info(CF,links), LF2=Links(SF), CF ! go, ",
    "F=receive {got,SF,{'EXIT',PF,RF}} -> {LF=:=[SF],LF2=:=[CF],PF=:=CF,RF} after 10000 -> no_exit end, ",
    "SG=Srv(true), Ready(SG), ",
    "CG=spawn(fun() -> receive stop -> ok end end), ",
    "SG ! {do,fun() -> true=link(CG), true=unlink(CG) end}, timer:sleep(300), ",
    "{links,LG} = process_info(CG,links), LG2=Links(SG), exit(CG,kill), ",
    "G={LG,LG2,Quiet(SG)}, ",
    "[exit(S,kill) || S <- [SA,SC,SD,SE,SF,SG]], ",
    "io:format(\"ELINK_RESULT ~p~n\",[[A,B,C,D,E,F,G]]), ",
    "io:format(\"DIST_MIXED_OK elink~n\")"
);

fn elink_result(output: &str) -> String {
    output
        .lines()
        .find(|line| line.starts_with("ELINK_RESULT"))
        .unwrap_or_else(|| panic!("no ELINK_RESULT in {output}"))
        .to_owned()
}

#[test]
fn dist_mixed_external_links_match_otp() {
    let _serial = serial_test();
    let expected = {
        let (_erl, node, cookie, _host) = start_erl();
        let n = node_literal(&node);
        let output = otp_eval(
            &cookie,
            &format!("N={n}, pong=net_adm:ping(N), {ELINK_CLIENT}"),
        );
        assert!(output.contains("DIST_MIXED_OK"), "{output}");
        elink_result(&output)
    };
    let id = NEXT_CASE.fetch_add(1, Ordering::Relaxed);
    let cookie = format!("dm_cookie_{}_{id:04x}", std::process::id() % 100_000);
    let host = short_hostname();
    let (_arinsal, node) = start_arinsal_server(&cookie, &host);
    let n = node_literal(&node);
    let output = otp_eval(
        &cookie,
        &format!("N={n}, pong=net_adm:ping(N), {ELINK_CLIENT}"),
    );
    assert!(output.contains("DIST_MIXED_OK"), "{output}");
    assert_eq!(elink_result(&output), expected);
}

/// The Arinsal release binary next to this test's target directory.
fn arinsal_binary() -> std::path::PathBuf {
    std::env::current_exe()
        .expect("current test executable")
        .parent()
        .and_then(std::path::Path::parent)
        .and_then(std::path::Path::parent)
        .expect("target directory")
        .join("release/arinsal")
}

/// Run `expression` once on `erl` (`arinsal == false`) or on Arinsal, not distributed or as a
/// short-named loopback node, and return the line starting with `marker`.
fn local_eval(arinsal: bool, distributed: bool, expression: &str, marker: &str) -> String {
    let id = NEXT_CASE.fetch_add(1, Ordering::Relaxed);
    let mut command = Command::new("timeout");
    command.args(["--kill-after=3", "60"]);
    if arinsal {
        command.env("ARINSAL_OTP_ROOT", otp_root());
        command.arg(arinsal_binary());
    } else {
        command.arg("erl");
    }
    command.arg("-noshell");
    if distributed {
        let node = format!("dm_l{}@localhost", unique_suffix(id));
        command.args([
            "-sname",
            &node,
            "-kernel",
            "inet_dist_use_interface",
            "{127,0,0,1}",
        ]);
    }
    let output = command
        .args(["-eval", &format!("{expression}, halt().")])
        .process_group(0)
        .stdin(Stdio::null())
        .output()
        .expect("run timeout-supervised node");
    let stdout = String::from_utf8_lossy(&output.stdout).replace('\n', " ");
    let stdout = stdout.split_whitespace().collect::<Vec<_>>().join(" ");
    match stdout.find(marker) {
        Some(start) => stdout[start..].to_owned(),
        None => panic!(
            "no {marker} (arinsal={arinsal}, distributed={distributed}): status={} stdout={stdout} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ),
    }
}

/// link/1, monitor/2, send and spawn_request towards a node that cannot be reached: the
/// node is not alive, it is alive but the node does not exist, or `net_kernel` is gone so the
/// auto-connect fails (bif.c link_opt and monitor on ERTS_DSIG_PREP_NOT_ALIVE /
/// ERTS_DSIG_PREP_NOT_CONNECTED, remote_send, erts_internal_dist_spawn_request_4).
const NOCONN_CLIENT: &str = r#"process_flag(trap_exit,true), Far=list_to_atom("dm_absent_"++integer_to_list(erlang:unique_integer([positive]))++"@localhost"), FarB=atom_to_binary(Far), FarL=byte_size(FarB), Ext=binary_to_term(<<131,88,100,FarL:16,FarB/binary,7:32,0:32,1:32>>), Has=fun() -> {links,Ls}=process_info(self(),links), lists:member(Ext,Ls) end, L1=link(Ext), E1=receive {'EXIT',Ext,R1} -> R1 after 3000 -> timeout end, H1=Has(), L2=link(Ext), E2=receive {'EXIT',Ext,R2} -> R2 after 3000 -> timeout end, {NT,NTM}=spawn_monitor(fun() -> link(Ext), receive after 3000 -> survived end end), NTR=receive {'DOWN',NTM,process,NT,R3} -> R3 after 5000 -> timeout end, M1=monitor(process,Ext), D1=receive {'DOWN',M1,process,O1,R4} -> {O1=:=Ext,R4} after 3000 -> timeout end, D2=try monitor(process,{x,Far}) of M2 -> receive {'DOWN',M2,process,O2,R5} -> {O2=:={x,Far},R5} after 3000 -> timeout end catch error:Er -> {error,Er} end, M3=monitor(process,Ext), DI=demonitor(M3,[info]), DQ=receive {'DOWN',M3,_,_,_} -> got_down after 300 -> quiet end, DIQ=(DI andalso DQ=:=quiet) orelse (not DI andalso DQ=:=got_down), M4=monitor(process,Ext), receive {'DOWN',M4,_,_,_} -> ok after 3000 -> ok end, DF=demonitor(M4,[info]), DF2=demonitor(M4), M5=monitor(process,Ext,[{tag,mytag}]), D5=receive {mytag,M5,process,_,R6} -> R6 after 3000 -> timeout end, S1=(Ext ! hi), S2=erlang:send({x,Far},hi), S3=erlang:send(Ext,hi,[noconnect]), S4=erlang:send({x,Far},hi,[noconnect]), SR1=erlang:spawn_request(Far,erlang,self,[],[]), SP1=receive {spawn_reply,SR1,A1,B1} -> {A1,B1} after 5000 -> timeout end, SR2=erlang:spawn_request(Far,erlang,self,[],[{reply_tag,tg},monitor,link]), SP2=receive {tg,SR2,A2,B2} -> {A2,B2} after 5000 -> timeout end, U=unlink(Ext), Mons=process_info(self(),monitors), Q=receive Any -> {unexpected,Any} after 300 -> quiet end, io:format("NOCONN_RESULT ~p~n",[[node()=/=nonode@nohost,L1,E1,H1,L2,E2,NTR,D1,D2,DIQ,DF,DF2,D5,S1,S2,S3,S4,SP1,SP2,U,Mons,Q]])"#;

#[test]
fn dist_mixed_unavailable_node_links_monitors_match_otp() {
    let _serial = serial_test();
    let without_net_kernel = format!("true=unregister(net_kernel), {NOCONN_CLIENT}");
    for (distributed, expression) in [
        (false, NOCONN_CLIENT),
        (true, NOCONN_CLIENT),
        (true, without_net_kernel.as_str()),
    ] {
        let expected = local_eval(false, distributed, expression, "NOCONN_RESULT");
        let actual = local_eval(true, distributed, expression, "NOCONN_RESULT");
        assert_eq!(
            actual, expected,
            "distributed={distributed} expression={expression}"
        );
    }
}

/// Monitors of remote processes by pid and by `{Name, Node}`, demonitor seen from the
/// monitored side (`monitored_by`), DOWN `noconnection` for both kinds when the connection
/// goes down, the monitored side forgetting the monitors of a lost connection, and a link
/// re-made after an unlink while the connection went down. Run from the tested node against
/// an OTP node and from an OTP node against the tested node.
const EMON_CLIENT: &str = r#"process_flag(trap_exit,true), Me=self(), Srv=fun() -> spawn(N, fun() -> process_flag(trap_exit,true), (fun L() -> receive stop -> ok; _ -> L() end end)() end) end, MB=fun(P) -> {monitored_by,L}=erpc:call(N,erlang,process_info,[P,monitored_by]), L end, P1=Srv(), P2=Srv(), P3=Srv(), true=erpc:call(N,erlang,register,[dm_named,P2]), M1=monitor(process,P1), M2=monitor(process,{dm_named,N}), M5=monitor(process,P1), timer:sleep(300), B1=MB(P1), B2=MB(P2), true=demonitor(M5), timer:sleep(300), B3=MB(P1), A={lists:sort(B1)=:=[Me,Me], B2=:=[Me], B3=:=[Me]}, true=link(P3), timer:sleep(300), true=unlink(P3), true=erlang:disconnect_node(N), true=link(P3), D1=receive {'DOWN',M1,process,O1,R1} -> {O1=:=P1,R1} after 5000 -> timeout end, D2=receive {'DOWN',M2,process,O2,R2} -> {O2=:={dm_named,N},R2} after 5000 -> timeout end, Q5=receive {'DOWN',M5,_,_,_} -> got after 300 -> quiet end, timer:sleep(500), L3=receive {'EXIT',P3,R3} -> {early_exit,R3} after 0 -> none end, Linked=lists:member(P3, element(2,process_info(self(),links))), B4=MB(P1), B5=MB(P2), erpc:call(N,erlang,exit,[P3,kill]), L4=receive {'EXIT',P3,R4} -> R4 after 2000 -> timeout end, M6=monitor(process,P1), erpc:call(N,erlang,exit,[P1,kill]), D6=receive {'DOWN',M6,process,_,R6} -> R6 after 5000 -> timeout end, P2 ! stop, Mons=process_info(self(),monitors), io:format("EMON_RESULT ~p~n",[[A,D1,D2,Q5,L3,Linked,B4,B5,L4,D6,Mons]]), io:format("DIST_MIXED_OK emon~n")"#;

/// `link/1` while the old external link is still unlinking on a connection that went down:
/// the remote end is suspended, so its unlink ack never comes (bif.c link_opt `replace`).
const ELINK_REPLACE_CLIENT: &str = r#"process_flag(trap_exit,true), Me=self(), P3=spawn(N, fun() -> process_flag(trap_exit,true), receive stop -> ok end end), true=link(P3), timer:sleep(300), Sus=spawn(N, fun() -> true=erlang:suspend_process(P3), Me ! suspended, receive resume -> true=erlang:resume_process(P3) end, receive stop -> ok end end), receive suspended -> ok end, true=unlink(P3), spawn(fun() -> erlang:disconnect_node(N), Me ! dc end), Spin=fun S(0) -> gave_up; S(K) -> case nodes() of [] -> down; _ -> S(K-1) end end, Down=Spin(100000000), true=link(P3), receive dc -> ok end, timer:sleep(500), L3=receive {'EXIT',P3,R3} -> {early_exit,R3} after 0 -> none end, Linked=lists:member(P3, element(2,process_info(self(),links))), pong=net_adm:ping(N), Sus ! resume, timer:sleep(300), erpc:call(N,erlang,exit,[P3,kill]), L4=receive {'EXIT',P3,R4} -> R4 after 2000 -> timeout end, Sus ! stop, io:format("REP_RESULT ~p~n",[[Down,L3,Linked,L4]])"#;

fn emon_run(client_arinsal: bool, server_arinsal: bool, expression: &str, marker: &str) -> String {
    let id = NEXT_CASE.fetch_add(1, Ordering::Relaxed);
    let host = short_hostname();
    let (output, _server) = if server_arinsal {
        let cookie = format!("dm_cookie_{}_{id:04x}", std::process::id() % 100_000);
        let (server, node) = start_arinsal_server(&cookie, &host);
        let n = node_literal(&node);
        let output = otp_eval(
            &cookie,
            &format!("N={n}, pong=net_adm:ping(N), {expression}"),
        );
        (output, Some(server))
    } else {
        let (erl, node, cookie, host) = start_erl();
        let n = node_literal(&node);
        let full = format!("N={n}, pong=net_adm:ping(N), {expression}");
        let output = if client_arinsal {
            arinsal_eval(&cookie, &host, &full)
        } else {
            otp_eval(&cookie, &full)
        };
        drop(erl);
        (output, None)
    };
    let flat = output.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(flat.contains("DIST_MIXED_OK"), "{flat}");
    let start = flat
        .find(marker)
        .unwrap_or_else(|| panic!("no {marker} in {flat}"));
    let line = &flat[start..];
    line[..line.find(" DIST_MIXED_OK").unwrap_or(line.len())].to_owned()
}

#[test]
fn dist_mixed_external_monitors_connection_down_match_otp() {
    let _serial = serial_test();
    let expected = emon_run(false, false, EMON_CLIENT, "EMON_RESULT");
    assert_eq!(emon_run(true, false, EMON_CLIENT, "EMON_RESULT"), expected);
    let replace = format!("{ELINK_REPLACE_CLIENT}, io:format(\"DIST_MIXED_OK replace~n\")");
    let expected = emon_run(false, false, &replace, "REP_RESULT");
    assert_eq!(emon_run(true, false, &replace, "REP_RESULT"), expected);
}

/// The monitored side of [`EMON_CLIENT`] on the tested node: incoming DOP_MONITOR_P /
/// DOP_DEMONITOR_P and the target halves dropped with a lost connection.
#[test]
fn dist_mixed_external_monitors_monitored_side_match_otp() {
    let _serial = serial_test();
    let expected = emon_run(false, false, EMON_CLIENT, "EMON_RESULT");
    assert_eq!(emon_run(false, true, EMON_CLIENT, "EMON_RESULT"), expected);
}

/// Signal BIFs with an external pid called from `-eval` reach the BIF through `erl_eval`'s
/// `apply/3`; erts has one `exit_2`/`link_1`/`unlink_1`/`demonitor_2` for every caller (bif.c),
/// so each must route to the distribution as a static call does. The expected values are what
/// erl 29.1.1 returns for the same expression.
#[test]
fn dist_mixed_eval_signal_bifs_to_remote_pid() {
    let _serial = serial_test();
    let (_erl, node, cookie, host) = start_erl();
    let n = node_literal(&node);
    let expression = format!(
        concat!(
            "N={n}, pong=net_adm:ping(N), Spawn=fun() -> rpc:call(N,erlang,spawn,[timer,sleep,[60000]]) end, ",
            "P1=Spawn(), R1=monitor(process,P1), true=exit(P1,eval_kill), ",
            "receive {{'DOWN',R1,process,P1,eval_kill}} -> ok after 10000 -> exit(no_exit2_down) end, ",
            "P2=Spawn(), R2=monitor(process,P2), true=apply(erlang,exit,[P2,applied_kill]), ",
            "receive {{'DOWN',R2,process,P2,applied_kill}} -> ok after 10000 -> exit(no_apply_exit2_down) end, ",
            "P3=Spawn(), R3=monitor(process,P3), true=exit(P3,normal), ",
            "receive {{'DOWN',R3,process,P3,_}}=D3 -> exit({{normal_killed,D3}}) after 300 -> ok end, ",
            "process_flag(trap_exit,true), true=link(P3), true=unlink(P3), true=exit(P3,kill), ",
            "receive {{'DOWN',R3,process,P3,killed}} -> ok after 10000 -> exit(no_kill_down) end, ",
            "receive {{'EXIT',P3,_}}=E3 -> exit({{unlinked_exit,E3}}) after 300 -> ok end, ",
            "P4=Spawn(), true=link(P4), true=exit(P4,linked_kill), ",
            "receive {{'EXIT',P4,linked_kill}} -> ok after 10000 -> exit(no_link_exit) end, ",
            "P5=Spawn(), R5=monitor(process,P5), true=demonitor(R5,[flush]), true=exit(P5,kill), ",
            "receive {{'DOWN',R5,_,_,_}}=D5 -> exit({{demonitored_down,D5}}) after 300 -> ok end, ",
            "P6=Spawn(), R6=monitor(process,P6), true=exit(P6,queued), ",
            "Wait=fun W() -> {{messages,Ms}}=process_info(self(),messages), case lists:keymember(R6,2,Ms) of true -> ok; false -> timer:sleep(10), W() end end, ",
            "ok=Wait(), false=demonitor(R6,[flush,info]), {{messages,[]}}=process_info(self(),messages), ",
            "io:format(\"DIST_MIXED_OK eval_signal_bifs~n\")"
        ),
        n = n
    );
    // The reference: the same expression on an erl client node.
    let reference = otp_eval(&cookie, &expression);
    assert!(
        reference.contains("DIST_MIXED_OK eval_signal_bifs"),
        "{reference}"
    );
    arinsal_eval(&cookie, &host, &expression);
}

/// The origin side of monitors of remote processes: by pid and by `{Name, Node}` with the
/// remote exit (`DOP_MONITOR_P_EXIT`), `process_info(monitors)`, demonitor, a name that does
/// not exist (`noproc`), the watcher's exit demonitoring (`monitored_by` on the remote side),
/// `spawn_request` with `monitor` (DOWN of the child, and of a child that is still running
/// when the connection goes down) and DOWN `noconnection` on connection loss.
const ORIGIN_CLIENT: &str = r#"Me=self(), Srv=fun() -> spawn(N, fun() -> (fun L() -> receive stop -> ok; {exit,R} -> exit(R); _ -> L() end end)() end) end, MB=fun(P) -> {monitored_by,L}=erpc:call(N,erlang,process_info,[P,monitored_by]), L end, P1=Srv(), P2=Srv(), true=erpc:call(N,erlang,register,[dm_o,P2]), M1=monitor(process,P1), M2=monitor(process,{dm_o,N}), Mons=process_info(self(),monitors), MI=(lists:sort(element(2,Mons))=:=lists:sort([{process,P1},{process,{dm_o,N}}])), P1 ! {exit,boom}, D1=receive {'DOWN',M1,process,O1,R1} -> {O1=:=P1,R1} after 5000 -> timeout end, P2 ! {exit,{shape,[1,2]}}, D2=receive {'DOWN',M2,process,O2,R2} -> {O2=:={dm_o,N},R2} after 5000 -> timeout end, P3=Srv(), M3=monitor(process,P3), timer:sleep(200), B3a=MB(P3), true=demonitor(M3), timer:sleep(200), B3=MB(P3), P3 ! {exit,x}, Q3=receive {'DOWN',M3,_,_,_} -> got after 300 -> quiet end, M4=monitor(process,{dm_absent,N}), D4=receive {'DOWN',M4,process,O4,R4} -> {O4=:={dm_absent,N},R4} after 5000 -> timeout end, P5=Srv(), W=spawn(fun() -> monitor(process,P5), Me ! ready, receive stop -> ok end end), receive ready -> ok end, timer:sleep(200), B5a=MB(P5), W ! stop, timer:sleep(300), B5b=MB(P5), R6=erlang:spawn_request(N,erlang,exit,[sr_done],[monitor]), S6=receive {spawn_reply,R6,ok,C6} -> receive {'DOWN',R6,process,O6,RR6} -> {O6=:=C6,RR6} after 5000 -> no_down end after 5000 -> timeout end, R7=erlang:spawn_request(N,erlang,apply,[fun() -> receive stop -> ok end end,[]],[monitor]), C7=receive {spawn_reply,R7,ok,C} -> C after 5000 -> timeout end, timer:sleep(200), MI7={lists:member({process,C7},element(2,process_info(self(),monitors))), MB(C7)=:=[Me]}, P8=Srv(), M8=monitor(process,P8), true=erlang:disconnect_node(N), D7=receive {'DOWN',R7,process,O7,RR7} -> {O7=:=C7,RR7} after 5000 -> timeout end, D8=receive {'DOWN',M8,process,O8,R8} -> {O8=:=P8,R8} after 5000 -> timeout end, MonsEnd=process_info(self(),monitors), Q=receive Any -> {unexpected,Any} after 300 -> quiet end, io:format("ORIGIN_RESULT ~p~n",[[MI,D1,D2,B3a=:=[Me],B3,Q3,D4,B5a=:=[W],B5b,S6,MI7,D7,D8,MonsEnd,Q]]), io:format("DIST_MIXED_OK origin~n")"#;

/// [`ORIGIN_CLIENT`] from the tested node against an OTP node, and from an OTP node against
/// the tested node (the monitored side and the child of a monitored `spawn_request`).
#[test]
fn dist_mixed_external_monitors_origin_side_match_otp() {
    let _serial = serial_test();
    let expected = emon_run(false, false, ORIGIN_CLIENT, "ORIGIN_RESULT");
    assert_eq!(
        emon_run(true, false, ORIGIN_CLIENT, "ORIGIN_RESULT"),
        expected
    );
    assert_eq!(
        emon_run(false, true, ORIGIN_CLIENT, "ORIGIN_RESULT"),
        expected
    );
}
