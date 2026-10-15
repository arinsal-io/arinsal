//! Inet driver state belongs to a port's runtime-local driver data.

use arinsal_difftest::RefErl;
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

fn source(gate_port: u16) -> String {
    let template = r#"
-module(inet_driver_vm_isolation).
-export([run/0]).

run() ->
    catch ets:new(ac_tab, [named_table, public, set]),
    TcpOpts = [{tcp_module, inet_tcp}, {ip, {127,0,0,1}}, binary, {active, false}],
    UdpOpts = [inet, {ip, {127,0,0,1}}, binary, {active, false}],
    GateOpts = [{tcp_module, inet_tcp}, {ip, {127,0,0,1}}, binary, {active, false}],
    {ok, Listen} = gen_tcp:listen(0, TcpOpts),
    {ok, Udp} = gen_udp:open(0, UdpOpts),
    {ok, Gate} = gen_tcp:connect({127,0,0,1}, GATE_PORT, GateOpts, 5000),
    ok = gen_tcp:send(Gate, <<"R">>),
    {ok, <<"G">>} = gen_tcp:recv(Gate, 1, 5000),
    ok = gen_tcp:close(Gate),
    {ok, TcpPort} = inet:port(Listen),
    {ok, UdpPort} = inet:port(Udp),
    {ok, Client} = gen_tcp:connect({127,0,0,1}, TcpPort, TcpOpts, 5000),
    {ok, Accepted} = gen_tcp:accept(Listen, 5000),
    ok = gen_tcp:send(Client, <<"tcp!">>),
    {ok, <<"tcp!">>} = gen_tcp:recv(Accepted, 4, 5000),
    ok = gen_tcp:send(Accepted, <<"pong">>),
    {ok, <<"pong">>} = gen_tcp:recv(Client, 4, 5000),
    ok = gen_udp:send(Udp, {127,0,0,1}, UdpPort, <<"udp!">>),
    {ok, {{127,0,0,1}, UdpPort, <<"udp!">>}} = gen_udp:recv(Udp, 4, 5000),
    ok = gen_tcp:close(Client),
    ok = gen_tcp:close(Accepted),
    ok = gen_tcp:close(Listen),
    ok = gen_udp:close(Udp),
    {ok, {Listen, Udp}}.
"#;
    template.replace("GATE_PORT", &gate_port.to_string())
}

fn port_ids(result: OwnedTerm) -> (u64, u64) {
    let OwnedTerm::Tuple(outer) = &result else {
        panic!("expected result tuple, got {result:?}");
    };
    assert!(matches!(outer.as_slice(), [OwnedTerm::Atom(ok), _] if ok == "ok"));
    let OwnedTerm::Tuple(ports) = &outer[1] else {
        panic!("expected socket tuple, got {:?}", outer[1]);
    };
    let [
        OwnedTerm::Port { id: tcp_id, .. },
        OwnedTerm::Port { id: udp_id, .. },
    ] = ports.as_slice()
    else {
        panic!("expected TCP and UDP ports, got {ports:?}");
    };
    (*tcp_id, *udp_id)
}

fn run_vm(beam: Vec<u8>) -> OwnedTerm {
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load isolation module");
    vm.eval_scheduled("inet_driver_vm_isolation", "run", &[], 2, None)
        .expect("run isolated TCP and UDP sockets")
        .term
}

#[test]
fn tcp_and_udp_ports_with_colliding_ids_are_isolated_between_vms() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping inet driver isolation test");
        return;
    };
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind gate on loopback");
    listener
        .set_nonblocking(true)
        .expect("set gate listener nonblocking");
    let gate_port = listener.local_addr().expect("gate address").port();
    let beam = reference
        .compile_named("inet_driver_vm_isolation", &source(gate_port), &[])
        .expect("compile inet driver isolation module");
    drop(reference);

    let gate = thread::spawn(move || -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut clients: Vec<TcpStream> = Vec::with_capacity(2);
        while clients.len() < 2 {
            match listener.accept() {
                Ok((mut client, _)) => {
                    let mut ready = [0; 1];
                    client
                        .read_exact(&mut ready)
                        .map_err(|error| format!("read gate readiness: {error}"))?;
                    if ready != *b"R" {
                        return Err("unexpected gate readiness byte".into());
                    }
                    clients.push(client);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err("both runtimes did not reach the gate".into());
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(format!("accept gate connection: {error}")),
            }
        }
        for client in &mut clients {
            client
                .write_all(b"G")
                .map_err(|error| format!("release gate connection: {error}"))?;
        }
        Ok(())
    });
    let beam_a = beam.clone();
    let a = thread::spawn(move || run_vm(beam_a));
    let b = thread::spawn(move || run_vm(beam));
    let result_a = a.join().expect("runtime A thread");
    let result_b = b.join().expect("runtime B thread");
    gate.join()
        .expect("gate thread")
        .expect("synchronize runtimes");

    let ids_a = port_ids(result_a);
    let ids_b = port_ids(result_b);
    similar_asserts::assert_eq!(ids_a, ids_b, "both runtimes allocated colliding port ids");
}
