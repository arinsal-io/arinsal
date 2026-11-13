//! `net_kernel:start/stop/start` returns the node to `nonode@nohost` as erts does
//! (dist.c setnode_2, set_node_not_alive). The same script runs on `erl` and on Arinsal and the
//! outputs must be equal.
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn otp_root() -> std::ffi::OsString {
    std::env::var_os("ARINSAL_OTP_ROOT").unwrap_or_else(|| {
        let output = Command::new("erl")
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

fn run(binary: &std::path::Path, expression: &str) -> String {
    let output = Command::new("timeout")
        .env("ARINSAL_OTP_ROOT", otp_root())
        .args(["--kill-after=3", "120"])
        .arg(binary)
        .args([
            "-noshell",
            "-kernel",
            "inet_dist_use_interface",
            "{127,0,0,1}",
            "-eval",
            expression,
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .expect("run node");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn arinsal_binary() -> std::path::PathBuf {
    std::env::current_exe()
        .expect("current test executable")
        .parent()
        .and_then(std::path::Path::parent)
        .and_then(std::path::Path::parent)
        .expect("target directory")
        .join("release/arinsal")
}

fn script(tag: &str) -> String {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let (a, b) = (format!("rs_{tag}_a{unique}"), format!("rs_{tag}_b{unique}"));
    format!(
        "P=fun(T) -> io:format(\"~p~n\",[T]) end, \
         P({{start,node(),nodes(),erlang:is_alive()}}), \
         ok=net_kernel:monitor_nodes(true,#{{connection_id=>true,node_type=>all,nodedown_reason=>true}}), \
         {{ok,_}}=net_kernel:start([{a},shortnames]), \
         receive {{nodeup,N1,I1}} -> P({{up,N1=:=node(),I1}}) after 5000 -> P(no_nodeup) end, \
         P({{up,hd(string:split(atom_to_list(node()),\"@\")) =:= \"{a}\",nodes(),erlang:is_alive()}}), \
         C1=erlang:system_info(creation), P({{creation_ok,C1>=4}}), \
         {{error,_}}=net_kernel:start([{b},shortnames]), \
         ok=net_kernel:stop(), \
         receive {{nodedown,_,I2}} -> P({{down,I2}}) after 5000 -> P(no_nodedown) end, \
         timer:sleep(300), \
         P({{stopped,node(),nodes(),erlang:is_alive(),erlang:system_info(creation)}}), \
         {{ok,_}}=net_kernel:start([{b},shortnames]), \
         receive {{nodeup,_,I3}} -> P({{up_again,I3}}) after 5000 -> P(no_nodeup2) end, \
         P({{again,erlang:is_alive(),erlang:system_info(creation)>=4}}), \
         ok=net_kernel:stop(), timer:sleep(300), P({{end_state,node(),erlang:is_alive()}}), halt()."
    )
}

#[test]
fn net_kernel_start_stop_start_matches_erl() {
    let erl = Command::new("erl")
        .arg("-noshell")
        .args(["-eval", "halt()."])
        .status();
    if erl.is_err() {
        eprintln!("skipped: erl is not on PATH");
        return;
    }
    let binary = arinsal_binary();
    assert!(
        binary.exists(),
        "build the release binary first: cargo build --release -p arinsal-cli"
    );
    let expected = run(std::path::Path::new("erl"), &script("e"));
    let actual = run(&binary, &script("a"));
    assert!(expected.contains("end_state"), "erl output: {expected}");
    assert_eq!(
        normalize(&actual),
        normalize(&expected),
        "arinsal: {actual}"
    );
}

fn normalize(text: &str) -> String {
    text.lines().collect::<Vec<_>>().join("\n")
}
