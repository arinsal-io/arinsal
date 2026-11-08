use similar_asserts::assert_eq;
use std::path::Path;
use std::process::Command;

fn run(runtime: &Path, node: &str, peer: &str) -> String {
    let eval = format!(
        "{{ok,Peer,Remote}}=peer:start_link(#{{name=>{peer},connection=>standard_io}}), Parent=self(), Ref=make_ref(), ParentPid=self(), _=spawn(Remote,fun()->Parent!{{echo,Ref,ParentPid}} end), Result=receive {{echo,Received,ReceivedPid}}->{{Ref=:=Received,Ref==Received,ParentPid=:=ReceivedPid,Ref=:=binary_to_term(term_to_binary(Ref))}} after 5000->timeout end, io:format(\"result=~p~n\",[Result]), peer:stop(Peer), halt()."
    );
    let output = Command::new("timeout")
        .args([
            "60",
            runtime.to_str().expect("runtime path"),
            "-sname",
            node,
        ])
        .args([
            "-kernel",
            "inet_dist_use_interface",
            "{127,0,0,1}",
            "-noshell",
            "-eval",
            &eval,
        ])
        .output()
        .expect("run distribution repro");
    assert!(
        output.status.success(),
        "{} exited with {:?}\nstdout: {}\nstderr: {}",
        runtime.display(),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn peer_standard_io_spawn_reply_matches_erts() {
    let suffix = std::process::id() % 100_000;
    let node = format!("a{suffix}");
    let peer = format!("b{suffix}");
    let erl = std::env::var_os("ERL")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| Path::new("erl").to_path_buf());
    let expected = run(&erl, &node, &peer);
    assert!(
        expected.contains("result={true,true,true,true}"),
        "erl: {expected}"
    );

    let arinsal = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/arinsal");
    assert!(arinsal.is_file(), "build target/debug/arinsal first");
    let actual = run(&arinsal, &node, &peer);
    assert_eq!(actual, expected);
}
