//! `code:purge` + `code:delete` must not pin the module. Mix protocol
//! consolidation deletes the current beam and the next call autoloads whatever
//! is now first on the code path.

#[test]
fn deleted_module_autoloads_replacement() {
    let root = std::env::temp_dir().join(format!("mix_loop3_reload_{}", std::process::id()));
    let first = root.join("v1");
    let second = root.join("v2");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&first).unwrap();
    std::fs::create_dir_all(&second).unwrap();
    let source =
        |body: &str| format!("-module(mix_loop3_reload). -export([run/0]). run() -> {body}.\n");
    std::fs::write(first.join("mix_loop3_reload.erl"), source("1")).unwrap();
    std::fs::write(second.join("mix_loop3_reload.erl"), source("2")).unwrap();
    let otp_bin = "$HOME/.asdf/installs/erlang/29.1.1/bin";
    for dir in [&first, &second] {
        let compiled = std::process::Command::new(format!("{otp_bin}/erlc"))
            .arg("-o")
            .arg(dir)
            .arg(dir.join("mix_loop3_reload.erl"))
            .status()
            .expect("erlc");
        assert!(compiled.success(), "erlc {dir:?}");
    }
    let loader_source = first.join("native_code_load.erl");
    std::fs::write(
        &loader_source,
        "-module(native_code_load). -export([value/0]). value() -> loaded.\n",
    )
    .unwrap();
    let loader_compiled = std::process::Command::new(format!("{otp_bin}/erlc"))
        .arg("-o")
        .arg(&first)
        .arg(&loader_source)
        .status()
        .expect("erlc native_code_load");
    assert!(loader_compiled.success(), "erlc {loader_source:?}");
    let loader2_source = first.join("native_code_load2.erl");
    std::fs::write(
        &loader2_source,
        "-module(native_code_load2). -export([value/0]). value() -> loaded.\n",
    )
    .unwrap();
    let loader2_compiled = std::process::Command::new(format!("{otp_bin}/erlc"))
        .arg("-o")
        .arg(&first)
        .arg(&loader2_source)
        .status()
        .expect("erlc native_code_load2");
    assert!(loader2_compiled.success(), "erlc {loader2_source:?}");
    let expr = |out: &std::path::Path| {
        format!(
            "{{ok,LoaderBin}}=file:read_file(\"{loader}\"), {{ok,Loader2Bin}}=file:read_file(\"{loader2}\"), LoadBinary=code:load_binary(native_code_load,\"memory\",LoaderBin), LoadFile=code:is_loaded(native_code_load), LoadWhich=code:which(native_code_load), Listed=lists:keymember(native_code_load,1,code:all_loaded()), SoftEmpty=code:soft_purge(native_code_load), PurgeEmpty=code:purge(native_code_load), DeleteLoader=code:delete(native_code_load), LoadModule=erlang:load_module(native_code_load2,Loader2Bin), DeleteLoaded=code:delete(native_code_load2), code:add_pathz(\"{v1}\"), One=mix_loop3_reload:run(), Purged=code:purge(mix_loop3_reload), Deleted=code:delete(mix_loop3_reload), Gone=code:is_loaded(mix_loop3_reload), code:add_patha(\"{v2}\"), Two=mix_loop3_reload:run(), Back=code:is_loaded(mix_loop3_reload), Which=code:which(mix_loop3_reload), file:write_file(\"{out}\",io_lib:format(\"~p\",[{{LoadBinary,LoadFile,LoadWhich,Listed,SoftEmpty,PurgeEmpty,DeleteLoader,LoadModule,DeleteLoaded,One,Purged,Deleted,Gone,Two,Back,Which}}])), halt().",
            loader = first.join("native_code_load.beam").display(),
            loader2 = first.join("native_code_load2.beam").display(),
            v1 = first.display(),
            v2 = second.display(),
            out = out.display(),
        )
    };
    let expected_out = root.join("expected");
    let actual_out = root.join("actual");
    let erl = std::process::Command::new(format!("{otp_bin}/erl"))
        .args(["-noshell", "-eval", &expr(&expected_out)])
        .status()
        .expect("erl");
    assert!(erl.success(), "erl reload");
    let bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/arinsal");
    assert!(bin.is_file(), "build arinsal-cli before this test");
    let mut child = std::process::Command::new(&bin)
        .args(["-noshell", "-eval", &expr(&actual_out)])
        .spawn()
        .expect("arinsal");
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait") {
            break status;
        }
        if started.elapsed() > std::time::Duration::from_secs(40) {
            let _ = child.kill();
            panic!("arinsal reload timed out");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    assert!(status.success(), "arinsal reload status {status}");
    let actual = std::fs::read(&actual_out).expect("arinsal output");
    let expected = std::fs::read(&expected_out).expect("erl output");
    assert_eq!(
        String::from_utf8_lossy(&actual),
        String::from_utf8_lossy(&expected)
    );
    let _ = std::fs::remove_dir_all(&root);
}
