use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::Term;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(proc_bifs).
-export([scenario/1]).
scenario(0) -> K={key,1}, undefined=put(K,42), {K,42}=lists:last(get()), 42=get(K), 42=erase(K), undefined = get(K), ok;
scenario(1) -> false=process_flag(trap_exit,true), true=process_flag(trap_exit,false), ok;
scenario(2) -> true=erlang:yield(), ok;
scenario(3) -> true=garbage_collect(), ok;
scenario(4) -> Leader=group_leader(), {group_leader,Leader}=process_info(self(),group_leader), ok;
scenario(5) -> {message_queue_len,0}=process_info(self(),message_queue_len), ok;
scenario(6) -> {dictionary,[]}=process_info(self(),dictionary), ok;
scenario(7) -> true=is_list(processes()), ok;
scenario(8) -> {trap_exit,false}=process_info(self(),trap_exit), ok;
scenario(9) -> error_handler=process_flag(error_handler,old), old=process_flag(error_handler,error_handler), ok;
scenario(10) -> normal=process_flag(priority,low), low=process_flag(priority,normal), ok;
scenario(11) -> on_heap=process_flag(message_queue_data,off_heap), off_heap=process_flag(message_queue_data,on_heap), ok;
scenario(12) -> false=process_flag(sensitive,true), true=process_flag(sensitive,false), ok;
scenario(13) -> 65535=process_flag(fullsweep_after,4), 4=process_flag(fullsweep_after,0), ok;
scenario(14) -> ok=erlang:send(self(),hello,[nosuspend,noconnect]), receive hello -> ok end;
scenario(15) -> true=erlang:send_nosuspend(self(),hello), receive hello -> ok end;
scenario(16) -> {heap_size,H}=process_info(self(),heap_size), true=is_integer(H), ok;
scenario(17) -> {memory,M}=process_info(self(),memory), true=is_integer(M), ok;
scenario(18) -> {reductions,R}=process_info(self(),reductions), true=is_integer(R), ok;
scenario(19) -> {links,L}=process_info(self(),links), true=is_list(L), ok;
scenario(20) -> {monitors,M}=process_info(self(),monitors), true=is_list(M), ok;
scenario(21) -> {garbage_collection,G}=process_info(self(),garbage_collection), true=is_list(G), ok;
scenario(22) -> {catchlevel,C}=process_info(self(),catchlevel), true=is_integer(C), ok;
scenario(23) -> {messages,[]}=process_info(self(),messages), ok;
scenario(24) -> {current_stacktrace,S}=process_info(self(),current_stacktrace), true=is_list(S), ok;
scenario(25) -> {suspending,S}=process_info(self(),suspending), true=is_list(S), ok;
scenario(26) -> false=process_flag(async_dist,true), true=process_flag(async_dist,false), ok;
scenario(27) -> 0=process_flag(save_calls,4), 4=process_flag(save_calls,0), ok;
scenario(28) -> {message_queue_data,on_heap}=process_info(self(),message_queue_data), ok;
scenario(29) -> {error_handler,error_handler}=process_info(self(),error_handler), ok;
scenario(30) -> {priority,normal}=process_info(self(),priority), ok;
scenario(31) -> ok;
scenario(32) -> {stack_size,N}=process_info(self(),stack_size), true=is_integer(N), ok;
scenario(33) -> {total_heap_size,N}=process_info(self(),total_heap_size), true=is_integer(N), ok;
scenario(34) -> []=process_info(self(),registered_name), ok;
scenario(35) -> {sequential_trace_token,[]} = process_info(self(),sequential_trace_token), ok;
scenario(36) -> {trace,0} = process_info(self(),trace), ok;
scenario(37) -> true=is_process_alive(self()), ok;
scenario(38) -> A=alias(), A!hello, receive hello -> true=unalias(A), ok end;
scenario(39) -> A=alias(), true=unalias(A), A!dropped, receive dropped -> bad after 0 -> ok end;
scenario(40) -> try process_flag(trap_exit,invalid) catch error:badarg -> badarg end;
scenario(41) -> async=garbage_collect(self(),[{async,request}]), receive {garbage_collect,request,true} -> ok end;
scenario(42) -> Info=process_info(self()), true=is_list(Info), {status,running}=lists:keyfind(status,1,Info), ok;
scenario(43) -> Info=process_info(self(),[status,trap_exit,message_queue_len,registered_name]), true=is_list(Info), {status,running}=lists:keyfind(status,1,Info), ok;
scenario(44) -> 0=process_flag(self(),save_calls,4), 4=process_flag(self(),save_calls,0), ok;
scenario(45) -> try process_info(self(),unknown_item) catch error:badarg -> badarg end;
scenario(46) -> {backtrace,B}=process_info(self(),backtrace), true=is_binary(B), ok;
scenario(47) -> {binary,B}=process_info(self(),binary), true=is_list(B), ok;
scenario(48) -> {current_function,{proc_bifs,scenario,1}}=process_info(self(),current_function), ok;
scenario(49) -> {current_location,{proc_bifs,scenario,1,Info}}=process_info(self(),current_location), true=is_list(Info), ok;
scenario(50) -> {initial_call,{M,F,A}}=process_info(self(),initial_call), true=is_atom(M), true=is_atom(F), true=is_integer(A), ok;
scenario(51) -> {fullsweep_after,65535}=process_info(self(),fullsweep_after), ok;
scenario(52) -> 233=process_flag(min_heap_size,128), 233=process_flag(min_heap_size,233), ok;
scenario(53) -> 46422=process_flag(min_bin_vheap_size,10), 46422=process_flag(min_bin_vheap_size,46422), ok;
scenario(54) -> true=group_leader(self(),self()), L=group_leader(), L=self(), ok;
scenario(55) -> true=erlang:process_display(self(),backtrace), ok;
scenario(56) -> P=spawn(fun()->ok end), R=monitor(process,P,[{tag,notice}]), receive {notice,R,process,P,noproc} -> ok; {notice,R,process,P,normal} -> ok after 5000 -> timeout end;
scenario(57) -> try monitor(process,self(),[{bad,true}]) catch error:badarg -> badarg end;
scenario(58) -> try erlang:send_nosuspend(self(),x,[bad]) catch error:badarg -> badarg end.
"#;

#[test]
fn process_bif_scenarios_match_otp_29() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping process BIF differential scenarios");
        return;
    };
    let beam = reference.compile_named("proc_bifs", SOURCE, &[]).unwrap();
    reference.load("proc_bifs", &beam).unwrap();
    for scenario in 0..59 {
        let expected = reference.call("proc_bifs", "scenario", &[OwnedTerm::Int(scenario)]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm.eval_scheduled(
            "proc_bifs",
            "scenario",
            &[Term::small(scenario).unwrap()],
            1,
            Some(71),
        );
        assert_eq!(
            expected,
            CallResult::Ok(
                actual
                    .unwrap_or_else(|e| panic!("scenario {scenario}: {e}"))
                    .term
            ),
            "scenario {scenario}"
        );
    }
}
