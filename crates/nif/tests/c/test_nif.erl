-module(test_nif).
-on_load(init/0).
-export([init/0,basic/1,atom_string_probe/0,compare_probe/0,system_info_probe/0,schedule_probe/0,map_probe/0,iolist_probe/0,env_probe/0,binary_probe/0,
         resource_probe/0,resource_binary_probe/0,dynamic_probe/0,dtor_count/0,format_probe/0,etf_probe/0,time_probe/0,
         hash_probe/0,ioq_probe/0,iovec_probe/0,thread_probe/0,send_probe/0,exception_probe/0]).
init() -> erlang:load_nif(os:getenv("TEST_NIF_PATH"), 0).
basic(_) -> erlang:nif_error(nif_not_loaded).
atom_string_probe() -> erlang:nif_error(nif_not_loaded).
compare_probe() -> erlang:nif_error(nif_not_loaded).
system_info_probe() -> erlang:nif_error(nif_not_loaded).
schedule_probe() -> erlang:nif_error(nif_not_loaded).
map_probe() -> erlang:nif_error(nif_not_loaded).
iolist_probe() -> erlang:nif_error(nif_not_loaded).
env_probe() -> erlang:nif_error(nif_not_loaded).
binary_probe() -> erlang:nif_error(nif_not_loaded).
resource_probe() -> erlang:nif_error(nif_not_loaded).
resource_binary_probe() -> erlang:nif_error(nif_not_loaded).
dynamic_probe() -> erlang:nif_error(nif_not_loaded).
dtor_count() -> erlang:nif_error(nif_not_loaded).
format_probe() -> erlang:nif_error(nif_not_loaded).
etf_probe() -> erlang:nif_error(nif_not_loaded).
time_probe() -> erlang:nif_error(nif_not_loaded).
thread_probe() -> erlang:nif_error(nif_not_loaded).
hash_probe() -> erlang:nif_error(nif_not_loaded).
ioq_probe() -> erlang:nif_error(nif_not_loaded).
iovec_probe() -> erlang:nif_error(nif_not_loaded).
send_probe() -> erlang:nif_error(nif_not_loaded).
exception_probe() -> erlang:nif_error(nif_not_loaded).
