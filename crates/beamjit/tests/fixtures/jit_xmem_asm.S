%% Hand-written BEAM assembly: instructions that the compiler never emits with operands in
%% X registers above the BeamAsm register cache (X6+). Compiled with `erlc` (from_asm).
{module, jit_xmem_asm}.

{exports, [{run,0}]}.

{attributes, []}.

{labels, 40}.

{function, run, 0, 2}.
  {label,1}.
    {line,[]}.
    {func_info,{atom,jit_xmem_asm},{atom,run},0}.
  {label,2}.
    {allocate,5,0}.
    {init_yregs,{list,[{y,0},{y,1},{y,2},{y,3},{y,4}]}}.
    {call,0,{f,4}}.
    {move,{x,0},{y,0}}.
    {call,0,{f,6}}.
    {move,{x,0},{y,1}}.
    {call,0,{f,8}}.
    {move,{x,0},{y,2}}.
    {call,0,{f,12}}.
    {move,{x,0},{y,3}}.
    {call,0,{f,16}}.
    {move,{x,0},{y,4}}.
    {call,0,{f,21}}.
    {test_heap,12,1}.
    {put_list,{x,0},nil,{x,0}}.
    {put_list,{y,4},{x,0},{x,0}}.
    {put_list,{y,3},{x,0},{x,0}}.
    {put_list,{y,2},{x,0},{x,0}}.
    {put_list,{y,1},{x,0},{x,0}}.
    {put_list,{y,0},{x,0},{x,0}}.
    {deallocate,5}.
    return.

%% swap and swap chains on X6+.
{function, swaps, 0, 4}.
  {label,3}.
    {line,[]}.
    {func_info,{atom,jit_xmem_asm},{atom,swaps},0}.
  {label,4}.
    {move,{atom,a},{x,0}}.
    {move,nil,{x,1}}.
    {move,nil,{x,2}}.
    {move,nil,{x,3}}.
    {move,nil,{x,4}}.
    {move,nil,{x,5}}.
    {move,{integer,1},{x,6}}.
    {move,{integer,2},{x,7}}.
    {move,{integer,3},{x,8}}.
    {move,{atom,b},{x,9}}.
    {move,{integer,4},{x,10}}.
    {move,{integer,5},{x,11}}.
    {swap,{x,6},{x,7}}.
    {swap,{x,0},{x,9}}.
    {swap,{x,8},{x,11}}.
    {swap,{x,11},{x,10}}.
    {test_heap,8,12}.
    {put_tuple2,{x,0},{list,[{x,6},{x,7},{x,0},{x,9},{x,8},{x,10},{x,11}]}}.
    return.

%% Paired moves between X6+ and Y registers (store_two_values / load_two_xregs).
{function, pairs, 0, 6}.
  {label,5}.
    {line,[]}.
    {func_info,{atom,jit_xmem_asm},{atom,pairs},0}.
  {label,6}.
    {allocate,2,0}.
    {move,{integer,10},{x,6}}.
    {move,{integer,20},{x,7}}.
    {move,{x,6},{y,0}}.
    {move,{x,7},{y,1}}.
    {move,{atom,z},{x,6}}.
    {move,{atom,z},{x,7}}.
    {move,{y,0},{x,7}}.
    {move,{y,1},{x,6}}.
    {move,{y,0},{x,8}}.
    {move,{y,1},{x,9}}.
    {move,nil,{x,0}}.
    {move,nil,{x,1}}.
    {move,nil,{x,2}}.
    {move,nil,{x,3}}.
    {move,nil,{x,4}}.
    {move,nil,{x,5}}.
    {test_heap,5,10}.
    {put_tuple2,{x,0},{list,[{x,6},{x,7},{x,8},{x,9}]}}.
    {deallocate,2}.
    return.

%% call_fun2 with the fun in X7, move_call_last and move_deallocate_return from X6+.
{function, funs, 0, 8}.
  {label,7}.
    {line,[]}.
    {func_info,{atom,jit_xmem_asm},{atom,funs},0}.
  {label,8}.
    {allocate,1,0}.
    {init_yregs,{list,[{y,0}]}}.
    {move,{atom,erlang},{x,0}}.
    {move,{atom,abs},{x,1}}.
    {move,{integer,1},{x,2}}.
    {call_ext,3,{extfunc,erlang,make_fun,3}}.
    {move,{x,0},{x,7}}.
    {move,{integer,-5},{x,0}}.
    {call_fun2,{atom,unsafe},1,{x,7}}.
    {move,{x,0},{y,0}}.
    {call,0,{f,12}}.
    {move,{x,0},{x,6}}.
    {move,{y,0},{x,8}}.
    {move,nil,{x,0}}.
    {move,nil,{x,1}}.
    {move,nil,{x,2}}.
    {move,nil,{x,3}}.
    {move,nil,{x,4}}.
    {move,nil,{x,5}}.
    {move,nil,{x,7}}.
    {test_heap,3,9}.
    {put_tuple2,{x,9},{list,[{x,6},{x,8}]}}.
    {move,{x,9},{x,0}}.
    {call_last,1,{f,14},1}.

{function, mdr, 0, 12}.
  {label,11}.
    {line,[]}.
    {func_info,{atom,jit_xmem_asm},{atom,mdr},0}.
  {label,12}.
    {allocate,1,0}.
    {move,{atom,q},{y,0}}.
    {move,{literal,{mdr,1}},{x,7}}.
    {move,{x,7},{x,0}}.
    {deallocate,1}.
    return.

{function, ident, 1, 14}.
  {label,13}.
    {line,[]}.
    {func_info,{atom,jit_xmem_asm},{atom,ident},1}.
  {label,14}.
    return.

%% Receive markers in X6+.
{function, markers, 0, 16}.
  {label,15}.
    {line,[]}.
    {func_info,{atom,jit_xmem_asm},{atom,markers},0}.
  {label,16}.
    {allocate,1,0}.
    {init_yregs,{list,[{y,0}]}}.
    {call_ext,0,{extfunc,erlang,make_ref,0}}.
    {move,{x,0},{y,0}}.
    {move,{x,0},{x,8}}.
    {move,nil,{x,1}}.
    {move,nil,{x,2}}.
    {move,nil,{x,3}}.
    {move,nil,{x,4}}.
    {move,nil,{x,5}}.
    {move,nil,{x,6}}.
    {recv_marker_reserve,{x,7}}.
    {recv_marker_bind,{x,7},{x,8}}.
    {recv_marker_use,{x,8}}.
    {test_heap,3,9}.
    {put_tuple2,{x,1},{list,[{x,8},{atom,hello}]}}.
    {bif,self,{f,0},[],{x,0}}.
    send.
  {label,17}.
    {loop_rec,{f,19},{x,0}}.
    {test,is_tuple,{f,18},[{x,0}]}.
    {test,test_arity,{f,18},[{x,0},2]}.
    {get_tuple_element,{x,0},0,{x,1}}.
    {test,is_eq_exact,{f,18},[{x,1},{y,0}]}.
    {get_tuple_element,{x,0},1,{x,2}}.
    {recv_marker_clear,{y,0}}.
    remove_message.
    {test_heap,3,3}.
    {put_tuple2,{x,0},{list,[{atom,got},{x,2}]}}.
    {deallocate,1}.
    return.
  {label,18}.
    {loop_rec_end,{f,17}}.
  {label,19}.
    {wait_timeout,{f,17},{integer,1000}}.
    timeout.
    {recv_marker_clear,{y,0}}.
    {move,{atom,timeout},{x,0}}.
    {deallocate,1}.
    return.

%% `raise` with its stacktrace and value operands in X9 and X10.
{function, raise_outer, 0, 21}.
  {label,20}.
    {line,[]}.
    {func_info,{atom,jit_xmem_asm},{atom,raise_outer},0}.
  {label,21}.
    {allocate,1,0}.
    {'try',{y,0},{f,22}}.
    {call,0,{f,24}}.
    {try_end,{y,0}}.
    {deallocate,1}.
    return.
  {label,22}.
    {try_case,{y,0}}.
    {test_heap,4,2}.
    {put_tuple2,{x,0},{list,[{atom,caught},{x,0},{x,1}]}}.
    {deallocate,1}.
    return.

{function, raise_inner, 0, 24}.
  {label,23}.
    {line,[]}.
    {func_info,{atom,jit_xmem_asm},{atom,raise_inner},0}.
  {label,24}.
    {allocate,1,0}.
    {'try',{y,0},{f,25}}.
    {move,{atom,boom},{x,0}}.
    {call_ext,1,{extfunc,erlang,error,1}}.
    {try_end,{y,0}}.
    {deallocate,1}.
    return.
  {label,25}.
    {try_case,{y,0}}.
    {move,{x,2},{x,9}}.
    {move,{x,1},{x,10}}.
    {bif,raise,{f,0},[{x,9},{x,10}],{x,0}}.
    {deallocate,1}.
    return.
