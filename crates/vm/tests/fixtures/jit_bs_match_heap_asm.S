%% Reduced from Elixir OptionParser.next_with_config/2: `bs_match` + `test_heap` fuse into
%% `i_bs_match_test_heap` whose Live (1) is below the match context register (x2), while the
%% fail label still reads x1.
{module, jit_bs_match_heap_asm}.
{exports, [{run,0},{t,2}]}.
{attributes, []}.
{labels, 7}.

{function, run, 0, 2}.
  {label,1}.
    {func_info,{atom,jit_bs_match_heap_asm},{atom,run},0}.
  {label,2}.
    {allocate,1,0}.
    {init_yregs,{list,[{y,0}]}}.
    {move,{literal,<<>>},{x,0}}.
    {move,{atom,cfg},{x,1}}.
    {call,2,{f,4}}.
    {move,{x,0},{y,0}}.
    {move,{literal,<<"x">>},{x,0}}.
    {move,{literal,#{a => 1}},{x,1}}.
    {call,2,{f,4}}.
    {test_heap,4,1}.
    {put_list,{x,0},nil,{x,0}}.
    {put_list,{y,0},{x,0},{x,0}}.
    {deallocate,1}.
    return.

{function, t, 2, 4}.
  {label,3}.
    {func_info,{atom,jit_bs_match_heap_asm},{atom,t},2}.
  {label,4}.
    {test,bs_start_match3,{f,3},2,[{x,0}],{x,2}}.
    {bs_match,{f,5},{x,2},{commands,[{ensure_exactly,0}]}}.
    {test_heap,3,1}.
    {put_tuple2,{x,0},{list,[{atom,empty},{x,0}]}}.
    return.
  {label,5}.
    {test_heap,3,2}.
    {put_tuple2,{x,0},{list,[{atom,nonempty},{x,1}]}}.
    return.
