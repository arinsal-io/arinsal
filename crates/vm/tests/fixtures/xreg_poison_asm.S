%% probe/4 tests X3 for [] (live); xreg_poison.rs byte-patches it to test X7 (dead). Compiled with erlc (from_asm).
{module, xreg_poison_asm}.

{exports, [{probe,4}]}.

{attributes, []}.

{labels, 4}.

{function, probe, 4, 2}.
  {label,1}.
    {line,[]}.
    {func_info,{atom,xreg_poison_asm},{atom,probe},4}.
  {label,2}.
    {test,is_nil,{f,3},[{x,3}]}.
    {move,{atom,stale},{x,0}}.
    return.
  {label,3}.
    {move,{atom,dead},{x,0}}.
    return.
