%% Exercises X registers above the BeamAsm register cache (X6+) across op families.
%% Every function takes enough arguments that the interesting operands live in X6..X15.
-module(jit_xmem).
-compile([export_all, nowarn_export_all]).
-record(r, {a, b, c}).

run() ->
    [{Name, try F() catch Class:Reason -> {Class, Reason} end} || {Name, F} <- cases()].

cases() ->
    [{arith, fun() -> arith(a, b, c, d, e, f, 7, 8, 9, 10, 3, 1 bsl 70) end},
     {arith_big, fun() -> arith(a, b, c, d, e, f, 1 bsl 62, 1 bsl 61, -5, 12, 1, 2) end},
     {arith_badarith, fun() -> arith(a, b, c, d, e, f, x, 8, 9, 10, 3, 4) end},
     {guards_int, fun() -> guards(a, b, c, d, e, f, 7, 2.5, foo, <<1, 2>>, [1], {1, 2}) end},
     {guards_other, fun() -> guards(a, b, c, d, e, f, x, 7, "s", 1, #{}, self()) end},
     {cmp, fun() -> cmp(a, b, c, d, e, f, 1, 2, 3, 3.0, z, [z]) end},
     {cmp2, fun() -> cmp(a, b, c, d, e, f, 9, 2, 3, 4, a, b) end},
     {construct, fun() -> construct(a, b, c, d, e, f, 1, [2, 3], {4, 5, 6}, 7, 8, 9) end},
     {destruct, fun() -> destruct(a, b, c, d, e, f, [1, 2 | 3], {x, y, z}, [h | t], {p, q}, 0, 0) end},
     {select, fun() -> [select(a, b, c, d, e, f, V, T) || V <- [1, 2, 3, foo, bar, 4.0, <<>>],
                                                             T <- [{}, {1}, {1, 2}, {1, 2, 3}, x]] end},
     {maps, fun() -> maps(a, b, c, d, e, f, #{k => 1, j => 2}, k, j, 99, new, #{1 => 2}) end},
     {maps_miss, fun() -> maps(a, b, c, d, e, f, #{k => 1}, k, j, 99, new, #{}) end},
     {map_update_badmap, fun() -> maps(a, b, c, d, e, f, notmap, k, j, 99, new, #{}) end},
     {bits, fun() -> bits(a, b, c, d, e, f, <<1, 2, 3, 4, 5, 6, 7, 8, "tail">>, 16, 3, <<"xyz">>, 255, 2.5) end},
     {bits_utf, fun() -> bits_utf(a, b, c, d, e, f, <<"h€llo"/utf8>>, <<0, 104, 0, 105>>, 8364, $a) end},
     {floats, fun() -> floats(a, b, c, d, e, f, 1.5, 2, 3.25, -4, 0.5, 10) end},
     {floats_bad, fun() -> floats(a, b, c, d, e, f, 1.5, 2, 3.25, -4, 0.0, 10) end},
     {bifs, fun() -> bifs(a, b, c, d, e, f, [1, 2, 3], {1, 2, 3}, <<1, 2, 3>>, -7, #{a => 1}, 2) end},
     {funs, fun() -> funs(a, b, c, d, e, f, 10, 20, fun(X, Y) -> X * Y end, lists, reverse, [1, 2]) end},
     {records, fun() -> records(a, b, c, d, e, f, #r{a = 1, b = 2, c = 3}, 10, 20, 30, other, x) end},
     {records_bad, fun() -> records(a, b, c, d, e, f, {r, 1}, 10, 20, 30, other, x) end},
     {errors_badmatch, fun() -> errors(a, b, c, d, e, f, 1, 2, badmatch) end},
     {errors_case, fun() -> errors(a, b, c, d, e, f, 1, 2, case_clause) end},
     {errors_if, fun() -> errors(a, b, c, d, e, f, 1, 2, if_clause) end},
     {errors_try, fun() -> errors(a, b, c, d, e, f, 1, 2, try_clause) end},
     {errors_ok, fun() -> errors(a, b, c, d, e, f, 1, 1, ok) end},
     {try_catch, fun() -> try_catch(a, b, c, d, e, f, throw, value, 3, 4) end},
     {try_error, fun() -> try_catch(a, b, c, d, e, f, error, reason, 3, 4) end},
     {try_exit, fun() -> try_catch(a, b, c, d, e, f, exit, why, 3, 4) end},
     {try_none, fun() -> try_catch(a, b, c, d, e, f, none, why, 3, 4) end},
     {raise, fun() -> raise(a, b, c, d, e, f, error, myreason, 5) end},
     {receive_, fun() -> receive_(a, b, c, d, e, f, msg1, 1000, tag, 7) end},
     {receive_timeout, fun() -> receive_(a, b, c, d, e, f, nomsg, 5, tag, 7) end},
     {setel, fun() -> setel(a, b, c, d, e, f, {1, 2, 3, 4, 5}, x, y, z) end},
     {swap, fun() -> swap(a, b, c, d, e, f, 1, 2, 3, 4, 5, 6) end},
     {many, fun() -> many(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20) end},
     {length, fun() -> len(a, b, c, d, e, f, lists:seq(1, 100), [x | y], 3) end},
     {process_dict, fun() -> pdict(a, b, c, d, e, f, key1, val1, key2) end}].

arith(A, B, C, D, E, F, G, H, I, J, K, L) ->
    R1 = G + H,
    R2 = H - I,
    R3 = I * J,
    R4 = J div K,
    R5 = J rem K,
    R6 = G band J,
    R7 = G bor K,
    R8 = G bxor J,
    R9 = G bsl K,
    R10 = J bsr K,
    R11 = bnot G,
    R12 = -H,
    R13 = L * G + H,
    R14 = L div I,
    {A, B, C, D, E, F, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, R13, R14}.

guards(A, B, C, D, E, F, G, H, I, J, K, L) ->
    T1 = if is_integer(G) -> int; is_atom(G) -> atom; true -> other end,
    T2 = if is_float(H) -> float; is_number(H) -> number; true -> other end,
    T3 = if is_atom(I) -> atom; is_list(I) -> list; true -> other end,
    T4 = if is_binary(J) -> binary; is_bitstring(J) -> bits; is_integer(J) -> int; true -> other end,
    T5 = if is_list(K), K =/= [] -> nonempty; is_map(K) -> map; K =:= [] -> nil; true -> other end,
    T6 = if is_tuple(L), tuple_size(L) =:= 2 -> pair; is_pid(L) -> pid; is_tuple(L) -> tuple;
             true -> other end,
    T7 = if is_boolean(G) -> bool; is_function(G) -> function; is_reference(G) -> ref;
             is_port(G) -> port; true -> none end,
    T8 = if G >= 0, G < 10 -> in_range; true -> out end,
    {A, B, C, D, E, F, T1, T2, T3, T4, T5, T6, T7, T8}.

cmp(A, B, C, D, E, F, G, H, I, J, K, L) ->
    {A, B, C, D, E, F,
     G < H, G >= H, I == J, I =:= J, I /= J, I =/= J, K < L, max(G, H), min(I, J),
     if G =:= 1 -> one; true -> notone end,
     if K =:= z -> zed; true -> notzed end}.

construct(A, B, C, D, E, F, G, H, I, J, K, L) ->
    List = [G, J | H],
    Tuple = {G, H, I, J, K, L},
    Nested = {[K | L], {J}, [G]},
    Bin = <<G:8, J:16, K/integer, L:32/little>>,
    {A, B, C, D, E, F, List, Tuple, Nested, Bin}.

destruct(A, B, C, D, E, F, G, H, I, J, _K, _L) ->
    [G1, G2 | G3] = G,
    {H1, H2, H3} = H,
    Hd = hd(I),
    Tl = tl(I),
    {J1, J2} = J,
    {A, B, C, D, E, F, G1, G2, G3, H1, H2, H3, Hd, Tl, J1, J2, element(2, H)}.

select(A, B, C, D, E, F, V, T) ->
    S1 = case V of
             1 -> one;
             2 -> two;
             3 -> three;
             foo -> foo;
             bar -> bar;
             _ -> other
         end,
    S2 = case T of
             {} -> zero;
             {_} -> one;
             {_, _} -> two;
             {_, _, _} -> three;
             _ -> notuple
         end,
    {A, B, C, D, E, F, S1, S2}.

maps(A, B, C, D, E, F, M, K1, K2, V, K3, M2) ->
    #{K1 := X1} = M,
    X2 = maps:get(K2, M, default),
    Mu = M#{K3 => V},
    Mx = Mu#{K1 := V},
    #{K1 := Y1, K2 := Y2} = Mx,
    New = #{K1 => V, K3 => M2, V => K1},
    Size = map_size(Mx),
    IsKey = is_map_key(K3, Mx),
    Get = map_get(K3, Mu),
    {A, B, C, D, E, F, X1, X2, Mu, Mx, Y1, Y2, New, Size, IsKey, Get}.

bits(A, B, C, D, E, F, Bin, Size, Skip, Str, Byte, Flt) ->
    <<X:Size, Y:8/signed, Z:16/little, _:Skip/binary, Rest/binary>> = Bin,
    <<P:4, Q:4, Tail/bits>> = Rest,
    Pos = case Bin of
              <<_:Size, "xyz", _/binary>> -> has_xyz;
              <<_:8, _:8, _/binary>> -> no_xyz
          end,
    Built = <<Str/binary, Byte:8, Flt/float, Size:Skip/unit:8, Tail/bits>>,
    Sz = byte_size(Built),
    BitSz = bit_size(Tail),
    {A, B, C, D, E, F, X, Y, Z, P, Q, Tail, Pos, Built, Sz, BitSz}.

bits_utf(A, B, C, D, E, F, U8, U16, CP, Ch) ->
    <<H/utf8, E2/utf8, Rest/binary>> = U8,
    <<W1/utf16, W2/utf16>> = U16,
    Out = <<CP/utf8, Ch/utf16, CP/utf32>>,
    {A, B, C, D, E, F, H, E2, Rest, W1, W2, Out}.

floats(A, B, C, D, E, F, G, H, I, J, K, L) ->
    R1 = G + H,
    R2 = I - J,
    R3 = G * I,
    R4 = I / K,
    R5 = -G,
    R6 = (G + I) * (H - L) / K,
    {A, B, C, D, E, F, R1, R2, R3, R4, R5, R6}.

bifs(A, B, C, D, E, F, G, H, I, J, K, L) ->
    {A, B, C, D, E, F,
     length(G), tuple_size(H), byte_size(I), abs(J), map_size(K), element(L, H),
     hd(G), tl(G), node(), is_list(G) and is_tuple(H), not is_atom(G),
     is_binary(I) or false, self() =:= self(), erlang:phash2(H), atom_to_list(A),
     integer_to_list(J), list_to_tuple(G), lists:sum(G) + L}.

funs(A, B, C, D, E, F, G, H, Fun, M, Fn, Args) ->
    Clo = fun(X) -> X + G + H end,
    R1 = Fun(G, H),
    R2 = Clo(1),
    R3 = apply(M, Fn, [Args]),
    R4 = M:Fn(Args),
    R5 = (fun M:Fn/1)(Args),
    R6 = lists:map(fun(X) -> X * G end, Args),
    {A, B, C, D, E, F, R1, R2, R3, R4, R5, R6, is_function(Clo, 1)}.

records(A, B, C, D, E, F, R, X, Y, Z, O, P) ->
    #r{a = Ra, b = Rb} = R,
    R2 = R#r{a = X, c = Z},
    R3 = R2#r{b = Y},
    IsR = is_record(R, r),
    IsO = is_record(O, r),
    {A, B, C, D, E, F, Ra, Rb, R2, R3, IsR, IsO, R3#r.c, P}.

errors(A, B, C, D, E, F, G, H, Kind) ->
    case Kind of
        badmatch -> G = H;
        case_clause -> case G of H -> ok end;
        if_clause -> if G =:= H -> ok end;
        try_clause -> try G of H -> ok catch _ -> caught end;
        ok -> {A, B, C, D, E, F, G = H}
    end.

try_catch(A, B, C, D, E, F, Class, Reason, G, H) ->
    try
        case Class of
            throw -> throw({Reason, G});
            error -> error({Reason, H});
            exit -> exit({Reason, G + H});
            none -> {no_exception, G * H}
        end
    of
        V -> {A, B, C, D, E, F, value, V}
    catch
        throw:T -> {A, B, C, D, E, F, thrown, T};
        error:Err:Stk -> {A, B, C, D, E, F, errored, Err, is_list(Stk)};
        exit:X -> {A, B, C, D, E, F, exited, X}
    after
        put(after_ran, {G, H})
    end.

raise(A, B, C, D, E, F, Class, Reason, G) ->
    Stk = try error(first) catch error:first:S -> S end,
    try erlang:raise(Class, {Reason, G}, Stk)
    catch Cl:Rs -> {A, B, C, D, E, F, Cl, Rs}
    end.

receive_(A, B, C, D, E, F, Msg, Timeout, Tag, G) ->
    Ref = make_ref(),
    case Msg of
        nomsg -> ok;
        _ -> self() ! {Tag, Ref, Msg, G}
    end,
    R = receive
            {Tag, Ref, M, G} -> {got, M}
        after Timeout -> {timeout, Timeout}
        end,
    {A, B, C, D, E, F, R}.

setel(A, B, C, D, E, F, T, X, Y, Z) ->
    T1 = setelement(2, T, X),
    T2 = setelement(3, T1, Y),
    T3 = setelement(5, T2, Z),
    {A, B, C, D, E, F, T3, setelement(1, T, Z)}.

swap(A, B, C, D, E, F, G, H, I, J, K, L) ->
    swap2(A, B, C, D, E, F, H, G, J, I, L, K).

swap2(A, B, C, D, E, F, G, H, I, J, K, L) ->
    swapped(L, K, J, I, H, G, F, E, D, C, B, A).

swapped(A, B, C, D, E, F, G, H, I, J, K, L) -> [A, B, C, D, E, F, G, H, I, J, K, L].

many(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20) ->
    S = A7 + A8 + A9 + A10 + A11 + A12 + A13 + A14 + A15 + A16 + A17 + A18 + A19 + A20,
    many_tail(A20, A19, A18, A17, A16, A15, A14, A13, A12, A11, A10, A9, A8, A7, A6, A5, A4, A3,
              A2, A1 + S).

many_tail(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19,
          A20) ->
    {A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20}.

len(A, B, C, D, E, F, L, Improper, N) ->
    Len = length(L),
    Bad = try length(Improper) catch error:Why -> {error, Why} end,
    {A, B, C, D, E, F, Len, Bad, lists:nth(N, L)}.

pdict(A, B, C, D, E, F, K1, V1, K2) ->
    put(K1, V1),
    G1 = get(K1),
    G2 = get(K2),
    erase(K1),
    {A, B, C, D, E, F, G1, G2, get(K1)}.
