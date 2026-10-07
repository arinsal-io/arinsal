#!/usr/bin/env escript
%%! -noshell
%% Generate deterministic OTP 29.1.1 differential cases.
-module(arinsal_float_gen).
-export([main/1]).

-define(MASK, 16#FFFFFFFFFFFFFFFF).

main(["--port"]) -> port_loop();
main(["--bounds"]) -> bounds();
main([Path, CountText]) ->
    Count = list_to_integer(CountText),
    {ok, File} = file:open(Path, [write, raw, binary, delayed_write]),
    Specials = special_bits(),
    lists:foreach(fun(B) -> write_float(File, B) end, Specials),
    random_floats(File, Count - length(Specials), 16#9e3779b97f4a7c15),
    random_parses(File, 100000, 16#d1b54a32d192ed03),
    ok = file:close(File).

special_bits() ->
    Base = [0, 16#8000000000000000, 1, 2, 16#000fffffffffffff,
            16#0010000000000000, 16#0010000000000001,
            16#7fefffffffffffff, 16#7feffffffffffffe,
            16#3fb999999999999a, 16#3fd5555555555555,
            16#4340000000000000, 16#4340000000000001,
            16#3ff0000000000000, 16#4004000000000000,
            16#400c000000000000],
    Powers = lists:flatmap(fun(E) ->
        B = ((E + 1023) bsl 52),
        [B, B bor 1, B - 1, B bor 16#000fffffffffffff,
         B bor 16#8000000000000000]
    end, lists:seq(-1022, 1023)),
    Decimal = [float_bits(math:pow(10, E)) || E <- lists:seq(-323, 308)],
    Ties = [float_bits(F) || F <- [0.5, 1.5, 2.5, 3.5, 1.25, 1.35,
                                    1.005, 1.015, 1.125, 1.375, 1.625,
                                    1.0e23, 5.0e-324, 2.2250738585072014e-308,
                                    999999999999999.5, 1000000000000000.5,
                                    10000000000000000.0, 100000000000000000.0]],
    Borders = lists:flatmap(fun(N) ->
        F = float(N),
        B = float_bits(F),
        [B - 1, B, B + 1]
    end, [1000000000000000, 10000000000000000, 100000000000000000]),
    lists:usort(Base ++ Powers ++ Decimal ++ Ties ++ Borders).

float_bits(F) -> <<B:64/unsigned>> = <<F:64/float>>, B.

next(S) ->
    A = ((S bxor (S bsr 30)) * 16#bf58476d1ce4e5b9) band ?MASK,
    B = ((A bxor (A bsr 27)) * 16#94d049bb133111eb) band ?MASK,
    New = (S + 16#9e3779b97f4a7c15) band ?MASK,
    {(B bxor (B bsr 31)) band ?MASK, New}.

random_floats(_File, 0, _) -> ok;
random_floats(File, N, State) ->
    {Bits, Next} = next(State),
    case (Bits bsr 52) band 16#7ff of
        16#7ff -> random_floats(File, N, Next);
        _ -> write_float(File, Bits), random_floats(File, N - 1, Next)
    end.

write_float(_File, Bits) when ((Bits bsr 52) band 16#7ff) =:= 16#7ff -> ok;
write_float(File, Bits) ->
    <<F:64/float>> = <<Bits:64/unsigned>>,
    Scis = [format(F, [{scientific, D}]) || D <- [0,1,5,10,17,20,40]],
    Decs = lists:flatmap(fun(D) ->
        [format(F, [{decimals,D}]), format(F, [{decimals,D},compact])]
    end, [0,1,2,4,10,20,40]),
    Fields = [integer_to_binary(Bits,16), format(F, []), format(F, [short])]
             ++ Scis ++ Decs ++ [iolist_to_binary(io_lib:format("~p",[F]))],
    ok = write_record(File, [<<"F\t">>, lists:join(<<"\t">>, Fields), <<"\n">>]),
    case Bits band 1 of
        0 -> write_parse(File, format(F, [short]));
        1 -> write_parse(File, lists:nth(2 + ((Bits bsr 1) rem 24), Fields))
    end.

format(F, Opts) ->
    try erlang:float_to_binary(F, Opts) of
        B -> B
    catch error:badarg -> <<"!">>
    end.

write_parse(File, S) ->
    Result = try erlang:list_to_float(binary_to_list(S)) of
        F -> integer_to_binary(float_bits(F),16)
    catch error:badarg -> <<"!">>
    end,
    ok = write_record(File, [<<"P\t">>, binary:encode_hex(S), <<"\t">>, Result, <<"\n">>]).

random_parses(_File, 0, _) -> ok;
random_parses(File, N, State) ->
    {A, S1} = next(State),
    {B, S2} = next(S1),
    {C, S3} = next(S2),
    Digits = integer_to_binary(A rem 10000000000000000),
    Frac = integer_to_binary(B rem 10000000000000000),
    Exp = integer_to_binary(C rem 1000),
    Prefix = case A rem 4 of 0 -> <<"+">>; 1 -> <<"-">>; _ -> <<>> end,
    Radix = case B rem 5 of 0 -> <<",">>; 1 -> <<>>; _ -> <<".">> end,
    ExpPart = case C rem 7 of
        0 -> <<"e",Exp/binary>>;
        1 -> <<"E-",Exp/binary>>;
        2 -> <<"e+">>;
        3 -> <<"e">>;
        _ -> <<>>
    end,
    End = case A rem 11 of 0 -> <<" ">>; 1 -> <<0,"tail">>; _ -> <<>> end,
    Text = <<Prefix/binary,Digits/binary,Radix/binary,Frac/binary,ExpPart/binary,End/binary>>,
    write_parse(File, Text),
    random_parses(File, N - 1, S3).

port_loop() ->
    case io:get_line(standard_io, "") of
        eof -> ok;
        Line ->
            Bits = list_to_integer(string:trim(Line), 16),
            case (Bits bsr 52) band 16#7ff of
                16#7ff -> io:format("!~n");
                _ ->
                    <<F:64/float>> = <<Bits:64/unsigned>>,
                    io:format("~s~n", [float_to_binary(F, [short])])
            end,
            port_loop()
    end.

write_record(File, Data) ->
    file:write(File, Data).

bounds() ->
    BitsList = [0, 1, 16#8000000000000000, 16#3fb999999999999a,
                16#4340000000000000, 16#7fefffffffffffff],
    lists:foreach(fun(Bits) ->
        <<F:64/float>> = <<Bits:64/unsigned>>,
        lists:foreach(fun(D) ->
            io:format("B\t~16.16.0B\ts\t~B\t~s~n",
                      [Bits,D,format(F,[{scientific,D}])])
        end, lists:seq(0,251)),
        lists:foreach(fun(D) ->
            io:format("B\t~16.16.0B\td\t~B\t~s~n",
                      [Bits,D,format(F,[{decimals,D}])]),
            io:format("B\t~16.16.0B\tc\t~B\t~s~n",
                      [Bits,D,format(F,[{decimals,D},compact])])
        end, lists:seq(0,255))
    end, BitsList).
