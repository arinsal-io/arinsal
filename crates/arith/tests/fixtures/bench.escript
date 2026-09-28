#!/usr/bin/env escript
%%! -noshell
main(_) ->
    A = 1 bsl 1000,
    ExactB = pow(3,700),
    X = (1 bsl 4096)-1,
    Y = (1 bsl 4095)+12345,
    As = {A,A+1},
    Xs = {X,X-1},
    bench("mul_2pow1000_3pow700_20000_us",fun(I)->element(1+I rem 2,As)*ExactB end,20000),
    bench("bsl_4096_20000_us",fun(I)->element(1+I rem 2,Xs) bsl 31 end,20000),
    bench("band_4096_20000_us",fun(I)->element(1+I rem 2,Xs) band Y end,20000),
    bench("factorial_1000_200_us",fun(_)->factorial(1000,1) end,200).

pow(_,0) -> 1;
pow(A,N) -> A*pow(A,N-1).
factorial(0,A) -> A;
factorial(N,A) -> factorial(N-1,A*N).
bench(Name,F,N) ->
    {Time, Result} = timer:tc(fun()->repeat(N,F,undefined) end),
    _ = Result,
    io:format("~s=~B~n",[Name,Time]).
repeat(0,_,Result) -> Result;
repeat(N,F,_) -> repeat(N-1,F,F(N)).
