-module(integers).
-export([fib/1, fib_guard/1, fib_three/1, fib_swapped/1, helper_fib/1,
         decrement/1, tail_sum/2, sum_overflow/2, badarith/1,
         difference/2, product/2, quotient/2, remainder/2,
         bit_and/2, bit_or/2, left_shift/2, right_shift/2,
         ackermann/2, tak/3, fail_after/2, overflow_recursive/2]).

fib(N) when N < 2 -> N;
fib(N) -> fib(N - 1) + fib(N - 2).

fib_guard(N) when N < 2 -> N;
fib_guard(N) when is_integer(N) -> fib_guard(N - 1) + fib_guard(N - 2).

fib_three(0) -> 0;
fib_three(1) -> 1;
fib_three(N) when N > 1 -> fib_three(N - 1) + fib_three(N - 2).

fib_swapped(N) when N < 2 -> N;
fib_swapped(N) -> fib_swapped(N - 2) + fib_swapped(N - 1).

helper_fib(N) when N < 2 -> N;
helper_fib(N) -> helper_fib(decrement(N)) + helper_fib(N - 2).
decrement(N) -> N - 1.

tail_sum(0, Acc) -> Acc;
tail_sum(N, Acc) -> tail_sum(N - 1, Acc + N).

sum_overflow(A, B) -> A + B.
badarith(N) -> N + wrong.
difference(A, B) -> A - B.
product(A, B) -> A * B.
quotient(A, B) -> A div B.
remainder(A, B) -> A rem B.
bit_and(A, B) -> A band B.
bit_or(A, B) -> A bor B.
left_shift(A, B) -> A bsl B.
right_shift(A, B) -> A bsr B.

ackermann(0, N) -> N + 1;
ackermann(M, 0) -> ackermann(M - 1, 1);
ackermann(M, N) -> ackermann(M - 1, ackermann(M, N - 1)).

tak(X, Y, Z) when Y >= X -> Z;
tak(X, Y, Z) -> tak(tak(X - 1, Y, Z),
                     tak(Y - 1, Z, X),
                     tak(Z - 1, X, Y)).

fail_after(0, D) -> 1 div D;
fail_after(N, D) -> fail_after(N - 1, D) + 1.

overflow_recursive(0, V) -> V;
overflow_recursive(N, V) -> overflow_recursive(N - 1, V) + 1.
