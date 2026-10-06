-module(binparse_variants).
-export([reordered/1, bytes/1, extra_clause/1, comprehension/1, recursive/1,
         copy_only/1, sum_only/1,
         list_length/1,
         sum_range/3,
         sum_generic/1, sum_unaligned/0,
         sum_seq/2,
         copy_value/2, copy_unaligned/0,
         invalid_binary/1, invalid_copy/1,
         recursive_swapped/1, parse_input/1, sum_input/1,
         escape_tail/1, stored_tail/1,
         comprehension_build_only/1, comprehension_fold_only/1]).

stream(Frames) ->
    Payload = <<7, (binary:copy(<<0>>, 1022))/binary, 9>>,
    binary:copy(<<1024:32/big, Payload/binary>>, Frames).

copy_only(Frames) -> byte_size(stream(Frames)).
sum_only(Frames) -> lists:sum(binary:bin_to_list(binary:copy(<<7,0,9>>, Frames))).
list_length(Bytes) -> erlang:length(binary:bin_to_list(Bytes)).
sum_range(Bytes, Start, End) -> lists:sum(binary:bin_to_list(Bytes, Start, End)).
sum_generic(Values) -> lists:sum(Values).
sum_seq(First, Last) -> lists:sum(lists:seq(First, Last)).
sum_unaligned() ->
    <<_:1, Data:3/binary, _:7>> = <<1:1, 7, 8, 9, 0:7>>,
    lists:sum(binary:bin_to_list(Data)).
copy_value(Bytes, Count) -> binary:copy(Bytes, Count).
copy_unaligned() ->
    <<_:1, Data:3/binary, _:7>> = <<1:1, 7, 8, 9, 0:7>>,
    binary:copy(Data, 4).

reordered(Frames) -> parse_reordered(0, stream(Frames)).
parse_reordered(Total, <<>>) -> Total;
parse_reordered(Total, <<Size:32/big, Data:Size/binary, More/binary>>) ->
    parse_reordered(Total + lists:sum(binary:bin_to_list(Data)) + Size, More).

bytes(Frames) -> parse_bytes(stream(Frames), 0).
parse_bytes(<<>>, Total) -> Total;
parse_bytes(<<Size:32/big, Data:Size/bytes, More/binary>>, Total) ->
    parse_bytes(More, Total + Size + lists:sum(binary:bin_to_list(Data))).

extra_clause(Frames) -> parse_extra(stream(Frames), 0).
parse_extra(<<>>, Total) -> Total;
parse_extra(<<Size:32/big, Data:Size/binary, More/binary>>, Total) ->
    parse_extra(More, Total + Size + lists:sum(binary:bin_to_list(Data)));
parse_extra(_, _) -> bad_frame.

comprehension(Frames) -> parse_comprehension(stream(Frames), 0).
parse_comprehension(<<>>, Total) -> Total;
parse_comprehension(<<Size:32/big, Data:Size/binary, More/binary>>, Total) ->
    Copy = << <<Byte>> || <<Byte>> <= Data >>,
    ByteSum = lists:foldl(fun(Byte, Acc) -> Acc + Byte end,
                          0, binary:bin_to_list(Copy)),
    parse_comprehension(More, Total + Size + ByteSum).

recursive(Frames) -> parse_recursive(stream(Frames), 0).
parse_recursive(<<>>, Total) -> Total;
parse_recursive(<<Size:32/big, Data:Size/binary, More/binary>>, Total) ->
    parse_recursive(More, Total + Size + sum_bytes(Data, 0)).
sum_bytes(<<>>, Total) -> Total;
sum_bytes(<<Byte, More/binary>>, Total) -> sum_bytes(More, Total + Byte).

recursive_swapped(Frames) -> parse_recursive_swapped(0, stream(Frames)).
parse_recursive_swapped(Total, <<>>) -> Total;
parse_recursive_swapped(Total, <<Size:32/big, Data:Size/binary, More/binary>>) ->
    parse_recursive_swapped(Total + Size + sum_swapped(0, Data), More);
parse_recursive_swapped(_, _) -> bad_frame.
sum_swapped(Total, <<>>) -> Total;
sum_swapped(Total, <<Byte, More/binary>>) -> sum_swapped(Total + Byte, More);
sum_swapped(_, _) -> bad_byte_string.

parse_input(Data) -> parse_recursive(Data, 0).
sum_input(Data) -> sum_bytes(Data, 0).
escape_tail(<<_, Tail/binary>>) -> Tail.
stored_tail(<<_, Tail/binary>>) -> {Tail, [Tail]}.

comprehension_build_only(Frames) -> build_frames(stream(Frames), 0).
build_frames(<<>>, Total) -> Total;
build_frames(<<Size:32/big, Data:Size/binary, More/binary>>, Total) ->
    Copy = << <<Byte>> || <<Byte>> <= Data >>,
    build_frames(More, Total + Size + copied_size(Copy)).
copied_size(Copy) -> byte_size(Copy).

comprehension_fold_only(Frames) -> fold_frames(stream(Frames), 0).
fold_frames(<<>>, Total) -> Total;
fold_frames(<<Size:32/big, Data:Size/binary, More/binary>>, Total) ->
    ByteSum = lists:foldl(fun(Byte, Acc) -> Acc + Byte end,
                          0, binary:bin_to_list(Data)),
    fold_frames(More, Total + Size + ByteSum).

invalid_binary(Value) -> lists:sum(binary:bin_to_list(Value)).
invalid_copy(Value) -> binary:copy(Value, 2).
