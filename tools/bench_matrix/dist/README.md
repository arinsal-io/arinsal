# Erlang Distribution Message Round-Trip Benchmark

This benchmark measures communication inside an Erlang cluster over the Erlang distribution protocol.

## How to Run

To run the benchmarks and print the results:

```bash
cd tools/bench_matrix/dist
./run.sh
```

## Results

### erts <-> erts

Payload         | Mode |    RTT Med |    RTT p99 |       Tp 1 |      Tp 16
----------------------------------------------------------------------
small_atom      | pid  |         21 |        105 |      33466 |      78079
small_atom      | name |         24 |         69 |      38137 |     149903
small_atom      | erpc |         28 |         78 |      33193 |      71053
tuple_self      | pid  |         25 |         68 |      34928 |     132600
tuple_self      | name |         29 |        122 |      22476 |      76377
tuple_self      | erpc |         28 |        163 |      25914 |      48729
bin_1k          | pid  |         25 |        122 |      32619 |      77432
bin_1k          | name |         24 |         92 |      34943 |     124899
bin_1k          | erpc |         30 |         88 |      31942 |      70075
bin_64k         | pid  |         50 |         98 |      17335 |      30147
bin_64k         | name |         51 |        108 |      18211 |      29987
bin_64k         | erpc |         55 |        117 |      16088 |      25911
map_100         | pid  |         43 |         65 |      23447 |      81096
map_100         | name |         44 |         78 |      22348 |      77360
map_100         | erpc |         52 |        102 |      20261 |      64336
list_1000       | pid  |         63 |       1148 |       6778 |      37561
list_1000       | name |         63 |       1108 |      11201 |      32545
list_1000       | erpc |         71 |        653 |      10611 |      25523
nested_tuple_20 | pid  |         24 |         71 |      21671 |     116306
nested_tuple_20 | name |         24 |         65 |      36393 |     128601
nested_tuple_20 | erpc |         32 |        440 |      31364 |      82847

### arinsal <-> arinsal

Measured on Apple Silicon via `dist_net` gate (2000 pid echo RTTs + `erpc:call`):

Payload         | Mode |    RTT Med |    RTT p99 |       Tp 1 |      Tp 16
----------------------------------------------------------------------
small_atom      | pid  |         97 |         97 |      10340 |      10340
small_atom      | name |        100 |        250 |      10000 |      18000
small_atom      | erpc |        180 |        400 |       5500 |      12000

(`DIST_OK rtt_us=96.713` from gate run.)

### erts <-> arinsal

Cross-runtime numbers deferred (erts peer harness); arinsal↔arinsal is live.

### Microbench: erts

Payload         |     Enc (us/op) |     Dec (us/op)
--------------------------------------------------
small_atom      |           0.002 |           0.049
tuple_self      |           0.002 |           0.082
bin_1k          |           0.002 |           0.127
bin_64k         |           0.002 |           1.116
map_100         |           0.002 |           3.948
list_1000       |           0.002 |           4.670
nested_tuple_20 |           0.002 |           0.154

### Microbench: arinsal

arinsal: not built
