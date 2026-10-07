# Benchmark Results: erts vs Arinsal vs Go

- **Date**: 2026-09-28 (Mon Sep 28 03:45:03 CEST 2026)
- **Git Commit**: `010cc68`
- **Machine**:
  - `hw.model`: `Apple Silicon`
  - Cores: 10 cores (`hw.ncpu: 10`, 8 performance + 2 efficiency)
- **Load Note**:
  - `uptime` before run: `03:45  up 19 days, 17:31, 3 users, load averages: 9.24 5.62 5.41`
  - `uptime` after run: `03:46  up 19 days, 17:32, 3 users, load averages: 6.45 5.74 5.48`
  - Note: Other builds or parallel agent tasks were running on the system during execution.

## Changes since the previous table (2026-09-27)

Kernels that moved >20% in execution time (ns/op) or Arinsal/erts ratio:
- **list build+map+fold 100k** (sched `default`): Arinsal default 10,297.0 → 265.1 ns/op (-97.4%), Arinsal/erts 356.53x → 8.22x (-97.7%)
- **map put/get 100k** (sched `default`): Arinsal default 26,523.0 → 766.8 ns/op (-97.1%), Arinsal/erts 89.38x → 2.55x (-97.1%)
- **sort 100k ints** (sched `default`): Arinsal default 4,404.0 → 185.6 ns/op (-95.8%), Arinsal/erts 162.46x → 5.34x (-96.7%)
- **binary build** (sched `default`): Arinsal default 576.4 → 67.8 ns/op (-88.2%), Arinsal/erts 134.30x → 15.31x (-88.6%)
- **closure calls** (sched `default`): Arinsal default 214.1 → 87.9 ns/op (-58.9%), Arinsal/erts 66.50x → 25.68x (-61.4%)
- **ets hash table** (sched `default`): Arinsal default 1,114.0 → 500.8 ns/op (-55.0%), Arinsal/erts 6.01x → 1.68x (-72.1%)
- **ping-pong 1M** (sched `default`): Arinsal default 1,472.0 → 866.9 ns/op (-41.1%), Arinsal/erts 3.17x → 1.77x (-44.3%)
- **ping-pong 1M** (sched `1`): Arinsal default 1,468.0 → 874.3 ns/op (-40.4%), Arinsal/erts 0.95x → 0.56x (-41.5%)
- **spawn+exit+recv 100k** (sched `1`): Arinsal default 2,520.0 → 1,572.2 ns/op (-37.6%), Arinsal/erts 1.42x → 0.86x (-39.4%)
- **spawn+exit+recv 100k** (sched `default`): Arinsal default 2,455.0 → 1,564.0 ns/op (-36.3%), Arinsal/erts 3.60x → 2.12x (-41.2%)
- **spawn+exit 100k** (sched `1`): Arinsal default 2,753.0 → 1,801.8 ns/op (-34.6%), Arinsal/erts 0.32x → 0.19x (-39.6%)
- **spawn+exit 100k** (sched `default`): Arinsal default 2,728.0 → 1,822.2 ns/op (-33.2%), Arinsal/erts 0.25x → 0.10x (-58.9%)
- **gen_server call** (sched `1`): Arinsal default 6,466.0 → 4,946.4 ns/op (-23.5%), Arinsal/erts 3.19x → 2.39x (-25.1%)
- **gen_server call** (sched `default`): Arinsal default 6,436.0 → 4,940.8 ns/op (-23.2%), Arinsal/erts 6.90x → 5.08x (-26.4%)
- **fan-in 8 producers** (sched `default`): Arinsal default 167.9 → 131.1 ns/op (-21.9%), Arinsal/erts 0.44x → 0.58x (+31.0%)
- **fan-in 8 producers** (sched `1`): Arinsal default 166.2 → 130.3 ns/op (-21.6%), Arinsal/erts 1.56x → 1.17x (-25.2%)

Additionally, JIT execution with `ARINSAL_BEAMASM=1` progressed from failing across almost all kernels (20 FAIL, 1 TIMEOUT, 2 CRASH) to passing 21 of 23 benchmark configurations (only `gen_server call` remains FAIL).

## Benchmark Matrix Table

| kernel | sched | semantics note | erts ns/op | Arinsal default ns/op | Arinsal ARINSAL_BEAMASM=1 ns/op | Go ns/op | Arinsal/erts | Arinsal/Go | Go/erts |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| int loop sum | default | tail recursion vs for-loop, 1..10M, int64 | 1.69 (1.69..1.70) | 8.27 (8.11..8.28) | 8.47 (8.46..8.50) | 0.33 (0.33..0.33) | 4.89x | 24.95x | 0.20x |
| fib(27) | default | naive recursive calls, 635k calls | 2.49 (2.48..2.52) | 5.72 (5.71..5.81) | 73.3 (72.1..74.7) | 1.04 (1.04..1.06) | 2.30x | 5.48x | 0.42x |
| list build+map+fold 100k | default | build+map(+1)+fold; Go: boxed linked list | 32.3 (32.1..37.5) | 265.1 (254.3..268.4) | 290.2 (277.8..291.2) | 38.3 (31.6..42.7) | 8.22x | 6.93x | 1.19x |
| tuple setelement loop | default | setelement(2, Tuple, I) 100k; Go: 3-elem struct copy | 2.25 (2.25..2.35) | 54.4 (54.4..54.5) | 56.8 (56.7..56.9) | 0.32 (0.32..0.34) | 24.19x | 169.43x | 0.14x |
| binary byte scan 1 MiB | default | 1 MiB binary byte-by-byte scan | 2.91 (2.91..2.92) | 52.7 (46.6..74.4) | 45.7 (44.7..47.0) | 0.34 (0.33..0.45) | 18.08x | 153.01x | 0.12x |
| map put/get 100k | default | insert & lookup 100k small ints; Go map[int]int | 300.2 (297.7..374.5) | 766.8 (651.2..811.0) | 718.4 (663.0..721.9) | 42.9 (40.6..49.9) | 2.55x | 17.86x | 0.14x |
| ets hash table | default | insert & lookup 100k items; Go map + sync.Mutex | 298.8 (192.2..326.5) | 500.8 (489.3..561.0) | 546.4 (494.9..555.5) | 51.3 (49.4..59.5) | 1.68x | 9.77x | 0.17x |
| spawn+exit 100k | 1 | spawn 100k, backlog 100k msgs before recv (measures on-heap msgq GC) | 9,319 (9,189..9,378) | 1,802 (1,793..1,827) | 1,712 (1,697..1,718) | 674.9 (500.2..841.7) | 0.19x | 2.67x | 0.07x |
| spawn+exit 100k | default | spawn 100k, backlog 100k msgs before recv (measures on-heap msgq GC) | 17,748 (11,872..22,939) | 1,822 (1,810..1,834) | 1,768 (1,746..1,774) | 653.1 (631.1..937.1) | 0.10x | 2.79x | 0.04x |
| spawn+exit+recv 100k | 1 | spawn 100k, recv each immediately (no backlog, pure spawn+msg roundtrip) | 1,827 (1,816..1,834) | 1,572 (1,561..1,581) | 1,468 (1,449..1,503) | 246.5 (245.8..262.6) | 0.86x | 6.38x | 0.13x |
| spawn+exit+recv 100k | default | spawn 100k, recv each immediately (no backlog, pure spawn+msg roundtrip) | 739.3 (736.9..750.1) | 1,564 (1,556..1,590) | 1,458 (1,444..1,480) | 338.4 (305.6..386.3) | 2.12x | 4.62x | 0.46x |
| ping-pong 1M | 1 | 1M ping-pong round-trips; Go unbuffered chan | 1,573 (1,570..1,620) | 874.3 (868.3..875.8) | 752.9 (750.0..755.5) | 223.0 (221.3..226.1) | 0.56x | 3.92x | 0.14x |
| ping-pong 1M | default | 1M ping-pong round-trips; Go unbuffered chan | 490.6 (485.8..492.3) | 866.9 (863.4..871.0) | 754.0 (750.1..846.7) | 275.7 (265.0..276.2) | 1.77x | 3.14x | 0.56x |
| fan-in 8 producers | 1 | 8 producers x 125k msgs -> 1 consumer | 111.6 (110.9..111.9) | 130.3 (127.9..130.9) | 142.3 (140.0..142.5) | 24.9 (24.9..25.0) | 1.17x | 5.22x | 0.22x |
| fan-in 8 producers | default | 8 producers x 125k msgs -> 1 consumer | 227.6 (201.6..274.9) | 131.1 (130.6..202.3) | 142.0 (141.9..223.1) | 66.2 (64.1..73.5) | 0.58x | 1.98x | 0.29x |
| float math | default | 1M iterations x = x*1.0000001 + 0.5 (boxed float vs Go float64) | 8.04 (7.81..8.08) | 41.2 (40.9..41.5) | 41.1 (40.9..41.3) | 1.32 (1.32..1.32) | 5.13x | 31.30x | 0.16x |
| closure calls | default | 1M calls of captured fun F(X)->X+K via lists:foldl vs Go closure | 3.42 (3.29..3.43) | 87.9 (87.8..88.6) | 99.5 (99.0..101.1) | 0.66 (0.66..0.67) | 25.68x | 132.78x | 0.19x |
| binary build | default | build 1 MiB via <<Acc/binary, B>> (private_append) vs Go append []byte | 4.43 (4.38..4.53) | 67.8 (66.5..68.0) | 67.4 (67.0..67.7) | 1.23 (1.05..1.41) | 15.31x | 55.07x | 0.28x |
| record/tuple update | default | 1M updates of 5-field record (setelement) vs Go struct copy | 2.35 (2.35..2.36) | 65.1 (64.1..69.8) | 64.7 (64.0..65.6) | 3.98 (3.94..4.61) | 27.70x | 16.34x | 1.70x |
| string→atom→string | default | 100k list_to_atom/atom_to_list of existing atoms vs Go map[string]int interning | 102.4 (102.2..111.3) | 1,332 (1,312..1,346) | 1,301 (1,270..1,312) | 9.37 (9.26..9.43) | 13.01x | 142.15x | 0.09x |
| sort 100k ints | default | lists:sort 100k pseudo-random ints (fixed seed) vs Go sort.Ints on copy | 34.8 (33.9..37.2) | 185.6 (177.8..185.9) | 178.1 (177.4..178.6) | 40.4 (38.8..40.7) | 5.34x | 4.59x | 1.16x |
| gen_server call | 1 | 100k gen_server:call round-trips to local server vs Go 2 unbuffered chans | 2,071 (2,066..2,088) | 4,946 (4,922..4,961) | FAIL | 227.6 (225.9..231.9) | 2.39x | 21.73x | 0.11x |
| gen_server call | default | 100k gen_server:call round-trips to local server vs Go 2 unbuffered chans | 972.8 (966.0..977.5) | 4,941 (4,921..4,954) | FAIL | 298.8 (280.7..314.6) | 5.08x | 16.53x | 0.31x |

## Biggest Gaps

### 8 Worst Kernels (highest Arinsal/erts ratio — Arinsal slowest relative to erts)

1. **record/tuple update** (sched default): 27.70x (65.1 ns/op vs 2.35 ns/op)
2. **closure calls** (sched default): 25.68x (87.9 ns/op vs 3.42 ns/op)
3. **tuple setelement loop** (sched default): 24.19x (54.4 ns/op vs 2.25 ns/op)
4. **binary byte scan 1 MiB** (sched default): 18.08x (52.7 ns/op vs 2.91 ns/op)
5. **binary build** (sched default): 15.31x (67.8 ns/op vs 4.43 ns/op)
6. **string→atom→string** (sched default): 13.01x (1,332 ns/op vs 102.4 ns/op)
7. **list build+map+fold 100k** (sched default): 8.22x (265.1 ns/op vs 32.3 ns/op)
8. **sort 100k ints** (sched default): 5.34x (185.6 ns/op vs 34.8 ns/op)

### 5 Best Kernels (lowest Arinsal/erts ratio — Arinsal fastest relative to erts)

By unique kernel:
1. **spawn+exit 100k**: 0.10x (sched default: 1,822 ns/op vs 17,748 ns/op) / 0.19x (sched 1: 1,802 ns/op vs 9,319 ns/op)
2. **ping-pong 1M**: 0.56x (sched 1: 874.3 ns/op vs 1,573 ns/op) / 1.77x (sched default: 866.9 ns/op vs 490.6 ns/op)
3. **fan-in 8 producers**: 0.58x (sched default: 131.1 ns/op vs 227.6 ns/op) / 1.17x (sched 1: 130.3 ns/op vs 111.6 ns/op)
4. **spawn+exit+recv 100k**: 0.86x (sched 1: 1,572 ns/op vs 1,827 ns/op) / 2.12x (sched default: 1,564 ns/op vs 739.3 ns/op)
5. **ets hash table**: 1.68x (sched default: 500.8 ns/op vs 298.8 ns/op)

By individual configuration row:
1. **spawn+exit 100k** (sched default): 0.10x
2. **spawn+exit 100k** (sched 1): 0.19x
3. **ping-pong 1M** (sched 1): 0.56x
4. **fan-in 8 producers** (sched default): 0.58x
5. **spawn+exit+recv 100k** (sched 1): 0.86x

## Previous run (2026-09-27)

- **Date**: 2026-09-27 (Sun Sep 27 16:31:54 CEST 2026)
- **Git Commit**: `9c838cc`
- **Machine**:
  - `hw.model`: `Apple Silicon`
  - Cores: 10 cores (`hw.ncpu: 10`, 8 performance + 2 efficiency)
- **Load Note**:
  - `uptime` before run: `16:31  up 19 days,  6:17, 3 users, load averages: 2.34 1.88 2.18`
  - `uptime` after run: `16:39  up 19 days,  6:25, 3 users, load averages: 1.54 1.55 1.86`
  - Note: Other builds or parallel agent tasks may have been running on the system during execution.

### Benchmark Matrix Table

| kernel | sched | semantics note | erts ns/op | Arinsal default ns/op | Arinsal ARINSAL_BEAMASM=1 ns/op | Go ns/op | Arinsal/erts | Go/erts |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| int loop sum | default | tail recursion vs for-loop, 1..10M, int64 | 1.59 (1.59..1.60) | 8.06 (8.06..8.07) | FAIL | 0.53 (0.45..0.69) | 5.06x | 0.33x |
| fib(27) | default | naive recursive calls, 635k calls | 2.65 (2.65..2.68) | 5.92 (5.91..5.93) | FAIL | 1.02 (1.01..1.02) | 2.23x | 0.38x |
| list build+map+fold 100k | default | build+map(+1)+fold; Go: boxed linked list | 28.9 (28.8..32.5) | 10,297 (10,281..10,301) | FAIL | 37.0 (27.1..51.9) | 356.53x | 1.28x |
| tuple setelement loop | default | setelement(2, Tuple, I) 100k; Go: 3-elem struct copy | 2.21 (2.21..2.21) | 52.2 (52.2..52.6) | FAIL | 0.33 (0.33..0.38) | 23.64x | 0.15x |
| binary byte scan 1 MiB | default | 1 MiB binary byte-by-byte scan | 2.74 (2.74..2.75) | 52.7 (46.8..73.8) | FAIL | 0.33 (0.33..0.35) | 19.20x | 0.12x |
| map put/get 100k | default | insert & lookup 100k small ints; Go map[int]int | 296.7 (296.5..300.4) | 26,523 (26,502..26,576) | FAIL | 39.7 (38.0..43.9) | 89.38x | 0.13x |
| ets hash table | default | insert & lookup 100k items; Go map + sync.Mutex | 185.5 (185.1..186.3) | 1,114 (1,112..1,126) | FAIL | 49.1 (48.1..52.4) | 6.01x | 0.26x |
| spawn+exit 100k | 1 | spawn 100k, backlog 100k msgs before recv (measures on-heap msgq GC) | 8,582 (8,471..8,613) | 2,753 (2,745..2,756) | FAIL | 655.8 (459.2..880.7) | 0.32x | 0.08x |
| spawn+exit 100k | default | spawn 100k, backlog 100k msgs before recv (measures on-heap msgq GC) | 10,952 (9,985..11,344) | 2,728 (2,725..2,736) | FAIL | 461.7 (419.6..481.8) | 0.25x | 0.04x |
| spawn+exit+recv 100k | 1 | spawn 100k, recv each immediately (no backlog, pure spawn+msg roundtrip) | 1,772 (1,767..1,780) | 2,520 (2,511..2,527) | FAIL | 231.2 (229.6..246.0) | 1.42x | 0.13x |
| spawn+exit+recv 100k | default | spawn 100k, recv each immediately (no backlog, pure spawn+msg roundtrip) | 681.7 (680.1..691.6) | 2,455 (2,450..2,463) | FAIL | 303.8 (298.2..305.7) | 3.60x | 0.45x |
| ping-pong 1M | 1 | 1M ping-pong round-trips; Go unbuffered chan | 1,538 (1,538..1,548) | 1,468 (1,467..1,473) | FAIL | 213.0 (211.7..217.3) | 0.95x | 0.14x |
| ping-pong 1M | default | 1M ping-pong round-trips; Go unbuffered chan | 464.7 (464.1..465.1) | 1,472 (1,470..1,474) | FAIL | 262.2 (260.4..263.0) | 3.17x | 0.56x |
| fan-in 8 producers | 1 | 8 producers x 125k msgs -> 1 consumer | 106.2 (105.8..106.5) | 166.2 (165.8..167.1) | FAIL | 23.5 (23.4..23.5) | 1.56x | 0.22x |
| fan-in 8 producers | default | 8 producers x 125k msgs -> 1 consumer | 384.4 (348.7..424.7) | 167.9 (167.8..169.2) | FAIL | 75.2 (62.6..82.9) | 0.44x | 0.20x |
| float math | default | 1M iterations x = x*1.0000001 + 0.5 (boxed float vs Go float64) | 7.71 (7.70..7.75) | 41.8 (41.3..42.0) | FAIL | 1.24 (1.24..1.25) | 5.43x | 0.16x |
| closure calls | default | 1M calls of captured fun F(X)->X+K via lists:foldl vs Go closure | 3.22 (3.21..3.30) | 214.1 (214.1..214.3) | FAIL | 0.62 (0.62..0.63) | 66.50x | 0.19x |
| binary build | default | build 1 MiB via <<Acc/binary, B>> (private_append) vs Go append []byte | 4.29 (4.28..4.31) | 576.4 (571.1..582.9) | FAIL | 1.09 (0.93..1.27) | 134.30x | 0.25x |
| record/tuple update | default | 1M updates of 5-field record (setelement) vs Go struct copy | 2.21 (2.21..2.23) | 58.3 (57.3..62.2) | FAIL | 4.35 (4.34..4.37) | 26.33x | 1.97x |
| string→atom→string | default | 100k list_to_atom/atom_to_list of existing atoms vs Go map[string]int interning | 97.3 (97.1..107.6) | 1,461 (1,457..1,466) | TIMEOUT | 9.11 (9.07..9.13) | 15.02x | 0.09x |
| sort 100k ints | default | lists:sort 100k pseudo-random ints (fixed seed) vs Go sort.Ints on copy | 27.1 (27.0..32.6) | 4,404 (4,387..4,421) | CRASH | 38.2 (38.0..38.3) | 162.46x | 1.41x |
| gen_server call | 1 | 100k gen_server:call round-trips to local server vs Go 2 unbuffered chans | 2,030 (2,026..2,035) | 6,466 (6,457..6,470) | CRASH | 215.3 (213.8..217.0) | 3.19x | 0.11x |
| gen_server call | default | 100k gen_server:call round-trips to local server vs Go 2 unbuffered chans | 932.2 (931.8..932.7) | 6,436 (6,418..6,455) | CRASH | 267.1 (264.1..271.2) | 6.90x | 0.29x |

### Biggest Gaps

#### 8 Worst Kernels (highest Arinsal/erts ratio — Arinsal slowest relative to erts)

1. **list build+map+fold 100k** (sched default): 356.53x (10,297 ns/op vs 28.9 ns/op)
2. **sort 100k ints** (sched default): 162.46x (4,404 ns/op vs 27.1 ns/op)
3. **binary build** (sched default): 134.30x (576.4 ns/op vs 4.29 ns/op)
4. **map put/get 100k** (sched default): 89.38x (26,523 ns/op vs 296.7 ns/op)
5. **closure calls** (sched default): 66.50x (214.1 ns/op vs 3.22 ns/op)
6. **record/tuple update** (sched default): 26.33x (58.3 ns/op vs 2.21 ns/op)
7. **tuple setelement loop** (sched default): 23.64x (52.2 ns/op vs 2.21 ns/op)
8. **binary byte scan 1 MiB** (sched default): 19.20x (52.7 ns/op vs 2.74 ns/op)

#### 5 Best Kernels (lowest Arinsal/erts ratio — Arinsal fastest relative to erts)

By unique kernel:
1. **spawn+exit 100k**: 0.25x (sched default: 2,728 ns/op vs 10,952 ns/op) / 0.32x (sched 1: 2,753 ns/op vs 8,582 ns/op)
2. **fan-in 8 producers**: 0.44x (sched default: 167.9 ns/op vs 384.4 ns/op) / 1.56x (sched 1: 166.2 ns/op vs 106.2 ns/op)
3. **ping-pong 1M**: 0.95x (sched 1: 1,468 ns/op vs 1,538 ns/op) / 3.17x (sched default: 1,472 ns/op vs 464.7 ns/op)
4. **spawn+exit+recv 100k**: 1.42x (sched 1: 2,520 ns/op vs 1,772 ns/op) / 3.60x (sched default: 2,455 ns/op vs 681.7 ns/op)
5. **fib(27)**: 2.23x (sched default: 5.92 ns/op vs 2.65 ns/op)

By individual configuration row:
1. **spawn+exit 100k** (sched default): 0.25x
2. **spawn+exit 100k** (sched 1): 0.32x
3. **fan-in 8 producers** (sched default): 0.44x
4. **ping-pong 1M** (sched 1): 0.95x
5. **spawn+exit+recv 100k** (sched 1): 1.42x
