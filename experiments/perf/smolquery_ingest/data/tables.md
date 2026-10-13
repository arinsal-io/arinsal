<!-- table:runs -->
| run | rows/s | NDJSON MiB/s | ack p50 ms | ack p99 ms | warm-up rows/s | Bandit timeouts | seal attempts ok/error | hot files left after wait |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| full-erts-1 | 390287 | 869 | 167 | 324 | 373017 | 0 | 2/0 | 0 |
| full-erts-2 | 395162 | 880 | 167 | 374 | 366900 | 0 | 2/0 | 0 |
| full-erts-3 | 379627 | 845 | 177 | 364 | 311237 | 0 | 1/2 | 150 |
| full-arinsal-patched-1 | 105817 | 236 | 767 | 1093 | 94014 | 65 | 0/1 | 226 |
| full-arinsal-patched-2 | 105546 | 235 | 765 | 1090 | 86930 | 58 | 0/1 | 222 |
| full-arinsal-patched-3 | 107381 | 239 | 756 | 1199 | 93368 | 52 | 0/1 | 225 |
| full-arinsal-fast-1 | 267976 | 597 | 287 | 470 | 219407 | 56 | 0/1 | 268 |
| full-arinsal-fast-3 | 241333 | 537 | 310 | 556 | 212424 | 69 | 0/1 | 265 |
| full-arinsal-fast-4 | 254917 | 568 | 305 | 479 | 210618 | 34 | 0 | 269 |
| rate90k-erts | 89965 | 200 | 94 | 135 | 286793 | 0 | 1/0 | n/a |
| rate90k-arinsal-patched | 89120 | 198 | 489 | 736 | 92256 | 10 | 0 | n/a |
| rate90k-arinsal-fast | 89720 | 200 | 222 | 346 | 220223 | 12 | 0 | n/a |

<!-- table:cfg_full -->
| config | n | rows/s | ack p50 ms | ack p99 ms | warm-up rows/s | Bandit timeouts |
|---|---:|---:|---:|---:|---:|---:|
| erts | 3 | 390,287 (379,627–395,162) | 167 (167–177) | 364 (324–374) | 366,900 (311,237–373,017) | 0 |
| arinsal-patched | 3 | 105,817 (105,546–107,381) | 765 (756–767) | 1,093 (1,090–1,199) | 93,368 (86,930–94,014) | 58 (52–65) |
| arinsal-fast | 3 | 254,917 (241,333–267,976) | 305 (287–310) | 479 (470–556) | 212,424 (210,618–219,407) | 56 (34–69) |

<!-- table:cfg_rate90k -->
| config | n | rows/s | ack p50 ms | ack p99 ms | Bandit timeouts |
|---|---:|---:|---:|---:|---:|
| erts | 1 | 89,965 | 94 | 135 | 0 |
| arinsal-patched | 1 | 89,120 | 489 | 736 | 10 |
| arinsal-fast | 1 | 89,720 | 222 | 346 | 12 |

<!-- table:flush_size_full -->
| config | n | flushes in window | rows/flush (median) | NDJSON MiB/flush | segment MiB/flush | bodies/flush | task ms (median) |
|---|---:|---:|---:|---:|---:|---:|---:|
| erts | 3 | 151 (150–154) | 20,440 (20,439–20,452) | 45.8 (45.8–45.8) | 2.0 (1.9–2.0) | 2.0 | 148.2 (146.9–153.4) |
| arinsal-patched | 3 | 193 (191–194) | 18,477 (18,469–19,953) | 45.8 (45.8–45.8) | 1.6 (1.5–1.6) | 2.0 | 587.5 (573.1–591.6) |
| arinsal-fast | 3 | 230 (230–231) | 10,522 (10,455–10,542) | 22.9 (22.9–22.9) | 1.3 (1.3–1.3) | 1.0 | 121.0 (114.5–141.4) |

<!-- table:flush_parts_full -->
| part: median ms / mean ms (share of mean task_us) | erts | arinsal-patched | arinsal-fast |
|---|---:|---:|---:|
| spool write | 5.6 / 6.5 (4.0%) | 456.4 / 348.7 (71.8%) | 7.5 / 10.3 (7.2%) |
| probe | 0.0 / 0.0 (0.0%) | 0.0 / 0.0 (0.0%) | 0.0 / 0.0 (0.0%) |
| DuckDB COPY | 105.8 / 110.0 (66.6%) | 96.4 / 91.8 (18.9%) | 71.3 / 83.1 (58.6%) |
| footer row count | 0.7 / 14.9 (9.0%) | 0.9 / 5.1 (1.1%) | 1.0 / 9.4 (6.5%) |
| stats query | 26.9 / 29.8 (17.7%) | 28.7 / 32.8 (6.8%) | 25.6 / 30.2 (22.1%) |
| Store.put fsync | 0.7 / 0.9 (0.6%) | 3.9 / 4.0 (0.8%) | 4.1 / 4.8 (3.5%) |
| Store.put link | 0.3 / 0.5 (0.3%) | 0.3 / 0.4 (0.1%) | 0.4 / 0.5 (0.3%) |
| Store.put other | 1.1 / 2.2 (1.4%) | 1.0 / 1.7 (0.4%) | 1.0 / 1.1 (0.8%) |
| spool delete | 1.0 / 1.2 (0.7%) | 0.5 / 0.6 (0.1%) | 0.6 / 0.8 (0.5%) |
| other in task | 0.0 / 0.0 (0.0%) | 0.1 / 0.1 (0.0%) | 0.1 / 0.1 (0.1%) |
| **task_us (whole flush)** | **148.2 / 166.4** | **587.5 / 485.5** | **121.0 / 141.8** |

<!-- table:flush_permib_full -->
| ms per NDJSON MiB of the flush (median over flushes) | erts | arinsal-patched | arinsal-fast |
|---|---:|---:|---:|
| whole task | 3.27 | 14.05 | 4.61 |
| spool write | 0.13 | 10.10 | 0.30 |
| DuckDB COPY | 2.36 | 2.61 | 2.75 |
| stats query | 0.60 | 0.96 | 1.00 |

<!-- table:flush_size_rate90k -->
| config | n | flushes in window | rows/flush (median) | NDJSON MiB/flush | segment MiB/flush | bodies/flush | task ms (median) |
|---|---:|---:|---:|---:|---:|---:|---:|
| erts | 1 | 294 | 10,229 | 22.9 | 1.0 | 1.0 | 73.8 |
| arinsal-patched | 1 | 292 | 10,230 | 22.9 | 1.0 | 1.0 | 333.2 |
| arinsal-fast | 1 | 292 | 10,230 | 22.9 | 1.0 | 1.0 | 95.0 |

<!-- table:flush_parts_rate90k -->
| part: median ms / mean ms (share of mean task_us) | erts | arinsal-patched | arinsal-fast |
|---|---:|---:|---:|
| spool write | 2.6 / 2.8 (3.7%) | 231.2 / 232.7 (68.0%) | 6.2 / 6.3 (6.4%) |
| probe | 0.0 / 0.0 (0.0%) | 0.0 / 0.0 (0.0%) | 0.0 / 0.0 (0.0%) |
| DuckDB COPY | 50.9 / 51.1 (68.7%) | 64.8 / 69.5 (20.3%) | 59.2 / 61.8 (62.0%) |
| footer row count | 0.6 / 0.7 (0.9%) | 0.9 / 3.3 (1.0%) | 0.8 / 2.6 (2.6%) |
| stats query | 16.4 / 16.8 (22.6%) | 25.9 / 30.0 (8.8%) | 20.9 / 22.9 (23.0%) |
| Store.put fsync | 1.0 / 1.1 (1.4%) | 4.0 / 3.9 (1.2%) | 4.0 / 4.1 (4.1%) |
| Store.put link | 0.3 / 0.4 (0.5%) | 0.3 / 0.5 (0.2%) | 0.3 / 0.3 (0.3%) |
| Store.put other | 0.8 / 1.0 (1.4%) | 1.0 / 1.8 (0.5%) | 0.9 / 1.0 (1.0%) |
| spool delete | 0.5 / 0.5 (0.7%) | 0.5 / 0.5 (0.1%) | 0.5 / 0.5 (0.5%) |
| other in task | 0.0 / 0.0 (0.1%) | 0.1 / 0.1 (0.0%) | 0.1 / 0.1 (0.1%) |
| **task_us (whole flush)** | **73.8 / 74.3** | **333.2 / 342.4** | **95.0 / 99.7** |

<!-- table:flush_permib_rate90k -->
| ms per NDJSON MiB of the flush (median over flushes) | erts | arinsal-patched | arinsal-fast |
|---|---:|---:|---:|
| whole task | 3.26 | 14.56 | 4.16 |
| spool write | 0.11 | 10.10 | 0.27 |
| DuckDB COPY | 2.24 | 2.83 | 2.59 |
| stats query | 0.72 | 1.13 | 0.92 |

<!-- table:flush_runs -->
| run | flushes | rows/flush | NDJSON MiB/flush | task ms | spool ms | COPY ms | stats ms | footer ms | spool delete ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| full-erts-1 | 151 | 20440 | 45.8 | 146.9 | 5.6 | 105.8 | 26.4 | 0.7 | 1.0 |
| full-erts-2 | 150 | 20452 | 45.8 | 148.2 | 5.5 | 105.7 | 27.1 | 0.7 | 1.0 |
| full-erts-3 | 154 | 20439 | 45.8 | 153.4 | 6.1 | 109.6 | 26.9 | 0.8 | 1.1 |
| full-arinsal-patched-1 | 194 | 18469 | 45.8 | 587.5 | 456.4 | 96.9 | 28.7 | 0.9 | 0.4 |
| full-arinsal-patched-2 | 191 | 19953 | 45.8 | 591.6 | 459.3 | 96.4 | 28.4 | 0.9 | 0.5 |
| full-arinsal-patched-3 | 193 | 18477 | 45.8 | 573.1 | 442.5 | 94.8 | 28.7 | 0.9 | 0.7 |
| full-arinsal-fast-1 | 230 | 10542 | 22.9 | 114.5 | 7.5 | 67.4 | 25.5 | 1.0 | 0.5 |
| full-arinsal-fast-3 | 230 | 10522 | 22.9 | 141.4 | 8.8 | 72.2 | 25.6 | 1.0 | 0.6 |
| full-arinsal-fast-4 | 231 | 10455 | 22.9 | 121.0 | 7.5 | 71.3 | 25.6 | 1.1 | 0.6 |
| rate90k-erts | 294 | 10229 | 22.9 | 73.8 | 2.6 | 50.9 | 16.4 | 0.6 | 0.5 |
| rate90k-arinsal-patched | 292 | 10230 | 22.9 | 333.2 | 231.2 | 64.8 | 25.9 | 0.9 | 0.5 |
| rate90k-arinsal-fast | 292 | 10230 | 22.9 | 95.0 | 6.2 | 59.2 | 20.9 | 0.8 | 0.5 |

<!-- table:cpu_window_full -->
| thread class | erts | arinsal-patched | arinsal-fast |
|---|---:|---:|---:|
| normal schedulers (erts_sched_N / N_scheduler) | 4.6 (4.5–5.1) s, 13% | 105.2 (102.1–105.5) s, 79% | 33.5 (32.7–34.4) s, 50% |
| dirty CPU (erts_dcpus_N / N_dirty_cpu_scheduler) | 0.0 (0.0–0.0) s, 0% | 0.2 (0.2–0.2) s, 0% | 0.2 (0.2–0.2) s, 0% |
| dirty IO (erts_dios_N / N_dirty_io_scheduler) | 26.4 (25.7–26.7) s, 68% | 20.0 (19.8–22.3) s, 15% | 21.7 (21.5–22.0) s, 33% |
| poll / check-io (erts_poll_N / arinsal-check-io) | 0.0 (0.0–0.0) s, 0% | 2.0 (1.8–2.5) s, 2% | 3.8 (3.6–4.2) s, 6% |
| arinsal-inet | 0.0 s, 0% | 4.8 (4.8–5.4) s, 4% | 6.6 (6.3–6.8) s, 10% |
| other runtime threads (aux, async, dispatch, main, arinsal-*) | 0.0 (0.0–0.1) s, 0% | 0.0 (0.0–0.0) s, 0% | 0.0 (0.0–0.0) s, 0% |
| native unnamed (DuckDB, Polars) | 8.0 (2.0–9.5) s, 20% | 0.1 (0.1–0.1) s, 0% | 0.1 (0.1–0.2) s, 0% |
| exited threads (process total minus live threads) | 0.0 (0.0–0.0) s, 0% | 0.0 (0.0–0.0) s, 0% | 0.0 (0.0–0.0) s, 0% |
| **total process CPU** | **39.4 (33.1–40.4) s** | **132.4 (131.3–133.4) s** | **66.3 (65.0–66.8) s** |

<!-- table:cpu_window_rate90k -->
| thread class | erts | arinsal-patched | arinsal-fast |
|---|---:|---:|---:|
| normal schedulers (erts_sched_N / N_scheduler) | 5.5 s, 6% | 108.4 s, 79% | 36.5 s, 39% |
| dirty CPU (erts_dcpus_N / N_dirty_cpu_scheduler) | 0.0 s, 0% | 0.2 s, 0% | 0.2 s, 0% |
| dirty IO (erts_dios_N / N_dirty_io_scheduler) | 51.4 s, 56% | 22.8 s, 17% | 22.3 s, 24% |
| poll / check-io (erts_poll_N / arinsal-check-io) | 0.0 s, 0% | 1.5 s, 1% | 17.9 s, 19% |
| arinsal-inet | 0.0 s, 0% | 4.9 s, 4% | 16.3 s, 17% |
| other runtime threads (aux, async, dispatch, main, arinsal-*) | 0.1 s, 0% | 0.0 s, 0% | 0.0 s, 0% |
| native unnamed (DuckDB, Polars) | 35.2 s, 38% | 0.1 s, 0% | 0.1 s, 0% |
| exited threads (process total minus live threads) | 0.0 s, 0% | 0.0 s, 0% | 0.0 s, 0% |
| **total process CPU** | **92.2 s** | **138.0 s** | **93.4 s** |

<!-- table:cpu_lifetime_full -->
| thread class | erts | arinsal-patched | arinsal-fast |
|---|---:|---:|---:|
| normal schedulers (erts_sched_N / N_scheduler) | 12.2 (12.2–17.4) s, 6% | 159.7 (156.1–160.4) s, 43% | 79.9 (58.3–81.1) s, 26% |
| dirty CPU (erts_dcpus_N / N_dirty_cpu_scheduler) | 0.5 (0.5–0.7) s, 0% | 10.9 (10.6–11.2) s, 3% | 16.7 (6.1–17.7) s, 5% |
| dirty IO (erts_dios_N / N_dirty_io_scheduler) | 80.8 (78.5–95.5) s, 42% | 27.7 (27.5–148.1) s, 7% | 29.8 (27.5–41.1) s, 13% |
| poll / check-io (erts_poll_N / arinsal-check-io) | 0.0 (0.0–0.0) s, 0% | 93.5 (91.8–94.3) s, 25% | 97.5 (46.6–101.9) s, 31% |
| arinsal-inet | 0.0 s, 0% | 67.5 (64.9–70.9) s, 18% | 70.6 (34.4–72.1) s, 23% |
| other runtime threads (aux, async, dispatch, main, arinsal-*) | 0.1 (0.1–0.2) s, 0% | 0.1 (0.1–0.1) s, 0% | 0.1 (0.1–0.1) s, 0% |
| native unnamed (DuckDB, Polars) | 89.3 (74.2–104.4) s, 47% | 0.7 (0.6–0.8) s, 0% | 0.8 (0.5–0.8) s, 0% |
| exited threads (process total minus live threads) | 7.7 (7.5–11.5) s, 4% | 9.9 (9.7–10.1) s, 3% | 9.6 (4.9–9.6) s, 3% |
| **total process CPU** | **199.6 (190.3–203.5) s** | **374.1 (368.0–485.4) s** | **311.6 (178.4–317.8) s** |

<!-- table:cpu_lifetime_rate90k -->
| thread class | erts | arinsal-patched | arinsal-fast |
|---|---:|---:|---:|
| normal schedulers (erts_sched_N / N_scheduler) | 8.4 s, 8% | 133.1 s, 77% | 49.0 s, 42% |
| dirty CPU (erts_dcpus_N / N_dirty_cpu_scheduler) | 0.0 s, 0% | 0.3 s, 0% | 0.3 s, 0% |
| dirty IO (erts_dios_N / N_dirty_io_scheduler) | 57.0 s, 55% | 27.1 s, 16% | 26.8 s, 23% |
| poll / check-io (erts_poll_N / arinsal-check-io) | 0.0 s, 0% | 3.5 s, 2% | 20.0 s, 17% |
| arinsal-inet | 0.0 s, 0% | 7.0 s, 4% | 18.5 s, 16% |
| other runtime threads (aux, async, dispatch, main, arinsal-*) | 0.1 s, 0% | 0.1 s, 0% | 0.1 s, 0% |
| native unnamed (DuckDB, Polars) | 36.3 s, 35% | 0.3 s, 0% | 0.3 s, 0% |
| exited threads (process total minus live threads) | 2.3 s, 2% | 2.4 s, 1% | 2.2 s, 2% |
| **total process CPU** | **104.2 s** | **173.8 s** | **117.4 s** |

<!-- table:cpu_after_full -->
| thread class | erts | arinsal-patched | arinsal-fast |
|---|---:|---:|---:|
| normal schedulers (erts_sched_N / N_scheduler) | 5.3 (5.2–9.7) s, 3% | 33.4 (33.1–34.3) s, 16% | 38.4 (15.1–38.7) s, 16% |
| dirty CPU (erts_dcpus_N / N_dirty_cpu_scheduler) | 0.5 (0.5–0.7) s, 0% | 10.7 (10.4–11.0) s, 5% | 16.5 (5.9–17.5) s, 7% |
| dirty IO (erts_dios_N / N_dirty_io_scheduler) | 50.3 (47.7–65.4) s, 34% | 3.7 (3.6–121.6) s, 2% | 3.5 (1.4–15.3) s, 2% |
| poll / check-io (erts_poll_N / arinsal-check-io) | 0.0 (0.0–0.0) s, 0% | 90.9 (89.9–92.2) s, 43% | 93.6 (42.9–97.7) s, 43% |
| arinsal-inet | 0.0 s, 0% | 62.1 (59.5–64.9) s, 29% | 63.1 (27.4–64.8) s, 28% |
| other runtime threads (aux, async, dispatch, main, arinsal-*) | 0.0 (0.0–0.1) s, 0% | 0.0 s, 0% | 0.0 s, 0% |
| native unnamed (DuckDB, Polars) | 87.1 (64.5–96.3) s, 58% | 0.5 (0.4–0.5) s, 0% | 0.4 (0.2–0.5) s, 0% |
| exited threads (process total minus live threads) | 6.1 (5.8–9.8) s, 4% | 8.2 (8.1–8.4) s, 4% | 8.0 (3.2–8.0) s, 3% |
| **total process CPU** | **150.3 (148.9–155.9) s** | **213.1 (207.7–326.6) s** | **228.8 (96.1–237.0) s** |

<!-- table:cpu_after_rate90k -->
| thread class | erts | arinsal-patched | arinsal-fast |
|---|---:|---:|---:|
| normal schedulers (erts_sched_N / N_scheduler) | 0.4 s, 12% | 3.5 s, 45% | 3.7 s, 46% |
| dirty CPU (erts_dcpus_N / N_dirty_cpu_scheduler) | 0.0 s, 0% | 0.0 s, 0% | 0.0 s, 0% |
| dirty IO (erts_dios_N / N_dirty_io_scheduler) | 1.2 s, 38% | 0.2 s, 2% | 0.2 s, 2% |
| poll / check-io (erts_poll_N / arinsal-check-io) | 0.0 s, 0% | 2.0 s, 25% | 2.1 s, 25% |
| arinsal-inet | 0.0 s, 0% | 1.5 s, 19% | 1.5 s, 19% |
| other runtime threads (aux, async, dispatch, main, arinsal-*) | 0.0 s, 1% | 0.0 s, 0% | 0.0 s, 0% |
| native unnamed (DuckDB, Polars) | 0.9 s, 29% | 0.0 s, 0% | 0.0 s, 0% |
| exited threads (process total minus live threads) | 0.6 s, 20% | 0.6 s, 8% | 0.6 s, 7% |
| **total process CPU** | **3.2 s** | **7.9 s** | **8.1 s** |

<!-- table:cpu_runs -->
| run | pre-window CPU s | window CPU s | window wall s | window cores | window CPU s per 1M rows | after-window CPU s | after wall s | after cores | lifetime CPU s (cpu_end.json) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| full-erts-1 | 8.3 | 33.1 | 7.7 | 4.30 | 11.03 | 148.9 | 124 | 1.20 | 190.3 |
| full-erts-2 | 8.1 | 39.4 | 7.6 | 5.18 | 13.13 | 155.9 | 125 | 1.25 | 203.5 |
| full-erts-3 | 8.8 | 40.4 | 7.9 | 5.11 | 13.46 | 150.3 | 182 | 0.83 | 199.6 |
| full-arinsal-patched-1 | 27.6 | 133.4 | 28.4 | 4.70 | 44.47 | 213.1 | 187 | 1.14 | 374.1 |
| full-arinsal-patched-2 | 27.9 | 132.4 | 28.4 | 4.66 | 44.14 | 207.7 | 182 | 1.14 | 368.0 |
| full-arinsal-patched-3 | 27.5 | 131.3 | 27.9 | 4.70 | 43.77 | 326.6 | 182 | 1.79 | 485.4 |
| full-arinsal-fast-1 | 15.8 | 65.0 | 11.2 | 5.81 | 21.67 | 237.0 | 185 | 1.28 | 317.8 |
| full-arinsal-fast-3 | 15.9 | 66.8 | 12.4 | 5.37 | 22.27 | 228.8 | 186 | 1.23 | 311.6 |
| full-arinsal-fast-4 | 15.9 | 66.3 | 11.8 | 5.63 | 22.11 | 96.1 | 68 | 1.42 | 178.4 |
| rate90k-erts | 8.7 | 92.2 | 33.4 | 2.76 | 30.74 | 3.2 | 1 | 3.55 | 104.2 |
| rate90k-arinsal-patched | 28.0 | 138.0 | 33.7 | 4.10 | 45.99 | 7.9 | 3 | 2.44 | 173.8 |
| rate90k-arinsal-fast | 15.9 | 93.4 | 33.4 | 2.79 | 31.12 | 8.1 | 3 | 2.42 | 117.4 |

<!-- table:cpu_cfg_full -->
| config | n | pre-window s | window s | window cores | window s per 1M rows | after-window s | lifetime s |
|---|---:|---:|---:|---:|---:|---:|---:|
| erts | 3 | 8.3 (8.1–8.8) | 39.4 (33.1–40.4) | 5.11 (4.30–5.18) | 13.1 (11.0–13.5) | 150.3 (148.9–155.9) | 199.6 (190.3–203.5) |
| arinsal-patched | 3 | 27.6 (27.5–27.9) | 132.4 (131.3–133.4) | 4.70 (4.66–4.70) | 44.1 (43.8–44.5) | 213.1 (207.7–326.6) | 374.1 (368.0–485.4) |
| arinsal-fast | 3 | 15.9 (15.8–15.9) | 66.3 (65.0–66.8) | 5.63 (5.37–5.81) | 22.1 (21.7–22.3) | 228.8 (96.1–237.0) | 311.6 (178.4–317.8) |

<!-- table:cpu_cfg_rate90k -->
| config | n | pre-window s | window s | window cores | window s per 1M rows | after-window s | lifetime s |
|---|---:|---:|---:|---:|---:|---:|---:|
| erts | 1 | 8.7 | 92.2 | 2.76 | 30.7 | 3.2 | 104.2 |
| arinsal-patched | 1 | 28.0 | 138.0 | 4.10 | 46.0 | 7.9 | 173.8 |
| arinsal-fast | 1 | 15.9 | 93.4 | 2.79 | 31.1 | 8.1 | 117.4 |

<!-- table:threads_full -->
| config | thread name (digits -> N) | window CPU s, summed over threads |
|---|---|---:|
| erts | erts_dios_N | 26.4 (25.7–26.7) |
| erts | (unnamed) | 8.0 (2.0–9.5) |
| erts | erts_sched_N | 4.6 (4.5–5.1) |
| erts | erts_aux_N | 0.0 (0.0–0.1) |
| erts | erts_dcpus_N | 0.0 (0.0–0.0) |
| erts | erts_poll_N | 0.0 (0.0–0.0) |
| erts | erts_ssig_disp | 0.0 |
| erts | erts_smsg_disp | 0.0 |
| arinsal-patched | N_scheduler | 105.2 (102.1–105.5) |
| arinsal-patched | N_dirty_io_scheduler | 20.0 (19.8–22.3) |
| arinsal-patched | arinsal-inet | 4.8 (4.8–5.4) |
| arinsal-patched | arinsal-check-io | 2.0 (1.8–2.5) |
| arinsal-patched | N_dirty_cpu_scheduler | 0.2 (0.2–0.2) |
| arinsal-patched | (unnamed) | 0.1 (0.1–0.1) |
| arinsal-patched | arinsal-port-N | 0.0 (0.0–0.0) |
| arinsal-patched | main | 0.0 |
| arinsal-fast | N_scheduler | 33.5 (32.7–34.4) |
| arinsal-fast | N_dirty_io_scheduler | 21.7 (21.5–22.0) |
| arinsal-fast | arinsal-inet | 6.6 (6.3–6.8) |
| arinsal-fast | arinsal-check-io | 3.8 (3.6–4.2) |
| arinsal-fast | N_dirty_cpu_scheduler | 0.2 (0.2–0.2) |
| arinsal-fast | (unnamed) | 0.1 (0.1–0.2) |
| arinsal-fast | arinsal-port-N | 0.0 (0.0–0.0) |
| arinsal-fast | main | 0.0 |

<!-- table:threads_rate90k -->
| config | thread name (digits -> N) | window CPU s, summed over threads |
|---|---|---:|
| erts | erts_dios_N | 51.4 |
| erts | (unnamed) | 35.2 |
| erts | erts_sched_N | 5.5 |
| erts | erts_aux_N | 0.1 |
| erts | erts_dcpus_N | 0.0 |
| erts | erts_poll_N | 0.0 |
| erts | erts_ssig_disp | 0.0 |
| erts | erts_smsg_disp | 0.0 |
| arinsal-patched | N_scheduler | 108.4 |
| arinsal-patched | N_dirty_io_scheduler | 22.8 |
| arinsal-patched | arinsal-inet | 4.9 |
| arinsal-patched | arinsal-check-io | 1.5 |
| arinsal-patched | N_dirty_cpu_scheduler | 0.2 |
| arinsal-patched | (unnamed) | 0.1 |
| arinsal-patched | arinsal-port-N | 0.0 |
| arinsal-patched | main | 0.0 |
| arinsal-fast | N_scheduler | 36.5 |
| arinsal-fast | N_dirty_io_scheduler | 22.3 |
| arinsal-fast | arinsal-check-io | 17.9 |
| arinsal-fast | arinsal-inet | 16.3 |
| arinsal-fast | N_dirty_cpu_scheduler | 0.2 |
| arinsal-fast | (unnamed) | 0.1 |
| arinsal-fast | arinsal-port-N | 0.0 |
| arinsal-fast | main | 0.0 |

<!-- table:idle -->
| config | idle footprint MiB | idle RSS MiB | after-boot footprint MiB | boot CPU s | CPU s while idle | idle interval s | idle cores | erlang:memory total MiB | processes MiB | ets MiB | atom MiB | threads |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| erts | 172 | 211 | 180 | 3.4 | 1.92 | 31 | 0.062 | 76 | 21 | 1.8 | 1.0 | 156 |
| arinsal-patched | 481 | 622 | 480 | 6.0 | 2.89 | 31 | 0.093 | 33 | 10 | 1.3 | 2.1 | 156 |
| arinsal-fast | 482 | 617 | 481 | 5.8 | 2.83 | 31 | 0.091 | 33 | 10 | 1.3 | 2.1 | 156 |

<!-- table:mem_runs -->
| run | peak footprint in window MiB (1 Hz) | peak RSS in window MiB | lifetime max footprint MiB | footprint at end MiB | RSS at end MiB | erlang:memory total peak in window MiB (5 Hz) |
|---|---:|---:|---:|---:|---:|---:|
| full-erts-1 | 2885 | 3584 | 2997 | 375 | 3149 | 415 |
| full-erts-2 | 3130 | 3741 | 3166 | 406 | 3420 | 390 |
| full-erts-3 | 2560 | 3918 | 2638 | 1741 | 2979 | 423 |
| full-arinsal-patched-1 | 2001 | 3264 | 2350 | 2048 | 3421 | 520 |
| full-arinsal-patched-2 | 1839 | 3021 | 2205 | 1844 | 3144 | 630 |
| full-arinsal-patched-3 | 1900 | 3153 | 2172 | 1924 | 3347 | 471 |
| full-arinsal-fast-1 | 2418 | 3457 | 2783 | 2194 | 2637 | 616 |
| full-arinsal-fast-3 | 2205 | 2776 | 2495 | 2188 | 2813 | 602 |
| full-arinsal-fast-4 | 2088 | 3108 | 2358 | 2025 | 2442 | 633 |
| rate90k-erts | 2542 | 3745 | 2583 | 1832 | 3456 | 335 |
| rate90k-arinsal-patched | 1986 | 3180 | 2012 | 2012 | 3265 | 482 |
| rate90k-arinsal-fast | 1751 | 3065 | 1819 | 1740 | 3083 | 619 |

<!-- table:mem_cfg_full -->
| config | n | peak footprint in window | peak RSS in window | lifetime max footprint | footprint at end | RSS at end | erlang:memory peak in window |
|---|---:|---:|---:|---:|---:|---:|---:|
| erts | 3 | 2,885 (2,560–3,130) | 3,741 (3,584–3,918) | 2,997 (2,638–3,166) | 406 (375–1,741) | 3,149 (2,979–3,420) | 415 (390–423) |
| arinsal-patched | 3 | 1,900 (1,839–2,001) | 3,153 (3,021–3,264) | 2,205 (2,172–2,350) | 1,924 (1,844–2,048) | 3,347 (3,144–3,421) | 520 (471–630) |
| arinsal-fast | 3 | 2,205 (2,088–2,418) | 3,108 (2,776–3,457) | 2,495 (2,358–2,783) | 2,188 (2,025–2,194) | 2,637 (2,442–2,813) | 616 (602–633) |

<!-- table:mem_cfg_rate90k -->
| config | n | peak footprint in window | peak RSS in window | lifetime max footprint | footprint at end | RSS at end | erlang:memory peak in window |
|---|---:|---:|---:|---:|---:|---:|---:|
| erts | 1 | 2,542 | 3,745 | 2,583 | 1,832 | 3,456 | 335 |
| arinsal-patched | 1 | 1,986 | 3,180 | 2,012 | 2,012 | 3,265 | 482 |
| arinsal-fast | 1 | 1,751 | 3,065 | 1,819 | 1,740 | 3,083 | 619 |

<!-- table:erlang_memory_rate90k -->
| config | total | processes | binary | ets | system | code | atom |
|---|---:|---:|---:|---:|---:|---:|---:|
| erts | 334 | 76 | 209 | 10 | 270 | 19 | 1 |
| arinsal-patched | 510 | 41 | 443 | 12 | 474 | 21 | 2 |
| arinsal-fast | 641 | 50 | 570 | 12 | 602 | 21 | 2 |

<!-- table:seals -->
| run | attempt | result | segments | start, s after window start | duration s |
|---|---:|---:|---:|---:|---:|
| full-erts-1 | 1 | ok | 28 | 0.8 | 14.8 |
| full-erts-1 | 2 | ok | 148 | 15.6 | 110.9 |
| full-erts-2 | 1 | ok | 29 | 0.7 | 15.0 |
| full-erts-2 | 2 | ok | 147 | 15.7 | 114.3 |
| full-erts-3 | 1 | ok | 32 | 0.7 | 3.2 |
| full-erts-3 | 2 | error | 68 | 3.9 | 37.7 |
| full-erts-3 | 3 | error | 68 | 95.5 | 29.9 |
| full-arinsal-patched-1 | 1 | error | 36 | 1.7 | 143.7 |
| full-arinsal-patched-2 | 1 | error | 34 | 2.0 | 144.7 |
| full-arinsal-patched-3 | 1 | error | 35 | 1.9 | 144.8 |
| full-arinsal-fast-1 | 1 | error | 41 | 1.0 | 121.1 |
| full-arinsal-fast-3 | 1 | error | 38 | 0.9 | 122.3 |
| full-arinsal-fast-4 | - | no attempt finished | - | - | - |
| rate90k-erts | 1 | ok | 31 | 1.0 | 14.4 |
| rate90k-arinsal-patched | - | no attempt finished | - | - | - |
| rate90k-arinsal-fast | - | no attempt finished | - | - | - |

<!-- table:seal_runs -->
| run | seal attempts | ok | error | sealed segments | sealed rows | sealed MiB | seal wait s | hot files left | Bandit timeouts | first, s after measure start | last | bursts | burst sizes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| full-erts-1 | 2 | 2 | 0 | 2 | 3488010 | 360 | 118 | 0 | 0 | n/a | n/a | 0 | - |
| full-erts-2 | 2 | 2 | 0 | 2 | 3488010 | 360 | 123 | 0 | 0 | n/a | n/a | 0 | - |
| full-erts-3 | 3 | 1 | 2 | 1 | 538086 | 60 | 181 | 150 | 0 | n/a | n/a | 0 | - |
| full-arinsal-patched-1 | 1 | 0 | 1 | 0 | 0 | 0 | 185 | 226 | 65 | 56 | 244 | 6 | 12/12/10/9/12/10 |
| full-arinsal-patched-2 | 1 | 0 | 1 | 0 | 0 | 0 | 180 | 222 | 58 | 57 | 213 | 5 | 12/12/12/10/12 |
| full-arinsal-patched-3 | 1 | 0 | 1 | 0 | 0 | 0 | 181 | 225 | 52 | 57 | 213 | 5 | 10/10/10/10/12 |
| full-arinsal-fast-1 | 1 | 0 | 1 | 0 | 0 | 0 | 183 | 268 | 56 | 33 | 216 | 6 | 9/9/8/8/12/10 |
| full-arinsal-fast-3 | 1 | 0 | 1 | 0 | 0 | 0 | 184 | 265 | 69 | 33 | 216 | 6 | 12/12/12/12/11/10 |
| full-arinsal-fast-4 | 0 | 0 | 0 | 0 | 0 | 0 | 65 | 269 | 34 | 35 | 95 | 3 | 12/11/11 |
| rate90k-erts | 1 | 1 | 0 | 1 | 538081 | 60 | n/a | n/a | 0 | n/a | n/a | 0 | - |
| rate90k-arinsal-patched | 0 | 0 | 0 | 0 | 0 | 0 | n/a | n/a | 10 | 64 | 64 | 1 | 10 |
| rate90k-arinsal-fast | 0 | 0 | 0 | 0 | 0 | 0 | n/a | n/a | 12 | 32 | 32 | 1 | 12 |

