#!/usr/bin/env bash
# Interleaved runs: R rounds of each runtime, same data and settings.
#   scripts/matrix.sh <rounds> <runtime...>
IP=${IP:?set IP to the ingest-profile dir}
rounds=$1; shift
for r in $(seq 1 $rounds); do
  for rt in "$@"; do
    "$IP/scripts/run.sh" "$rt" "full-$rt-$r" --warmup h3:50 --measure h0,h1,h2 --seal-wait ${SEAL_WAIT:-180} 2>&1 | tail -6
  done
done
