#!/usr/bin/env bash
# One profiling run: fresh data dir, start the instrumented server on a runtime,
# drive the load, stop the server, keep results under results/<tag>/.
#   scripts/run.sh <erts|arinsal-patched> <tag> [extra load.py args...]
set -uo pipefail
IP=${IP:?set IP to the ingest-profile dir}
rt=$1; tag=$2; shift 2
out=$IP/results/$tag
data=$IP/scratch/run-$tag
rm -rf "$out" "$data"; mkdir -p "$out/prof"
for p in $(lsof -tiTCP:14000 -sTCP:LISTEN); do kill $p; done
sleep 1
SQ_PROFILE_DIR=$out/prof RUST_BACKTRACE=1 "$IP/scripts/server.sh" "$rt" "$data" prod > "$out/server.log" 2>&1 &
pid=$!
for i in $(seq 1 120); do
  kill -0 $pid 2>/dev/null || { echo "server died"; tail -30 "$out/server.log"; exit 1; }
  curl -s -o /dev/null -w '%{http_code}' -H 'authorization: Bearer bench' http://127.0.0.1:14000/v1/datasets | grep -q 200 && break
  sleep 1
done
echo "server pid=$pid ($(ps -o comm= -p $pid)) up after ${i}s"
python3 -I "$IP/scripts/load.py" --pid $pid --prof "$out/prof" --out "$out" "$@" 2>&1 | tee "$out/driver.log"
"$IP/bin/threadcpu" $pid > "$out/cpu_end.json" 2>/dev/null
kill -TERM $pid 2>/dev/null
for i in $(seq 1 60); do kill -0 $pid 2>/dev/null || break; sleep 1; done
kill -0 $pid 2>/dev/null && { echo "server did not stop, killing"; kill -9 $pid; }
du -sk "$data" > "$out/data_du.txt"
rm -rf "$data"
echo "done $tag"
