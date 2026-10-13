#!/usr/bin/env bash
# Boot on a runtime, wait for the API (or death), run the smoke test, stop.
#   scripts/try-boot.sh <runtime> <log-name> [mix_env]
IP=${IP:?set IP to the ingest-profile dir}
rt=$1; name=$2; envn=${3:-dev}
data=$IP/scratch/boot-$name
rm -rf "$data"
log=$IP/logs/boot-$name.log
"$IP/scripts/server.sh" "$rt" "$data" "$envn" > "$log" 2>&1 &
pid=$!
ok=0
for i in $(seq 1 ${WAIT:-120}); do
  if ! kill -0 $pid 2>/dev/null; then echo "DIED after ${i}s"; break; fi
  if curl -s -o /dev/null -w '%{http_code}' -H 'authorization: Bearer bench' http://127.0.0.1:14000/v1/datasets 2>/dev/null | grep -q 200; then ok=1; echo "UP after ${i}s"; break; fi
  sleep 1
done
if [ $ok = 1 ]; then "$IP/scripts/smoke.sh"; fi
if [ -z "${KEEP:-}" ]; then
  pkill -P $pid 2>/dev/null; kill $pid 2>/dev/null
  for p in $(lsof -tiTCP:14000 -sTCP:LISTEN); do kill $p; done
  sleep 1
fi
echo "--- log tail ($log)"; tail -${TAIL:-40} "$log" | cut -c1-400
