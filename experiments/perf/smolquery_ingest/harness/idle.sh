#!/usr/bin/env bash
# Idle memory after boot, no load: boot, create the table, wait, snapshot.
#   scripts/idle.sh <runtime> <tag> [wait_s]
IP=${IP:?set IP to the ingest-profile dir}
rt=$1; tag=$2; w=${3:-30}
out=$IP/results/$tag; data=$IP/scratch/idle-$tag
rm -rf "$out" "$data"; mkdir -p "$out/prof"
for p in $(lsof -tiTCP:14000 -sTCP:LISTEN); do kill $p; done; sleep 1
SQ_PROFILE_DIR=$out/prof "$IP/scripts/server.sh" "$rt" "$data" prod > "$out/server.log" 2>&1 &
pid=$!
for i in $(seq 1 120); do curl -s -o /dev/null -w '%{http_code}' -H 'authorization: Bearer bench' http://127.0.0.1:14000/v1/datasets | grep -q 200 && break; sleep 1; done
"$IP/bin/threadcpu" $pid > "$out/after_boot.json"
sleep "$w"
touch "$out/prof/ctl/idle"; sleep 1
"$IP/bin/threadcpu" $pid > "$out/idle.json"
kill -TERM $pid; for i in $(seq 1 30); do kill -0 $pid 2>/dev/null || break; sleep 1; done; kill -9 $pid 2>/dev/null
rm -rf "$data"
python3 - "$out" <<'PY'
import json,sys
d=sys.argv[1]; s=json.load(open(d+"/idle.json"))
m=[json.loads(l) for l in open(d+"/prof/events.jsonl") if '"mark"' in l][-1]["memory"]
print(d.split("/")[-1], "rss %.0f MiB footprint %.0f MiB maxfp %.0f MiB threads %d | erlang:memory MiB: %s" % (s["rss"]/2**20, s["phys_footprint"]/2**20, s["lifetime_max_phys_footprint"]/2**20, s["nthreads"], {k: round(v/2**20,1) for k,v in m.items() if k in ("total","processes","binary","ets","code","system","atom")}))
PY
