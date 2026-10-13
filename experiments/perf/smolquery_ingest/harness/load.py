"""Ingest load driver for one profiling run against a running smolquery.

    python3 -I load.py --pid <beam pid> --prof <SQ_PROFILE_DIR> --out <result dir>
                       [--api http://127.0.0.1:14000] [--workers 8]
                       [--warmup h3:50] [--measure h0,h1,h2] [--seal-wait 0]

Creates bench.hits (bench-matrix's ClickBench schema and clustering key),
posts the warm-up bodies, then the measured bodies, with N concurrent
inserters. Around the measured phase it touches $prof/ctl/start and
$prof/ctl/stop (the in-VM collector writes scheduler/msacc marks) and takes
per-thread CPU snapshots of the server process with bin/threadcpu; a 1 Hz
sampler records RSS/footprint and per-thread CPU over time.

Ack latency is client-measured: request start to full response.
"""
import argparse, http.client, json, os, queue, subprocess, sys, threading, time

IP = os.environ.get("IP") or sys.exit("set IP to the ingest-profile dir")
SCHEMA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "clickbench-schema.json")
THREADCPU = os.path.join(IP, "bin", "threadcpu")

ap = argparse.ArgumentParser()
ap.add_argument("--pid", type=int, required=True)
ap.add_argument("--prof", required=True)
ap.add_argument("--out", required=True)
ap.add_argument("--api", default="http://127.0.0.1:14000")
ap.add_argument("--workers", type=int, default=8)
ap.add_argument("--warmup", default="h3:50")
ap.add_argument("--measure", default="h0,h1,h2")
ap.add_argument("--seal-wait", type=int, default=0)
ap.add_argument("--key", default="bench")
ap.add_argument("--rate", type=float, default=0, help="offered load cap, rows/s (0 = closed loop)")
args = ap.parse_args()
os.makedirs(args.out, exist_ok=True)
host, port = args.api.split("//")[1].split(":")
port = int(port)
AUTH = {"authorization": "Bearer " + args.key}


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def call(method, path, body=None, timeout=600):
    c = http.client.HTTPConnection(host, port, timeout=timeout)
    headers = dict(AUTH)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["content-type"] = "application/json"
    c.request(method, path, body=data, headers=headers)
    r = c.getresponse()
    raw = r.read()
    c.close()
    return r.status, raw


def bodies(spec):
    out = []
    for part in spec.split(","):
        name, _, limit = part.partition(":")
        d = os.path.join(IP, "data", "bodies", name)
        files = sorted(os.listdir(d))
        if limit:
            files = files[: int(limit)]
        for f in files:
            rows = int(f.rsplit("-", 1)[1].split(".")[0])
            out.append((os.path.join(d, f), rows, f"{name}-{f.split('-')[1]}"))
    return out


def snapshot():
    p = subprocess.run([THREADCPU, str(args.pid)], capture_output=True, text=True)
    return json.loads(p.stdout) if p.returncode == 0 else {"error": p.stderr}


def ctl(name):
    d = os.path.join(args.prof, "ctl")
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, name), "w").close()


def run_phase(items, tag):
    q = queue.Queue()
    for it in items:
        q.put(it)
    lat, statuses, lock = [], {}, threading.Lock()
    acc = {"rows": 0, "bytes": 0, "r429": 0, "other": 0, "rejected": 0}
    pace = {"t0": time.monotonic(), "rows": 0}

    def worker():
        conn = http.client.HTTPConnection(host, port, timeout=300)
        while True:
            try:
                path, rows, iid = q.get_nowait()
            except queue.Empty:
                break
            with open(path, "rb") as f:
                raw = f.read()
            if args.rate and tag == "meas":
                with lock:
                    start_at = pace["t0"] + pace["rows"] / args.rate
                    pace["rows"] += rows
                delay = start_at - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
            backoff = 1.0
            for attempt in range(30):
                t0 = time.monotonic()
                try:
                    conn.request("POST", f"/v1/datasets/bench/tables/hits/insert?insertId={tag}-{iid}",
                                 body=raw, headers={**AUTH, "content-type": "application/x-ndjson"})
                    r = conn.getresponse()
                    resp = r.read()
                except Exception as e:  # reconnect and retry
                    log("request error", iid, repr(e))
                    conn.close()
                    conn = http.client.HTTPConnection(host, port, timeout=300)
                    with lock:
                        acc["other"] += 1
                    time.sleep(backoff); backoff = min(backoff * 2, 8)
                    continue
                dt = (time.monotonic() - t0) * 1000
                with lock:
                    statuses[r.status] = statuses.get(r.status, 0) + 1
                if r.status == 200:
                    n = json.loads(resp).get("insertedRows", 0)
                    with lock:
                        lat.append(dt); acc["rows"] += n; acc["bytes"] += len(raw)
                        acc["rejected"] += rows - n
                    break
                if r.status == 429:
                    with lock:
                        acc["r429"] += 1
                    time.sleep(min(float(r.getheader("retry-after") or 1), 5))
                    continue
                log("HTTP", r.status, iid, resp[:300])
                with lock:
                    acc["other"] += 1
                time.sleep(backoff); backoff = min(backoff * 2, 8)
        conn.close()

    t0 = time.monotonic()
    ts = [threading.Thread(target=worker) for _ in range(args.workers)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    el = time.monotonic() - t0
    lat.sort()
    pct = lambda p: lat[min(len(lat) - 1, int(round(p / 100 * (len(lat) - 1))))] if lat else None
    return {"duration_s": el, "rows": acc["rows"], "bytes": acc["bytes"], "rows_per_s": acc["rows"] / el,
            "mib_per_s": acc["bytes"] / el / 1048576, "requests_ok": len(lat), "statuses": statuses,
            "retries_429": acc["r429"], "retries_other": acc["other"], "rows_rejected": acc["rejected"],
            "latency_ms": {"p50": pct(50), "p90": pct(90), "p99": pct(99), "max": lat[-1] if lat else None,
                           "mean": sum(lat) / len(lat) if lat else None},
            "latencies_ms": lat}


def sampler(stop, path):
    with open(path, "w") as f:
        while not stop.is_set():
            s = snapshot()
            f.write(json.dumps(s) + "\n")
            stop.wait(1.0)


def count_rows():
    st, raw = call("POST", "/v1/queries", {"query": "SELECT count(*) AS n FROM bench.hits", "timeoutMs": 600000})
    try:
        return json.loads(raw)["rows"][0]["n"]
    except Exception:
        return {"status": st, "body": raw[:500].decode(errors="replace")}


def hot_files():
    st, raw = call("POST", "/v1/queries", {"query": "SELECT count(*) AS n FROM bench.hits WHERE CounterID = -1", "timeoutMs": 600000})
    try:
        return json.loads(raw)["job"]["statistics"]["hot"]["filesTotal"]
    except Exception:
        return None


schema = json.load(open(SCHEMA))
print(call("POST", "/v1/datasets", {"id": "bench"})[0],
      call("POST", "/v1/datasets/bench/tables", {"id": schema["id"], "schema": schema["schema"]})[0],
      call("PATCH", "/v1/datasets/bench/tables/hits", {"clustering": schema["clustering"]})[0])

result = {"rate": args.rate, "workers": args.workers, "warmup": args.warmup, "measure": args.measure}
if args.warmup:
    log("warm-up", args.warmup)
    w = run_phase(bodies(args.warmup), "warm")
    w.pop("latencies_ms")
    result["warmup_phase"] = w
    log("warm-up done", round(w["rows_per_s"]), "rows/s")
    time.sleep(3)

items = bodies(args.measure)
log("measure", len(items), "bodies")
stop = threading.Event()
th = threading.Thread(target=sampler, args=(stop, os.path.join(args.out, "samples.jsonl")))
ctl("start")
time.sleep(0.5)
result["cpu_start"] = snapshot()
th.start()
m = run_phase(items, "meas")
result["cpu_stop"] = snapshot()
ctl("stop")
stop.set(); th.join()
time.sleep(0.6)
json.dump(m.pop("latencies_ms"), open(os.path.join(args.out, "latencies_ms.json"), "w"))
result["measure_phase"] = m
log("measure done", round(m["rows_per_s"]), "rows/s", "p50", round(m["latency_ms"]["p50"]), "p99", round(m["latency_ms"]["p99"]))

if args.seal_wait:
    t0 = time.monotonic(); left = None
    while time.monotonic() - t0 < args.seal_wait:
        left = hot_files()
        if left == 0:
            break
        time.sleep(5)
    result["seal_wait"] = {"waited_s": time.monotonic() - t0, "hot_files_left": left}
result["count"] = count_rows()
log("count", result["count"])
json.dump(result, open(os.path.join(args.out, "load.json"), "w"), indent=1)
