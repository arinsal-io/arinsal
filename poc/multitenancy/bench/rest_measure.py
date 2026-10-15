import subprocess, time, re, json, os, sys, http.client, statistics
HERE = os.path.dirname(os.path.abspath(__file__))
REL = f"{HERE}/rest/_build/prod/rel/rt/bin/rt"
PATHX = "/opt/homebrew/opt/erlang@29/bin:/opt/homebrew/opt/elixir/bin:" + os.environ["PATH"]
TUNED = "+S 1:1 +SDcpu 1:1 +SDio 1 +sbwt none +sbwtdcpu none +sbwtdio none"
SNAP = f"{HERE}/snap_rest"; os.makedirs(SNAP, exist_ok=True); os.makedirs(f"{HERE}/logs", exist_ok=True)

def descendants(pid):
    kids = [int(p) for p in subprocess.run(["pgrep", "-P", str(pid)], capture_output=True, text=True).stdout.split()]
    return [pid] + [d for k in kids for d in descendants(k)]

def cpu_s(pid):
    t = subprocess.run(["ps", "-o", "time=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
    s = 0
    for x in (t.split(":") if t else ["0"]): s = s * 60 + float(x)
    return s

def footprint_kb(pid):
    out = subprocess.run(["footprint", "-p", str(pid)], capture_output=True, text=True).stdout
    m = re.search(r"Footprint: ([\d.]+) (KB|MB|GB)", out)
    return float(m.group(1)) * {"KB": 1, "MB": 1024, "GB": 1048576}[m.group(2)] if m else 0

def idlew(pid):
    lines = subprocess.run(["top", "-l", "1", "-pid", str(pid), "-stats", "pid,idlew"], capture_output=True, text=True).stdout.strip().splitlines()
    return int(lines[-1].split()[1].rstrip("+")) if lines and lines[-1].split()[0] == str(pid) else 0

def sample(roots):
    ps = [p for r in roots for p in descendants(r)]
    ps = [p for p in ps if "beam.smp" in subprocess.run(["ps", "-o", "comm=", "-p", str(p)], capture_output=True, text=True).stdout
          or "erl_child_setup" in subprocess.run(["ps", "-o", "comm=", "-p", str(p)], capture_output=True, text=True).stdout]
    return {"cpu": sum(map(cpu_s, ps)), "fp_kb": sum(map(footprint_kb, ps)), "idlew": sum(map(idlew, ps)), "n": len(ps)}

def start(port, tenants, items=200, flags="", name=None):
    env = dict(os.environ, PATH=PATHX, RELEASE_DISTRIBUTION="none", RT_PORT=str(port), RT_TENANTS=str(tenants),
               RT_ITEMS=str(items), RT_SNAP=SNAP, ERL_FLAGS=flags)
    log = open(f"{HERE}/logs/{name or port}.log", "w")
    return subprocess.Popen([REL, "start"], env=env, stdout=log, stderr=subprocess.STDOUT)

def get(conn, path):
    conn.request("GET", path); r = conn.getresponse(); r.read(); return r.status

def wait_ready(port, timeout=600):
    end = time.time() + timeout
    while time.time() < end:
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            if get(c, "/ready") == 200: return
        except OSError: pass
        time.sleep(0.2)
    raise SystemExit(f"port {port} not ready")

def warm(port, tenants, per_port=False):
    c = http.client.HTTPConnection("127.0.0.1", port)
    for t in range(1, tenants + 1):
        if per_port:
            c2 = http.client.HTTPConnection("127.0.0.1", port + t - 1); get(c2, "/t/1/items/1"); c2.close()
        else:
            get(c, f"/t/{t}/items/1")

def stop(procs):
    for p in procs:
        for d in descendants(p.pid)[::-1]:
            try: os.kill(d, 9)
            except ProcessLookupError: pass

def idle():
    cfg = {"host_0": [(4100, 0, "")], "host_1k": [(4101, 1000, "")], "host_10k": [(4102, 10000, "")],
           "nodes_default_x20": [(5000 + i, 1, "") for i in range(20)], "nodes_tuned_x20": [(5100 + i, 1, TUNED) for i in range(20)]}
    procs = {c: [start(p, t, flags=f) for p, t, f in specs] for c, specs in cfg.items()}
    for c, specs in cfg.items():
        for p, t, _ in specs: wait_ready(p)
        if c.startswith("host"): warm(specs[0][0], specs[0][1])
        else: warm(specs[0][0], len(specs), per_port=True)
    time.sleep(20)
    roots = {c: [p.pid for p in ps] for c, ps in procs.items()}
    s0 = {c: sample(r) for c, r in roots.items()}
    time.sleep(60)
    s1 = {c: sample(r) for c, r in roots.items()}
    stop([p for ps in procs.values() for p in ps])
    return {c: {"os_procs": s1[c]["n"], "footprint_mb": round(s1[c]["fp_kb"] / 1024, 1),
                "cpu_ms_per_min": round((s1[c]["cpu"] - s0[c]["cpu"]) * 1000), "idle_wakeups_per_min": s1[c]["idlew"] - s0[c]["idlew"]} for c in cfg}

def cold():
    boots = []
    for i in range(10):
        t0 = time.perf_counter(); p = start(5200, 1, name="boot")
        while True:
            try:
                if get(http.client.HTTPConnection("127.0.0.1", 5200, timeout=5), "/t/1/items/1") == 200: break
            except OSError: time.sleep(0.002)
        boots.append(round((time.perf_counter() - t0) * 1000, 1)); stop([p]); time.sleep(0.5)
    res = {"node_boot_to_first_200_ms": {"p50": statistics.median(boots), "max": max(boots), "all": boots}}
    for items, tenants in [(200, 100), (5000, 50)]:
        p = start(4103, tenants, items=items, name=f"cold_{items}"); wait_ready(4103); warm(4103, tenants)
        c = http.client.HTTPConnection("127.0.0.1", 4103)
        sus, first, again, size = [], [], [], []
        for t in range(1, tenants + 1):
            c.request("POST", f"/admin/suspend/{t}"); r = json.loads(c.getresponse().read()); sus.append(r["us"] / 1000); size.append(r["bytes"])
            t0 = time.perf_counter(); assert get(c, f"/t/{t}/items/7") == 200; first.append((time.perf_counter() - t0) * 1000)
            t0 = time.perf_counter(); get(c, f"/t/{t}/items/7"); again.append((time.perf_counter() - t0) * 1000)
        stop([p])
        q = lambda l: {"p50": round(statistics.median(l), 2), "p99": round(sorted(l)[int(len(l) * 0.99) - 1], 2)}
        res[f"tenant_items_{items}"] = {"snapshot_kb": round(statistics.median(size) / 1024, 1), "suspend_ms": q(sus),
                                        "first_request_resume_ms": q(first), "warm_request_ms": q(again)}
    return res

def load():
    res = {}
    for name, mode, specs in [("host_100", "host", [(4104, 100, "")]),
                              ("nodes_default_x100", "nodes", [(5300 + i, 1, "") for i in range(100)]),
                              ("nodes_tuned_x100", "nodes", [(5500 + i, 1, TUNED) for i in range(100)])]:
        procs = [start(p, t, flags=f, name=f"load_{p}") for p, t, f in specs]
        for p, _, _ in specs: wait_ready(p)
        warm(specs[0][0], specs[0][1]) if mode == "host" else warm(specs[0][0], 100, per_port=True)
        time.sleep(5)
        env = dict(os.environ, PATH=PATHX)
        out = subprocess.run(["elixir", "--erl", "+S 4", f"{HERE}/loadgen.exs", mode, str(specs[0][0]), "100", "64", "20"],
                             env=env, capture_output=True, text=True)
        fp = sample([p.pid for p in procs])["fp_kb"]
        stop(procs); time.sleep(2)
        res[name] = {**json.loads(out.stdout.strip().splitlines()[-1]), "footprint_mb": round(fp / 1024)} if out.returncode == 0 else {"error": out.stderr[-500:]}
    return res

if __name__ == "__main__":
    phase = sys.argv[1]
    print(json.dumps({"idle": idle, "cold": cold, "load": load}[phase](), indent=1))
