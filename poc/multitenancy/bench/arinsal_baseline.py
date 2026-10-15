"""Baseline for bench/rest run as `MIX_ENV=prod mix run --no-halt` on stock ERTS and on Arinsal.

usage: arinsal_baseline.py all [OUT.json]
       arinsal_baseline.py idle|load erts|arinsal TENANTS PORT

Env: ARINSAL_SHIM (dir with the `erl` symlink to the arinsal binary),
     OTP_PATH (PATH prefix with Homebrew OTP 29 and Elixir).
idle: warm every tenant with one GET, 20 s settle, 60 s window; reports phys_footprint
      of the node process and its children and the CPU time delta.
load: loadgen.exs (client on stock ERTS, +S 4) with 64 connections for 20 s.
Runs are sequential, one runtime at a time.
"""
import json, os, re, subprocess, sys, time, http.client

HERE = os.path.dirname(os.path.abspath(__file__))
REST = f"{HERE}/rest"
SHIM = os.environ.get("ARINSAL_SHIM", os.path.abspath(f"{HERE}/../../../target/release/arinsal-erl-shim"))
OTP = os.environ.get("OTP_PATH", "/opt/homebrew/opt/erlang@29/bin:/opt/homebrew/opt/elixir/bin")
STOCK = OTP + ":" + os.environ["PATH"]


def run_env(runtime, tenants, port):
    path = (SHIM + ":" + STOCK) if runtime == "arinsal" else STOCK
    return dict(os.environ, PATH=path, MIX_ENV="prod", RT_PORT=str(port), RT_TENANTS=str(tenants),
                RT_SNAP=f"{HERE}/snap_tmp")


def children(pid):
    ks = [int(x) for x in subprocess.run(["pgrep", "-P", str(pid)], capture_output=True, text=True).stdout.split()]
    return [pid] + [d for k in ks for d in children(k)]


def comm(pid):
    return subprocess.run(["ps", "-o", "comm=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()


def node_pids(root, runtime):
    ps = children(root)
    if runtime == "arinsal":
        main = [p for p in ps if comm(p) == "erl"]
        return [q for p in main for q in children(p)]
    return [p for p in ps if os.path.basename(comm(p)) in ("beam.smp", "erl_child_setup")]


def cpu_s(pid):
    t = subprocess.run(["ps", "-o", "time=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
    s = 0.0
    for x in (t.split(":") if t else ["0"]):
        s = s * 60 + float(x)
    return s


def footprint_mb(pid):
    out = subprocess.run(["footprint", "-p", str(pid)], capture_output=True, text=True).stdout
    m = re.search(r"Footprint: ([\d.]+) (KB|MB|GB)", out)
    return float(m.group(1)) * {"KB": 1 / 1024, "MB": 1, "GB": 1024}[m.group(2)] if m else 0.0


def get(c, path):
    c.request("GET", path)
    r = c.getresponse()
    r.read()
    return r.status


def start(runtime, tenants, port):
    log = open(f"{HERE}/logs/{runtime}-{port}.log", "w")
    t0 = time.time()
    p = subprocess.Popen(["mix", "run", "--no-halt"], cwd=REST, env=run_env(runtime, tenants, port),
                         stdout=log, stderr=subprocess.STDOUT)
    while True:
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            if get(c, "/ready") == 200:
                return p, c, time.time() - t0
        except OSError:
            time.sleep(0.2)


def stop(p, runtime, port):
    pids = node_pids(p.pid, runtime)
    p.terminate()
    for q in pids:
        subprocess.run(["kill", str(q)], capture_output=True)
    try:
        p.wait(15)
    except subprocess.TimeoutExpired:
        p.kill()
    time.sleep(2)


def idle(runtime, tenants, port):
    os.makedirs(f"{HERE}/logs", exist_ok=True)
    p, c, ready = start(runtime, tenants, port)
    for t in range(1, tenants + 1):
        get(c, f"/t/{t}/items/1")
    pids = node_pids(p.pid, runtime)
    time.sleep(20)
    c0 = sum(cpu_s(q) for q in pids)
    time.sleep(60)
    c1 = sum(cpu_s(q) for q in pids)
    r = {"runtime": runtime, "tenants": tenants, "ready_s": round(ready, 1),
         "footprint_mb": round(sum(footprint_mb(q) for q in pids), 1),
         "idle_cpu_ms_min": round((c1 - c0) * 1000), "procs": len(pids)}
    stop(p, runtime, port)
    return r


def load(runtime, tenants, port):
    os.makedirs(f"{HERE}/logs", exist_ok=True)
    p, c, ready = start(runtime, tenants, port)
    for t in range(1, tenants + 1):
        get(c, f"/t/{t}/items/1")
    pids = node_pids(p.pid, runtime)
    time.sleep(3)
    out = subprocess.run(["elixir", "--erl", "+S 4", f"{HERE}/loadgen.exs", "host", str(port), str(tenants), "64", "20"],
                         env=dict(os.environ, PATH=STOCK), capture_output=True, text=True).stdout.strip().splitlines()[-1]
    lg = json.loads(out)
    r = {"runtime": runtime, "tenants": tenants, "rps": lg["rps"], "p50_us": lg["p50_us"], "p99_us": lg["p99_us"],
         "p999_us": lg["p999_us"], "footprint_mb": round(sum(footprint_mb(q) for q in pids), 1)}
    stop(p, runtime, port)
    return r


def main():
    mode = sys.argv[1]
    if mode == "all":
        res = []
        for rt in ("erts", "arinsal"):
            for n, port in ((0, 4410), (1000, 4411)):
                res.append({"kind": "idle", **idle(rt, n, port)}); print(res[-1], flush=True)
            res.append({"kind": "load", **load(rt, 100, 4412)}); print(res[-1], flush=True)
        if len(sys.argv) > 2:
            json.dump(res, open(sys.argv[2], "w"), indent=1)
    else:
        print(json.dumps((idle if mode == "idle" else load)(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))))


if __name__ == "__main__":
    main()
