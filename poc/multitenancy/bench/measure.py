import subprocess, time, re, json, os, statistics, sys
ERL = "/opt/homebrew/opt/erlang@29/bin/erl"
HERE = os.path.dirname(os.path.abspath(__file__))
TUNED = ["+S", "1:1", "+SDcpu", "1:1", "+SDio", "1", "+sbwt", "none", "+sbwtdcpu", "none", "+sbwtdio", "none"]
WARMUP, WINDOW = 20, 60

def tree(pid):
    out = subprocess.run(["pgrep", "-P", str(pid)], capture_output=True, text=True).stdout.split()
    return [pid] + [int(p) for p in out]

def cpu_s(pid):
    t = subprocess.run(["ps", "-o", "time=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
    parts = [float(x) for x in t.split(":")] if t else [0]
    s = 0
    for x in parts: s = s * 60 + x
    return s

def idlew(pid):
    lines = subprocess.run(["top", "-l", "1", "-pid", str(pid), "-stats", "pid,idlew"], capture_output=True, text=True).stdout.strip().splitlines()
    return int(lines[-1].split()[1].rstrip("+")) if lines and lines[-1].split()[0] == str(pid) else 0

def footprint_kb(pid):
    out = subprocess.run(["footprint", "-p", str(pid)], capture_output=True, text=True).stdout
    m = re.search(r"Footprint: ([\d.]+) (KB|MB|GB)", out)
    return float(m.group(1)) * {"KB": 1, "MB": 1024, "GB": 1048576}[m.group(2)] if m else 0

def sample(pids):
    allp = [q for p in pids for q in tree(p)]
    return {"cpu": sum(cpu_s(p) for p in allp), "idlew": sum(idlew(p) for p in allp),
            "fp_kb": sum(footprint_kb(p) for p in allp), "nprocs": len(allp)}

def launch(name, flags, args):
    log = open(f"{HERE}/logs/{name}.log", "w")
    return subprocess.Popen([ERL, *flags, "-noshell", "-pa", HERE, "-s", "dens", "idle", *args], stdout=log, stderr=subprocess.STDOUT)

def ready(name):
    return "READY" in open(f"{HERE}/logs/{name}.log").read()

os.makedirs(f"{HERE}/logs", exist_ok=True)
K = 20
configs = {
    "ns_0": [("ns_0", [], ["0", "false", "100"])],
    "ns_1k": [("ns_1k", [], ["1000", "false", "100"])],
    "ns_10k": [("ns_10k", [], ["10000", "false", "100"])],
    "ns_10k_hib": [("ns_10k_hib", [], ["10000", "true", "100"])],
    "node_default_x20": [(f"nd_{i}", [], ["1", "false", "100"]) for i in range(K)],
    "node_tuned_x20": [(f"nt_{i}", TUNED, ["1", "false", "100"]) for i in range(K)],
}
procs = {c: [(n, launch(n, f, a)) for n, f, a in specs] for c, specs in configs.items()}
deadline = time.time() + 300
while not all(ready(n) for ps in procs.values() for n, _ in ps):
    if time.time() > deadline: sys.exit("not ready")
    time.sleep(1)
time.sleep(WARMUP)
pids = {c: [p.pid for _, p in ps] for c, ps in procs.items()}
s0 = {c: sample(p) for c, p in pids.items()}
time.sleep(WINDOW)
s1 = {c: sample(p) for c, p in pids.items()}
res = {}
for c in configs:
    mem = re.search(r"total => (\d+)", open(f"{HERE}/logs/{configs[c][0][0]}.log").read())
    res[c] = {"os_procs": s1[c]["nprocs"], "cpu_ms_per_min": round((s1[c]["cpu"] - s0[c]["cpu"]) * 1000, 1),
              "idle_wakeups_per_min": s1[c]["idlew"] - s0[c]["idlew"], "footprint_mb": round(s1[c]["fp_kb"] / 1024, 1),
              "erlang_total_mb_first": round(int(mem.group(1)) / 1048576, 1) if mem else None}
for ps in procs.values():
    for _, p in ps: p.kill()
print(json.dumps(res, indent=1))
