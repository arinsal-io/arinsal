import re
import os

with open("spec/otp-29.1.1/bif.tab", "r") as f:
    bif_tab = f.read()

bifs = set()
for line in bif_tab.splitlines():
    if line.startswith(("bif ", "hbif ", "ubif ")):
        parts = line.split()
        func = parts[1]
        if ":" in func:
            m = func.split(":")[0]
            fa = ":".join(func.split(":")[1:])
            a = int(fa.split("/")[-1])
            f = "/".join(fa.split("/")[:-1])
            bifs.add((m, f, a))
        else:
            a = int(func.split("/")[-1])
            f = "/".join(func.split("/")[:-1])
            bifs.add(("erlang", f, a))

lines = os.popen("python3 tools/native_audit/extract.py").read().splitlines()

for line in lines:
    if not line: continue
    m_fa = line.split(" ")[0]
    source = line.split(" ")[1]
    m = m_fa.split(":")[0]
    fa = ":".join(m_fa.split(":")[1:])
    a = int(fa.split("/")[-1])
    f = "/".join(fa.split("/")[:-1])
    
    if (m, f, a) in bifs:
        print(f"A | {m}:{f}/{a} | {source}")
    else:
        print(f"UNKNOWN | {m}:{f}/{a} | {source}")
