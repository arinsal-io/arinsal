import re
import glob
import os

implemented = set()

def add(m, f, a, source):
    if m == "erlang" and f == "system_time": # special case os vs erlang
        implemented.add(("erlang", f, a, source))
    else:
        implemented.add((m, f, a, source))

# 1. Look for IMPLEMENTED lists
files = glob.glob("crates/vm/src/natives/*.rs") + ["crates/vm/src/signals.rs", "crates/vm/src/calls.rs"]
for f in files:
    if not os.path.exists(f): continue
    with open(f, "r") as file:
        content = file.read()
        for match in re.finditer(r'const [A-Z_]*IMPLEMENTED.*?=\s*&\[(.*?)\];', content, re.DOTALL):
            items = re.findall(r'\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*(\d+)\s*\)', match.group(1))
            for m, func, a in items:
                add(m, func, int(a), f)

# 2. Look for match arms in crates/bifs/**/*.rs and calls.rs?
for f in glob.glob("crates/bifs/src/*.rs") + glob.glob("crates/vm/src/*.rs"):
    if not os.path.exists(f): continue
    with open(f, "r") as file:
        content = file.read()
        for match in re.finditer(r'\(\s*"([^"]+)"(?:\s*\|\s*"([^"]+)")?\s*,\s*"([^"]+)"(?:\s*\|\s*"([^"]+)")?\s*,\s*([^)]+)\s*\)\s*=>', content):
            m1 = match.group(1)
            m2 = match.group(2)
            func1 = match.group(3)
            func2 = match.group(4)
            arity_str = match.group(5)
            
            # arity parsing
            arities = []
            if ".." in arity_str:
                parts = arity_str.split("..")
                start = int(parts[0].strip())
                end = int(parts[1].replace("=", "").strip())
                arities = list(range(start, end + 1))
            elif "|" in arity_str:
                arities = [int(x.strip()) for x in arity_str.split("|")]
            else:
                try:
                    arities = [int(arity_str.strip())]
                except ValueError:
                    continue # e.g. '_'
                    
            for m in filter(None, [m1, m2]):
                for func in filter(None, [func1, func2]):
                    for a in arities:
                        add(m, func, a, f)

implemented_list = list(implemented)
implemented_list.sort()
for i in implemented_list:
    print(f"{i[0]}:{i[1]}/{i[2]} ({i[3]})")

# Manually add nif intercepts
implemented.add(("application", "load", 1, "crates/vm/src/natives/nif.rs"))
implemented.add(("application", "get_env", 2, "crates/vm/src/natives/nif.rs"))
implemented.add(("erlang", "apply", 2, "crates/vm/src/calls.rs"))
implemented.add(("erlang", "apply", 3, "crates/vm/src/calls.rs"))
implemented.add(("erlang", "!", 2, "crates/vm/src/calls.rs"))

implemented_list = list(implemented)
implemented_list.sort()
with open("tools/native_audit/extract_out.txt", "w") as f:
    for i in implemented_list:
        f.write(f"{i[0]}:{i[1]}/{i[2]} ({i[3]})\n")
