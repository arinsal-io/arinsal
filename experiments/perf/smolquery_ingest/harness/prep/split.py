"""Split an NDJSON file into request bodies of at most N bytes on line boundaries.
   python3 -I split.py <in.ndjson> <out_dir> <prefix> <max_bytes>"""
import os, sys
src, out, prefix, cap = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
os.makedirs(out, exist_ok=True)
idx, buf, size, rows, total = 0, [], 0, 0, 0
def flush():
    global idx, buf, size, rows
    if not buf: return
    with open(os.path.join(out, f"{prefix}-{idx:04d}-{rows}.ndjson"), "wb") as f:
        f.writelines(buf)
    idx += 1; buf = []; size = 0; rows = 0
with open(src, "rb", buffering=8 << 20) as f:
    for line in f:
        if not line.strip(): continue
        if not line.endswith(b"\n"): line += b"\n"
        if size + len(line) > cap: flush()
        buf.append(line); size += len(line); rows += 1; total += 1
flush()
print(f"{src}: {total} rows in {idx} bodies")
