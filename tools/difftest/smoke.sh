#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
mkdir -p tools/difftest/ebin
erlc -o tools/difftest/ebin tools/difftest/difftest_server.erl
python3 - <<'PY'
import struct, subprocess

def atom(s):
    b=s.encode(); return bytes([119,len(b)])+b

def integer(n):
    return bytes([97,n]) if 0 <= n < 256 else bytes([98])+struct.pack('>i',n)

def tuple_(*xs):
    return bytes([104,len(xs)])+b''.join(xs)

def list_(*xs):
    return bytes([108])+struct.pack('>I',len(xs))+b''.join(xs)+bytes([106])

def frame(term):
    data=bytes([131])+term; return struct.pack('>I',len(data))+data

def read(p):
    size=struct.unpack('>I',p.stdout.read(4))[0]; return p.stdout.read(size)

p=subprocess.Popen(['erl','-noshell','-pa','tools/difftest/ebin','-s','difftest_server','main'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
try:
    requests=[atom('ping'),tuple_(atom('call'),integer(1),atom('erlang'),atom('abs'),list_(integer(-9))),tuple_(atom('call_opts'),integer(2),atom('timer'),atom('sleep'),list_(atom('infinity')),list_(tuple_(atom('timeout'),integer(10)))),tuple_(atom('call'),integer(3),atom('erlang'),atom('abs'),list_(integer(-7))),tuple_(atom('call'),integer(4),atom('erlang'),atom('halt'),bytes([106]))]
    p.stdin.write(b''.join(map(frame,requests))); p.stdin.flush()
    replies=[read(p) for _ in requests]
    assert any(b'pong' in x and b'29' in x for x in replies), replies
    assert any(b'timeout' in x for x in replies), replies
    assert any(b'forbidden_call' in x for x in replies), replies
    assert any(bytes([97,9]) in x for x in replies), replies
    assert any(bytes([97,7]) in x for x in replies), replies
    p.stdin.write(frame(atom('stop'))); p.stdin.flush()
    assert b'stopped' in read(p)
    assert p.wait(timeout=5)==0
    print('PASS: ping, pipelined calls, timeout, forbidden halt, stop')
finally:
    if p.poll() is None: p.kill()
PY
