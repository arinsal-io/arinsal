#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

erlc +deterministic dist_rtt.erl
erlc +deterministic microbench.erl

EPMD_STARTED=0
if ! epmd -names >/dev/null 2>&1; then
    epmd -daemon
    EPMD_STARTED=1
fi

function cleanup {
    pkill -f 'sname b_node' || true
    pkill -f 'sname a_node' || true
    if [ "$EPMD_STARTED" -eq 1 ]; then
        epmd -kill >/dev/null 2>&1 || true
    fi
    rm -f *.beam erl_crash.dump
}
trap cleanup EXIT

run_bench() {
    local run_a=$1
    local run_b=$2
    local name=$3

    echo "=== $name ==="

    if [[ "$run_a" == *"arinsal"* ]] || [[ "$run_b" == *"arinsal"* ]]; then
        if [ ! -x "../../../target/release/arinsal" ]; then
            echo "arinsal: distribution not yet available"
            echo
            return 0
        fi
        # Check if arinsal supports distribution
        if ! ../../../target/release/arinsal -noshell -sname test_arinsal_dist -eval 'init:stop().' >/dev/null 2>&1; then
            echo "arinsal: distribution not yet available"
            echo
            return 0
        fi
    fi

    local b_cmd
    if [[ "$run_b" == "erts" ]]; then
        b_cmd="erl -noshell -pa \"$PWD\" -sname b_node -cookie bench_cookie -eval 'receive stop -> init:stop() end.'"
    else
        b_cmd="../../../target/release/arinsal -noshell -pa \"$PWD\" -sname b_node -cookie bench_cookie -eval 'receive stop -> init:stop() end.'"
    fi
    
    eval "$b_cmd &"
    NODE_B_PID=$!
    
    # Wait for node B to be up
    for i in {1..50}; do
        if epmd -names | grep -q b_node; then
            break
        fi
        sleep 0.1
    done
    sleep 0.5 # Give it a little more time to fully start distribution

    local a_cmd
    if [[ "$run_a" == "erts" ]]; then
        a_cmd="erl -noshell -pa \"$PWD\" -sname a_node -cookie bench_cookie -run dist_rtt run b_node"
    else
        a_cmd="../../../target/release/arinsal -noshell -pa \"$PWD\" -sname a_node -cookie bench_cookie -run dist_rtt run b_node"
    fi
    
    eval "$a_cmd" || echo "Bench failed"
    
    kill -9 $NODE_B_PID 2>/dev/null || true
    wait $NODE_B_PID 2>/dev/null || true
    
    # Wait for node B to unregister from epmd
    for i in {1..50}; do
        if ! epmd -names | grep -q b_node; then
            break
        fi
        sleep 0.1
    done
    
    echo
}

run_bench "erts" "erts" "erts <-> erts"
run_bench "arinsal" "arinsal" "arinsal <-> arinsal"
run_bench "erts" "arinsal" "erts <-> arinsal"

echo "=== Microbench: erts ==="
erl -noshell -run microbench run -run init stop
echo

echo "=== Microbench: arinsal ==="
if [ -x "../../../target/release/arinsal" ]; then
    ../../../target/release/arinsal -noshell -run microbench run -run init stop || echo "arinsal: microbench failed"
else
    echo "arinsal: not built"
fi
