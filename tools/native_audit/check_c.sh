#!/bin/bash
while read -r line; do
    m=$(echo $line | cut -d':' -f1)
    fa=$(echo $line | cut -d':' -f2 | awk '{print $1}')
    f=$(echo $fa | cut -d'/' -f1)
    a=$(echo $fa | cut -d'/' -f2)
    erl_file=$(echo $line | grep -o 'lib/.*\.erl\|erts/.*\.erl')
    
    # search for C NIF or BIF implementation
    c_file=$(grep -rl "\"$f\"" $HOME/dev/beam/ref/otp-29/erts/emulator/ $HOME/dev/beam/ref/otp-29/erts/preloaded/ 2>/dev/null | grep '\.c$' | head -n 1)
    
    if [ ! -z "$c_file" ]; then
        c_file_short=$(echo "$c_file" | sed 's|^$HOME/dev/beam/ref/otp-29/||')
        echo "B | $m:$f/$a | $c_file_short"
    else
        echo "C | $m:$f/$a | $erl_file"
    fi
done < tools/native_audit/erl_results.txt
