#!/bin/bash
OTP_SRC=${ARINSAL_OTP_SRC:-}
if [ -z "$OTP_SRC" ] || [ ! -d "$OTP_SRC/erts/emulator" ]; then
    echo "Skipping native audit: set ARINSAL_OTP_SRC to the OTP source tree" >&2
    exit 0
fi
while read -r line; do
    m=$(echo $line | cut -d':' -f1)
    fa=$(echo $line | cut -d':' -f2 | awk '{print $1}')
    f=$(echo $fa | cut -d'/' -f1)
    a=$(echo $fa | cut -d'/' -f2)
    erl_file=$(echo $line | grep -o 'lib/.*\.erl\|erts/.*\.erl')
    
    # search for C NIF or BIF implementation
    c_file=$(grep -rl "\"$f\"" "$OTP_SRC/erts/emulator/" "$OTP_SRC/erts/preloaded/" 2>/dev/null | grep '\.c$' | head -n 1)
    
    if [ ! -z "$c_file" ]; then
        c_file_short=${c_file#"$OTP_SRC/"}
        echo "B | $m:$f/$a | $c_file_short"
    else
        echo "C | $m:$f/$a | $erl_file"
    fi
done < tools/native_audit/erl_results.txt
