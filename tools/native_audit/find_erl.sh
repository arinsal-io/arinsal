#!/bin/bash
OTP_SRC=${ARINSAL_OTP_SRC:-}
if [ -z "$OTP_SRC" ] || [ ! -d "$OTP_SRC/lib" ]; then
    echo "Skipping native audit: set ARINSAL_OTP_SRC to the OTP source tree" >&2
    exit 0
fi
while read -r line; do
    m=$(echo $line | cut -d':' -f1)
    fa=$(echo $line | cut -d':' -f2)
    f=$(echo $fa | cut -d'/' -f1)
    a=$(echo $fa | cut -d'/' -f2)
    
    found=$(grep -E "^'?$f'?\(" "$OTP_SRC"/lib/*/src/$m.erl "$OTP_SRC"/erts/preloaded/src/$m.erl 2>/dev/null | head -n 1)
    if [ ! -z "$found" ]; then
        file=$(echo "$found" | cut -d':' -f1)
        file=${file#"$OTP_SRC/"}
        echo "$line -> C ($file)"
    else
        echo "$line -> NOT_FOUND"
    fi
done < tools/native_audit/unknown.txt
