#!/bin/bash
while read -r line; do
    m=$(echo $line | cut -d':' -f1)
    fa=$(echo $line | cut -d':' -f2)
    f=$(echo $fa | cut -d'/' -f1)
    a=$(echo $fa | cut -d'/' -f2)
    
    found=$(grep -E "^'?$f'?\(" $HOME/dev/beam/ref/otp-29/lib/*/src/$m.erl $HOME/dev/beam/ref/otp-29/erts/preloaded/src/$m.erl 2>/dev/null | head -n 1)
    if [ ! -z "$found" ]; then
        file=$(echo "$found" | cut -d':' -f1 | sed 's|^$HOME/dev/beam/ref/otp-29/||')
        echo "$line -> C ($file)"
    else
        echo "$line -> NOT_FOUND"
    fi
done < tools/native_audit/unknown.txt
