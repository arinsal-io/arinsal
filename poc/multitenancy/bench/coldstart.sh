#!/bin/zsh
zmodload zsh/datetime
# Node cold start (boot to first eval) and tenant suspend/resume to the filesystem.
ERL=/opt/homebrew/opt/erlang@29/bin/erl
cd ${0:A:h}
TUNED=(+S 1:1 +SDcpu 1:1 +SDio 1 +sbwt none +sbwtdcpu none +sbwtdio none)
for cfg in default tuned; do
  flags=(); [[ $cfg == tuned ]] && flags=($TUNED)
  ms=()
  for i in {1..15}; do
    t0=$EPOCHREALTIME
    $ERL $flags -noshell -pa . -s dens boot_ready >/dev/null
    t1=$EPOCHREALTIME
    ms+=$(printf %.0f $(( (t1 - t0) * 1000 )))
  done
  echo "node_boot_$cfg ms: ${(j:,:)ms}"
done
for spec in "200 100" "200 2000" "50 20000"; do
  rm -rf snap && mkdir snap
  $ERL -noshell -pa . -s dens suspend_resume ${=spec} snap | tr -s ' \n' ' '; echo
done
