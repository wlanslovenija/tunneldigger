#!/bin/bash

UUID="`cat /dev/random | head -c 5 | base64 | grep -oE '[^=]+'`"
IFACE="l2tp0"
HOOK="/srv/tunneldigger/client/hook.sh"

args=()
i=0

while [ -n "$1" ]; do
  if [ "$1" == "-u" ]; then
    UUID="$2"
    shift
    shift
  elif [ "$1" == "-f" ]; then
    shift
  elif [ "$1" == "-i" ]; then
    IFACE="$2"
    shift
    shift
  elif [ "$1" == "-s" ]; then
    HOOK="$2"
    shift
    shift
  else
    args[$i]=$1
    if echo "$1" | grep -qE '^-[ulbiIsil]$'; then
      # arguments with value
      i=$((i+1))
      args[$i]=$2
      shift
    fi
    i=$((i+1))
    shift
  fi
done

echo /usr/local/bin/tunneldigger -f -i "$IFACE" -s "$HOOK" -u "$UUID" "${args[@]}"
/usr/local/bin/tunneldigger -f -i "$IFACE" -s "$HOOK" -u "$UUID" "${args[@]}"

