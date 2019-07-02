#!/bin/bash

#
# Check mode, see
# https://github.com/hwdsl2/docker-ipsec-vpn-server/blob/f254eacd6e081020939b568541c7c3a50663d475/run.sh#L37
#
if ip link add dummy0 type dummy 2>&1 | grep -q "not permitted"; then
  cat 1>&2 <<'  EOF'
  Error: This Docker image must be run in privileged mode.
  For detailed instructions, please visit:
  https://tunneldigger.readthedocs.io/en/latest/server.html
  EOF
  exit 1
fi
ip link delete dummy0 >/dev/null 2>&1

#
# Set default values
#
UUID="`cat /dev/random | head -c 5 | base64 | grep -oE '[^=]+'`"
IFACE="l2tp0"
HOOK="/srv/tunneldigger/client/hook.sh"

#
# Parse parameters and replace default values
#
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

#
# Run tunneldigger
#
echo /usr/local/bin/tunneldigger -f -i "$IFACE" -s "$HOOK" -u "$UUID" "${args[@]}"
/usr/local/bin/tunneldigger -f -i "$IFACE" -s "$HOOK" -u "$UUID" "${args[@]}"

