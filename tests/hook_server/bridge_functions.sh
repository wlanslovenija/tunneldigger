ensure_policy()
{
  ip rule del $*
  ip rule add $*
}

ensure_bridge()
{
  local brname="$1"
  brctl addbr $brname 2>/dev/null

  if [[ "$?" == "0" ]]; then
    # Bridge did not exist before, we have to initialize it
    ip link set dev $brname up
    # Disable forwarding between bridge ports
    ebtables -A FORWARD --logical-in $brname -j DROP
  fi
}

