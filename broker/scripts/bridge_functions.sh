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
    # TODO The IP address should probably not be hardcoded here?
    ip addr add 10.254.0.2/16 dev $brname
    # TODO Policy routing should probably not be hardcoded here?
    ensure_policy from all iif $brname lookup mesh prio 1000
    # Disable forwarding between bridge ports
    ebtables -A FORWARD --logical-in $brname -j DROP
  fi
}

