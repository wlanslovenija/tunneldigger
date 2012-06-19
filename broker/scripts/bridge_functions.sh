ensure_bridge()
{
  local brname="$1"
  brctl addbr $brname 2>/dev/null
  
  if [[ "$?" == "0" ]]; then
    # Bridge did not exist before, we have to initialize it
    ip link set dev $brname up
    # TODO The IP address should probably not be hardcoded here?
    ip addr add 10.254.0.2/16 dev $brname
  fi
}

