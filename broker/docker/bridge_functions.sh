
add_to_dhcp_server()
{
  # add interface to dhcp server
  # see https://askubuntu.com/a/184351/136346
  (
    source /etc/default/isc-dhcp-server
    INTERFACESv4=`echo $INTERFACESv4 $@ | tr "[:space:]" "\n" | uniq`
    echo INTERFACESv4=\"$INTERFACESv4\" > /etc/default/isc-dhcp-server
  )

  if ! service isc-dhcp-server restart; then
    for file in /etc/default/isc-dhcp-server /etc/dhcp/dhcpd.conf; do
      echo --------------- $file --------------- 
      cat $file
    done
    echo ------------------------------------
    /usr/sbin/dhcpd -f /etc/dhcp/dhcpd.conf
    exit 1
  fi
}

