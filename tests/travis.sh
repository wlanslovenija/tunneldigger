#!/bin/bash
# Alexander Couzens <lynxis@fe80.eu>
#
# travis script

. $(dirname $0)/lib_ci.sh

#export PATH=/usr/bin/:/usr/sbin:/usr/local/bin:/usr/local/sbin:/bin:/sbin
#unset VIRTUAL_ENV

# NEW_REV, OLD_REV defined by .travis.yml
# SELECT too

# We had a lot of intermittent failures with the default keyserver (pool.sks-keyservers.net).
#export DOWNLOAD_KEYSERVER="pgp.mit.edu"
#export DOWNLOAD_KEYSERVER="keyserver.ubuntu.com"

# run required test

case "$SELECT" in
  nose)
    setup_container
    test_nose $OLD_REV $NEW_REV
    ;;
  usage)
    setup_container
    test_usage $NEW_REV
    ;;
  client)
    test_client_compile
    ;;
  *)
    # fail
    echo "No test selected. required export SELECT=<test>, test in [nose, usage, client]"
    echo "You entered '$SELECT'"
    exit 1
    ;;
esac
