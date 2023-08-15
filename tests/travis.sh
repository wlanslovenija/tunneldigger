#!/bin/bash
# Alexander Couzens <lynxis@fe80.eu>
#
# travis script

. $(dirname $0)/lib_ci.sh

# We had a lot of intermittent failures with the default keyserver (pool.sks-keyservers.net).
#export DOWNLOAD_KEYSERVER="pgp.mit.edu"
#export DOWNLOAD_KEYSERVER="keyserver.ubuntu.com"

# run requested test

case "$SELECT" in
  nose)
    setup_container
    test_nose $OLD_REV HEAD
    ;;
  usage)
    setup_container
    test_usage HEAD
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
