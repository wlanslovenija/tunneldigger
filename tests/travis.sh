#!/bin/bash
# Alexander Couzens <lynxis@fe80.eu>
#
# travis script

. $(dirname $0)/lib_ci.sh

export WORKSPACE=$PWD
#export PATH=/usr/bin/:/usr/sbin:/usr/local/bin:/usr/local/sbin:/bin:/sbin
#unset VIRTUAL_ENV

# NEW_REV, OLD_REV defined by .travis.yml
# SELECT too

if [ "$OLD_REV" = "HEAD" ] ; then
  OLD_REV=$NEW_REV
fi

# We had a lot of intermittent failures with the default keyserver (pool.sks-keyservers.net).
#export DOWNLOAD_KEYSERVER="pgp.mit.edu"
#export DOWNLOAD_KEYSERVER="keyserver.ubuntu.com"

set -ex
/usr/bin/env python --version

# finish setup
$(dirname $0)/tunneldigger.py --setup bionic
if [[ "$OLD_UBUNTU" == "trusty" || "$SELECT" == "usage" ]]; then
    $(dirname $0)/tunneldigger.py --setup trusty
fi

# run required test

case "$SELECT" in
  nose)
    test_nose $OLD_REV $OLD_UBUNTU $NEW_REV
    ;;
  usage)
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
