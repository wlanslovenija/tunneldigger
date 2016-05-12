#!/bin/sh
# Alexander Couzens <lynxis@fe80.eu>
#
# travis script

. $(dirname $0)/lib_ci.sh

set -e

export WORKSPACE=$PWD
export PATH=/usr/bin/:/usr/sbin:/usr/local/bin:/usr/local/sbin:/bin:/sbin
unset VIRTUAL_ENV

# retrieve git rev
NEW_REV=$(cd $WORKSPACE && git log -1 --format=format:%H)

# OLD_REV defined by .travis.yml
# SELECT too

if [ "$OLD_REV" = "HEAD" ] ; then
  OLD_REV=$TRAVIS_COMMIT
fi

case "$SELECT" in
  nose)
    test_nose $OLD_REV $NEW_REV
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
