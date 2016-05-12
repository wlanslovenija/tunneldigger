#!/bin/sh
# 2015-2016 Alexander Couzens <lynxis@fe80.eu>
#
# jenkins script

set -e

. $(dirname $0)/lib_ci.sh

# retrieve git rev
NEW_REV=$(cd $WORKSPACE && git log -1 --format=format:%H)

# compile the client
test_client_compile

# setup the base container
setup_container

# test the version aginst itself
test_nose $NEW_REV $NEW_REV

OLD_REV="c638231efca6b3a6e1c675ac0834a3e851ad1bdc 4e4f13cdc630c46909d47441093a5bdaffa0d67f"
# test against each other
for rev in $OLD_REV ; do
  # old client, new server
  test_nose $rev $NEW_REV

  # new client, old server
  test_nose $NEW_REV $rev
done

test_usage $NEW_REV
