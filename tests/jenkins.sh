#!/bin/sh
# 2015-2016 Alexander Couzens <lynxis@fe80.eu>
#
# jenkins script

nosetests() {
  nosetests3 test_nose.py
}

set -e

# compile test the l2tp client
echo "Try to compile the l2tp client"
cd $WORKSPACE/client/
make

# prepare lxc container template
$WORKSPACE/tests/tunneldigger.py --setup

# retrieve git rev
cd $WORKSPACE/
NEW_REV=$(git log -1 --format=format:%H)

cd $WORKSPACE/tests/
# test the version aginst itself
export CLIENT_REV=$NEW_REV
export SERVER_REV=$NEW_REV
nosetests


OLD_REV="c638231efca6b3a6e1c675ac0834a3e851ad1bdc 4e4f13cdc630c46909d47441093a5bdaffa0d67f"
# do client NEW_REV against old revs
for rev in $OLD_REV ; do
  export CLIENT_REV=$NEW_REV
  export SERVER_REV=$rev
  nosetests
done

# do server NEW_REV against old revs
for rev in $OLD_REV ; do
  export CLIENT_REV=$rev
  export SERVER_REV=$NEW_REV
  nosetests
done

for i in seq 1 5; do
  nosetests test_usage.py
done
