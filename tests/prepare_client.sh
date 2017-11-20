#!/bin/sh

# fail when something fails
set -e

# checkout the repo
cd /srv
git clone /git_repo tunneldigger
cd /srv/tunneldigger
git checkout "$1"

cd /srv/tunneldigger/client
if [ -f CMakeLists.txt ]; then
  cmake .
  make VERBOSE=1
else
  sed -i 's/-lnl/-lnl-3 -lnl-genl-3/g' Makefile
  sed -i 's#-I.#-I. -I/usr/include/libnl3 -DLIBNL_TINY#g' Makefile
  make
fi
