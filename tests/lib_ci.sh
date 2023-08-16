# included by jenkins.sh and travis.sh
#
# 2016 Alexander Couzens <lynxis@fe80.eu>

export WORKSPACE=$PWD

fail() {
  echo -e "$@" >&2
  exit 1
}

setup_container() {
  /usr/bin/env python --version
  # prepare lxc container template
  if ! $WORKSPACE/tests/tunneldigger.py --setup bionic ; then
    fail "While compiling the setup"
  fi
}

test_client_compile() {
  # compile test the l2tp client
  echo "Try to compile the l2tp client"
  cd $WORKSPACE/client/
  if [ -f CMakeLists.txt ]; then
    if ! cmake . ; then
      fail "Failed while preparing the client with cmake"
    fi
  else
    sed -i 's/-lnl/-lnl-3 -lnl-genl-3/g' Makefile
    sed -i 's#-I.#-I. -I/usr/include/libnl3 -DLIBNL_TINY#g' Makefile
  fi
  if ! make VERBOSE=1 ; then
    fail "Failed while compiling the client"
  fi
}

test_nose() {
  local old_rev=$(git rev-parse $1)
  local new_rev=$(git rev-parse $2)

  cd $WORKSPACE/tests/
  echo && echo "## Old client, new server" && echo
  if ! CLIENT_REV=$old_rev SERVER_REV=$new_rev nosetests3 --nocapture test_nose.py ; then
    fail "while running test_nose cli <> server.\nclient: '$old_rev'\nserver: '$new_rev'"
  fi
  echo && echo "## Old server, new client" && echo
  if ! CLIENT_REV=$new_rev SERVER_REV=$old_rev nosetests3 --nocapture test_nose.py ; then
    fail "while running test_nose cli <> server.\nclient: '$new_rev'\nserver: '$old_rev'"
  fi
}

test_usage() {
  local new_rev=$(git rev-parse $1)

  cd $WORKSPACE/tests/
  if ! CLIENT_REV=$new_rev nosetests3 --nocapture test_usage.py ; then
    fail "while running usage tests."
  fi
}
