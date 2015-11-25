#!/bin/sh
# Alexander Couzens <lynxis@fe80.eu>
#
# travis script

export WORKSPACE=$PWD
export PATH=/usr/bin/:/usr/sbin:/usr/local/bin:/usr/local/sbin:/bin:/sbin
unset VIRTUAL_ENV
exec tests/jenkins.sh
