#!/bin/sh

# fail when something fails
set -e

# checkout the repo
cd /srv
git clone /git_repo tunneldigger
cd /srv/tunneldigger
git checkout "$1"

cd /srv/tunneldigger/client
make
