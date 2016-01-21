# testing tunneldigger

The automatic testing with tunneldigger uses lxc container and the python3 api of lxc.


## Setup the environment

```./test_td.py --setup```

will setup the lxc environment and create a snapshot which is used by all tests.
The resulting container is named tunneldigger-base.


## Do a test run

A test run requires you have setted up the environment.
```./test_td.py -t -s HEAD -c HEAD```

will do a test run using HEAD for the server and the client.

## What does a test run?

* generate a build hash
* checkout the repository
* clone containers based on container `tunneldigger-base`, naming them `hash_client` and `hash_server`
* start the scripts `prepare_client.sh` and `prepare_server.sh` in their containers
* start the scripts `run_client.sh` and `run_server.sh`
* do a simple `wget` test

## Files

* travis.sh - entrypoint for travis tests
* jenkins.sh - entrypoint for jenkins tests

* hook_client.sh - hook for the client to configure the interface ip
* hook_server - hooks for the server. add/remove the interface to the bridge

* prepare_client.sh - locally checkout the client and compiles it
* prepare_server.sh - do network configuration, install dependencies(pip) and builds the server

* run_client.sh - starts the client
* run_server.sh - starts the server

* test-data - empty dir used by tests to put test-data like big files for download-testing into it
* test_nose.py - nose test cases
* tunneldigger.py - LXC logic and basic test logic (no tests)

## Future

* clean up environment if the test fails (stop containers + remove them)
