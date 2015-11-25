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
* clone containers based on container tunneldigger-base, naming them hash_client hash_server
* start the scripts prepare_client prepare_server in their containres
* start the scripts run_client run_server
* do a simple wget test

## Future

* clean up environment if the test fails (stop containers + remove them)
* use pynose for testing. Should also fix the missing clean up.

