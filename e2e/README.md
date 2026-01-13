# End-to-end tests for the CLI project

This folder contains our e2e tests for this CLI project.
The goal of the e2e tests is to simulate the user's interaction with the Infisical system all the way from the CLI to the backend API server and potentially third-party servers to ensure it works as expected.
Please note that the e2e tests are still under active development and subject to rapid changes.
The document here could be outdated.
If you find anything here that doesn't make sense or doesn't work as described in the document, it's likely we have already changed it.
Please feel free to reach out to @fangpenlin on the Slack channel if you encounter any problem with the e2e tests.

## Running the test

The main subject of testing is a CLI executable program, i.e., the `infisical` command.
Currently we support two approaches to test the CLI.
The default run method is `subprocess`.
You can set the `CLI_E2E_DEFAULT_RUN_METHOD` environment variable to change the default run method.
For example:

```bash
export CLI_E2E_DEFAULT_RUN_METHOD=functionCall
```

### The `subprocess` run method

The most straightforward way to run a CLI command and test it is to start a new subprocess with the command executable, control the input by environment vars, stdin, args and see how it connects to the server and what it outputs (stdout and stderr).
The benefit of this approach is that it simulates what a user really does and we can collect the stdout and stderr easily.
The drawback of this approach is that attaching a debugger to the CLI command requires some extra work (like finding the PID and attaching to it by using the PID from the debugger).
This is the default run method if not specified.

When using this run method, you need to make sure the executable is at the default location `./infisical-merge`.
Otherwise, you can also specify the path to the executable by setting the `INFISICAL_CLI_EXECUTABLE` environment variable like this:

```bash
export INFISICAL_CLI_EXECUTABLE=/path/to/infisical-merge
```

To build the executable, you can go to the root folder of this cli project then run

```bash
go build .
```

### The `functionCall` run method

The function call method calls the `main` command function directly from the e2e test case.
The benefit is that you can attach a debugger directly to the CLI process without extra effort.
The drawback is that currently we cannot collect stdout and stderr.
Some extra efforts might be needed to update the CLI code to abstract the stdout and stderr output from logs to make it possible.
In the meantime, since this is not available, we didn't set it as the default value.
With this run method, since we are linking the e2e test build with the CLI as a library directly, there's no need to build the executable separately.

## Setting the `INFISICAL_BACKEND_DIR` value

To make our CLI test against the actual Infisical API server, we provide an easy-to-use API to spin up the full Infisical stack in docker-compose like this:

```go
infisical := NewInfisicalService().
    WithBackendEnvironment(types.NewMappingWithEquals([]string{
        // This is needed for the private ip (current host) to be accepted for the relay server
        "ALLOW_INTERNAL_IP_CONNECTIONS=true",
    })).
		Up(t, ctx)
```

Because it runs the actual Infisical API server stack, you need to specify the `INFISICAL_BACKEND_DIR` value and point it to the `backend` folder of the [infisical repository](https://github.com/infisical/infisical) to make it work.
For example, if you have the repo checked out at `/Users/fangpen/workspace/infisical`.
Then you can set the environment variable like this:

```bash
export INFISICAL_BACKEND_DIR=/Users/fangpen/workspace/infisical/backend
```

Please note that the `/backend` path is appended.

Currently, you need to enable the needed feature flags for running your tests manually in the locally checked out Infisical repo.
If you don't know how to enable those feature flags, please contact the Infisical engineering team members; they will show you how to do that.
In the future, we will provide a builder API to the `NewInfisicalService()` object for you to simply specify which features you would like to enable.

## Running the test

To run the e2e test, you can do the following:

```bash
# switch to the e2e folder
cd e2e
go test github.com/infisical/cli/e2e-tests/relay
```

Combining the exported environment variables, you might end up with running commands like this:

```bash
export INFISICAL_CLI_EXECUTABLE=/path/to/infisical-merge
export INFISICAL_BACKEND_DIR=/path/to/infisical/backend
cd e2e
go test github.com/infisical/cli/e2e-tests/relay
```

It's a bit verbose right now, but we will improve the quality of life over time by adding things such as a Makefile to make it much easier.

## Troubleshooting the failing tests due to CLI error

Sometimes, the e2e tests fail.
To find out why they fail, if it's a failure of the CLI command process itself, such as the command exiting with an error code, you can look at the logs and may find this:

```
2026/01/12 11:05:14 INFO Running command as a sub-process executable=/Users/fangpenlin/workspace/cli/infisical-merge args="[relay start --domain http://localhost:54937]"
2026/01/12 11:05:14 INFO Writing stdout to temp file file=/var/folders/wc/g97rf4092_z9wqbp93djvnt00000gn/T/TestRelay_RegistersARelay2199940539/001/stdout.log
2026/01/12 11:05:14 INFO Writing stderr to temp file file=/var/folders/wc/g97rf4092_z9wqbp93djvnt00000gn/T/TestRelay_RegistersARelay2199940539/001/stderr.log
```

With the sub-process approach, the stdout and stderr logs should be outputting to the files as shown in the path.
In that case, you may want to inspect the stderr log file like:

```bash
less /var/folders/wc/g97rf4092_z9wqbp93djvnt00000gn/T/TestRelay_RegistersARelay2199940539/001/stderr.log
```

Then you should be able to find out why it fails.
You can also switch the call method to `functionCall` and set up a debugger to trace into the CLI program to find out why it fails.
If you run the command test with `functionCall`, it will not write the stdout / stderr to a file, but instead, it should print it to the console where you run the tests.

## Troubleshooting the failing tests due to Infisical backend API errors

If the errors happen in the backend, to find out what's going on, you can open the Docker Desktop app or use `docker ps` and then `docker logs` to find out what the error message is in the Infisical backend API server.
Please note that by default, the [testcontainers library](https://github.com/testcontainers/testcontainers-go) (the library we use to run the docker-compose for the Infisical stack) will start a container called Ryuk for deleting the containers after the test is finished.
Because of that, if you run into an error in the backend reproduced by running the test, the container might already be gone after the test finishes.
Then you won't be able to look inside the container and find out what's going on.
To solve the problem, you can set the `TESTCONTAINERS_RYUK_DISABLED` environment variable to `true` like this to disable the container deleting behavior:

```bash
TESTCONTAINERS_RYUK_DISABLED=true
```

To learn more about the behavior of Ryuk from testcontainers, please read [their document here](https://golang.testcontainers.org/features/garbage_collector/#ryuk).

## Use compose containers cache to speed up the development cycle

More often than not, we may find ourselves in the loop of:

- Change a few lines of CLI code
- Run the test
- Change a few lines of CLI code again
- Run the test again
- Change a few lines of CLI code once again
- Run the test once again
- ...

It would be very time consuming to wait for the Infisical backend server to fully boot up for each iteration.
To speed up the development cycle, we have a cache system built in.
Here's how it works.
If you have `TESTCONTAINERS_RYUK_DISABLED` set to `true`, each time the `Up` method of the `InfisicalService()` is called, we will look at the hash value of the compose YAML file generated from the desired environment defined in the e2e test case.
If there's such a container already running, we will reuse it by resetting its database instead of starting a new one.
That way, it's much faster than booting up a new compose stack and waiting for it to get online.

If for any reason the cache system is not working as desired, you can disable it by setting the `CLI_E2E_DISABLE_COMPOSE_CACHE` value to `1` like this:

```bash
export CLI_E2E_DISABLE_COMPOSE_CACHE=1
```
