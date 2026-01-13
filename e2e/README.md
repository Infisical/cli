# End-to-end tests for the CLI project

The folder under this folder is for our e2e tests of this CLI project.
The goal of the e2e tests is to simulate the user's interaction with Infisical system all the way from the cli to the backend API server and potentially third-party servers to ensure it works as expected.
Please note that the e2e tests is still under active development and it's subject to rapid changes.
The document here could be outdated.
If you find anything here that doesn't make sense or doesn't work as described in the document, it's likely we have already changed it.
Please feel free to reach out to @fangpenlin in Slack channel if you encounter any problem with the e2e tests.

## Running the test

The main subject of testing is a CLI executable program, i.e the `infisical` command.
Currently we support two approaches to test the CLI.
The default run method is `subprocess`.
You can set the `CLI_E2E_DEFAULT_RUN_METHOD` environment variable to change the default run method.
For example:

```bash
export CLI_E2E_DEFAULT_RUN_METHOD=functionCall
```

### The `subprocess` run method

The most straightforward way to run a CLI cmd and test it is to start a new subprocess with the cmd executable, control the input by environment vars, stdin, args and see how it connects to the server and what it outputs (stdout and stderr).
The benefit of this approach is that it simulates what user really does and we can collect the stdout and stderr easily.
The drawback of this approach is that attaching a debugger to the CLI cmd requires some extra work (like finding the PID and attach to it by using the PID from the debugger).
This is the default run method if not specified.

When using this run method, you need make sure the executable at the default location `./infisical-merge`.
Otherwise, you can also specify the path to the executable by setting `INFISICAL_CLI_EXECUTABLE` environment variable like this

```bash
export INFISICAL_CLI_EXECUTABLE=/path/to/infisical-merge
```

To build the executable, you can go to the root folder of this cli project then run

```bash
go build .
```

### The `functionCall` run method

The function call method calling the `main` cmd function directly from the e2e test case.
The benefit is that you can attach debugger directly to the cli process without extra effort.
The drawback is that currently we cannot collect stdout and stderr.
Some extra efforts might be needed to update the CLI code to abstract the stdout and stderr output from logs to make it possible.
In the meantime since this is not available, we didn't set it as the default value.
With this run method, since that we are linking the e2e test build with the CLI as a library directly, there's no need to build the executable sperately.

## Setting the `INFISICAL_BACKEND_DIR` value

To make our CLI test against the actual Infisical API server, we provide easy to use API to spin up the full Infisical stack in docker-compose like this:

```go
infisical := NewInfisicalService().
    WithBackendEnvironment(types.NewMappingWithEquals([]string{
        // This is needed for the private ip (current host) to be accepted for the relay server
        "ALLOW_INTERNAL_IP_CONNECTIONS=true",
    })).
		Up(t, ctx)
```

Because it runs the actual Infisical API server stack, you need to specify `INFISICAL_BACKEND_DIR` value and pointing to the `backend` folder of the [infisical repository](https://github.com/infisical/infisical) to make it works
Like, for example, you have the repo checked out at `/Users/fangpen/workspace/infisical`.
Then you can expose environment variable like this:

```bash
export INFISICAL_BACKEND_DIR=/Users/fangpen/workspace/infisical/backend
```

Please note that the `/backend` path is appended.

Currently, you need to enable the needed feature flag for running your tests manually in the locally checked out Infisical repo.
If you don't know how to enable those feature flags, please contact the infisical eng-team members, they will show you how to do that.
In the future, we will provide builder API to the `NewInfisicalService()` object for you to simply sepcify which feature you would like to enable.

## Running the test

To run the e2e test, you can do the following:

```bash
# switch to the e2e folder
cd e2e
go test github.com/infisical/cli/e2e-tests/relay
```

Combining the exporting environment variables, you might end up with running cmds like this:

```bash
export INFISICAL_CLI_EXECUTABLE=/path/to/infisical-merge
export INFISICAL_BACKEND_DIR=/path/to/infisical/backend
cd e2e
go test github.com/infisical/cli/e2e-tests/relay
```

It's a bit verbose right now, but we will improve the quality of life over time by adding things such as a Makefile to make it much easier.
