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
