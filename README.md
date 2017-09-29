# What is this?

`bun` is a tool for integrating fuzzer-based tests into a conventional CI pipeline.  The popular afl-fuzz tool in particular is designed to use all available compute time and keep records on persistent storage for later examination by an analyst; this particular workflow is ill-suited for cloud-based CI testing services, which do not persist storage for users and unceremoniously kill long-running processes.

## How does it work?

`bun` launches an afl-fuzz process and monitors its progress via the fuzzer_stats file.  When a cycle has completed or some crashes were found (whichever comes first), `bun` reports the progress, kills `afl-fuzz`, and exits.

## How do I use the output?

When crashes are detected, `bun` will base64-encode them and output them on the console.  You can then copy the text chunks and base64-decode them into reproduction cases to run locally.  `bun` wraps the base64-encoded test case into such a command.

# Building

linking will currently fail unless you link a version of `spawn` which knows to
link against pthread:

```
opam pin add spawn https://github.com/yomimono/spawn.git#pthread
```

Otherwise, the usual `jbuilder` runes should be sufficient:

```
jbuilder build @install
```
