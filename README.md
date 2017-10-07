# What is this?

`bun` is a tool for integrating fuzzer-based tests into a conventional CI pipeline.  The popular afl-fuzz tool in particular is designed to use all available compute time and keep records on persistent storage for later examination by an analyst; this particular workflow is ill-suited for cloud-based CI testing services, which do not persist storage for users and unceremoniously kill long-running processes.

## How does it work?

`bun` launches an afl-fuzz process and monitors its progress via the fuzzer_stats file.  When a cycle has completed or some crashes were found (whichever comes first), `bun` reports the progress, kills `afl-fuzz`, and exits.

## How do I use the output?

When crashes are detected, `bun` will base64-encode them and output them on the console.  You can then copy the text chunks and base64-decode them into reproduction cases to run locally.  `bun` wraps the base64-encoded test case into such a command.

## How do I run it?

See `bun --help` for the most current information.  Building `bun` with tests enabled also creates an independent binary `mon` with `bun`'s monitoring logic.  `bun` can test `mon` with `afl-fuzz` -- try `jbuilder build @runtest --no-buffer -j1` to see it in action.

Here's an example of fuzzing one of Crowbar's packaged examples, `calendar`:

```
$ bun --input=input --output=out -v ./calendar 
Executing /usr/local/bin/afl-fuzz -i input -o out -- ./calendar @@
/usr/local/bin/afl-fuzz launched: PID 23378
fuzzing hard at 2000.00 executions per second, having already discovered 0 execution paths with 100.00% stability
3 crashes found! Take a look; copy/paste to save for reproduction:
echo YWFhYWFhZABhYWFhYWFhYWFhYUBhYWFzVWY= | base64 -d > crash_$(date -u +%s).0
echo ZABUVFRUVFRUVFRUNlRUZFRUVFRUVFRUVFR9Zg== | base64 -d > crash_$(date -u +%s).1
echo Y2NjY2NjY1NjY2NjY2NjY2NjL+8= | base64 -d > crash_$(date -u +%s).2
Killing 23378...
```

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
