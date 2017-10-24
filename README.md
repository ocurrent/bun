# What is this?

`bun` is a tool for integrating fuzzer-based tests into a conventional CI pipeline.  The popular afl-fuzz tool in particular is designed to use all available compute time and keep records on persistent storage for later examination by an analyst; this particular workflow is ill-suited for cloud-based CI testing services, which do not persist storage for users and unceremoniously kill long-running processes.

## How does it work?

`bun` launches `afl-fuzz` processes and monitors their progress with `afl-whatsup`.  `afl-fuzz` instances run in a mode where they will stop when they find a crash or `afl-fuzz` determines that there is a low likelihood of finding one with additional work.

When crashes are detected on any `afl-fuzz` process, `bun` will stop the others and report the crash information.  If no crashes are detected, `bun` will continue running until the last `afl-fuzz` gives up.

## How do I use the output?

When crashes are detected, `bun` will base64-encode them and output them on the console.  You can then copy the text chunks and base64-decode them into reproduction cases to run locally.

## How do I run it?

See `bun --help` for the most current information.

Here's an example of fuzzing one of Crowbar's packaged examples, `calendar`:

```
$ bun -i input/ -o output/ ./calendar
The last (or only) fuzzer (28129) has finished!
Crashes found! Take a look; copy/paste to save for reproduction:
echo UN5QAd5Q3t7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u | base64 -d > crash_0.$(date -u +%s)
$ echo UN5QAd5Q3t7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u | base64 -d > crash_0.$(date -u +%s)
$ ./calendar crash_0.1508880277 
calendar: ....
calendar: FAIL

When given the input:

    [1825-01-30 22:50:45; 1825-03-17 04:05:41]
    
the test failed:

    1825-03-20 04:05:41 != 1825-03-17 04:05:41
    
Fatal error: exception Crowbar.TestFailure
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

# For CI

For an example of using `bun` in a CI environment, see [ocaml-test-stdlib](https://github.com/yomimono/ocaml-test-stdlib), which uses `bun` to manage its Crowbar tests in Travis CI.
