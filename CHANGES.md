v0.3.2 2018-05-01
-----------------

- use spawn v0.12 API (#5, @diml)

v0.3.1 2018-05-01
-----------------

- use alarms/pause instead of sleeping to prevent hanging around after fuzzers have terminated (fixes #3 reported by github user gasche - thanks!)
- add a --max-cores option, to be considerate when appropriate (#2, by gasche)
- add some tests and CI for this test and CI thing

v0.3 2018-04-04
---------------

- set up input directory if the user hasn't already
- avoid ugly invocation of whatsup before fuzzers have reported their status

v0.2 2018-03-29
---------------

- better pathfinding for the fuzzer
- add a no-kill mode (-n) to continue fuzzing after the first bug is found
- dump the crash data when bun receives SIGUSR1
- try harder to avoid CPU detection collisions
- tighten up dependency specifications for opam

v0.1 2017-10-24
---------------

- Initial pre-release.
