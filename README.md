# Building

linking will currently fail unless you link a version of `spawn` which knows to
link against pthread:

```
opam pin add spawn https://github.com/yomimono/spawn.git#pthread
```
