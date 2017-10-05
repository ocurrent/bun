let fpath_conv = Cmdliner.Arg.conv Fpath.(of_string, pp)

let verbosity =
  let doc = "Report on intermediate progress." in
  Cmdliner.Arg.(value & flag_all & info ["v"] ~docv:"VERBOSE" ~doc)

let oneshot =
  let doc = "Run once and report, rather than continually monitoring forever." in
  Cmdliner.Arg.(value & flag & info ["oneshot"] ~docv:"ONESHOT" ~doc)

let directory =
  let doc = "Directory to monitor for AFL stats (should have been given as -o \
             to some afl-fuzz or bun invocations)" in
  Cmdliner.Arg.(required & pos 0 (some fpath_conv) None & info []
                  ~docv:"DIRECTORY" ~doc)

let mon_t = Cmdliner.Term.(const Common.mon
                           $ verbosity
                           $ const (ref [] : int list ref)
                           $ oneshot $ directory)

let mon_info =
  let doc = "monitor a running afl-fuzz instance, and kill it once it's tried \
             hard enough" in
  Cmdliner.Term.(info ~version:"%%VERSION%%" ~exits:default_exits ~doc "mon")

let () = Cmdliner.Term.(exit @@ eval (mon_t, mon_info))
