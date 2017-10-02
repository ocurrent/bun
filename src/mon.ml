let fpath_conv = Cmdliner.Arg.conv Fpath.(of_string, pp)

let verbosity =
  let doc = "Report on intermediate progress." in
  Cmdliner.Arg.(value & flag_all & info ["v"] ~docv:"VERBOSE" ~doc)

let oneshot =
  let doc = "Run once and report, rather than polling the stats file." in
  Cmdliner.Arg.(value & flag & info ["oneshot"] ~docv:"ONESHOT" ~doc)

let stats =
  let doc = "Stats file to monitor.  It should be in an afl-fuzz output directory." in
  Cmdliner.Arg.(required & pos 0 (some fpath_conv) None & info [] ~docv:"STATS" ~doc)

let mon_t = Cmdliner.Term.(const Common.mon
                           $ verbosity
                           $ const None $ const true $ oneshot $ stats)

let mon_info =
  let doc = "monitor a running afl-fuzz instance, and kill it once it's tried \
             hard enough" in
  Cmdliner.Term.(info ~version:"%%VERSION%%" ~exits:default_exits ~doc "mon")

let () = Cmdliner.Term.(exit @@ eval (mon_t, mon_info))
