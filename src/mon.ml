let fpath_conv = Cmdliner.Arg.conv Fpath.(of_string, pp)

let output_dir =
  let doc = "Output directory for the fuzzer.  This should contain a fuzzer_stats \
             and is expected to be the -o argument to afl-fuzz." in
  Cmdliner.Arg.(required & pos 0 (some fpath_conv) None & info [] ~docv:"OUTPUT" ~doc)

let verbosity =
  let doc = "Report on intermediate progress." in
  Cmdliner.Arg.(value & flag_all & info ["v"] ~docv:"VERBOSE" ~doc)

let humane =
  let doc = "Humane mode (don't kill the fuzzer)" in
  Cmdliner.Arg.(value & flag & info ["H"] ~docv:"HUMANE" ~doc)

let oneshot =
  let doc = "Run once and report, rather than polling the stats file." in
  Cmdliner.Arg.(value & flag & info ["oneshot"] ~docv:"ONESHOT" ~doc)

let stats =
  let doc = "Stats file to monitor, if not OUTPUT/fuzzer_stats ." in
  Cmdliner.Arg.(value & opt (some fpath_conv) None & info ["statsfile"] ~docv:"STATS" ~doc)

let mon_t = Cmdliner.Term.(const Common.mon
                           $ verbosity $ humane $ oneshot $ stats $ output_dir)

let mon_info =
  let doc = "monitor a running afl-fuzz instance, and kill it once it's tried \
             hard enough" in
  Cmdliner.Term.(info ~version:"%%VERSION%%" ~exits:default_exits ~doc "mon")

let () = AflPersistent.run (fun () -> Cmdliner.Term.(exit @@ eval (mon_t,
                                                                   mon_info)))
