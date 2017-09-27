let program =
  let obligatory_file = Cmdliner.Arg.(some non_dir_file) in
  let doc = "Fuzz this program.  It should take one positional argument, the
  file to use for incoming random bytes.  (Ideally it's a Crowbar test.)" in
  Cmdliner.Arg.(required & pos 0 obligatory_file None & info [] ~docv:"PROGRAM"
                  ~doc)

let input_dir =
  let doc = "Cache of inputs to use in fuzzing the program.  Will be passed \
  through to the program as the input parameter." in
  Cmdliner.Arg.(value & opt dir "input" & info ["input"] ~docv:"INPUT" ~doc)

let output_dir =
  let doc = "Where to instruct the fuzzer to put its output." in
  Cmdliner.Arg.(value & opt dir "output" & info ["output"] ~docv:"OUTPUT" ~doc)

let fuzz input output program : (unit, Rresult.R.msg) result =
  let fuzz = "afl-fuzz" in
  let base = Bos.Cmd.v fuzz in
  match Bos.OS.Cmd.exists base with
  | Ok true ->
    let go = Bos.Cmd.(base % "-i" % input % "-o" % output % program % "@@") in
    Bos.OS.Cmd.run go
  | Ok false ->
    Error (`Msg (fuzz ^ " not found - please check $PATH")) 
  | Error (`Msg e) ->
    Error (`Msg ("couldn't try to find " ^ fuzz ^ ": " ^ e))

let fuzz_t = Cmdliner.Term.(const fuzz $ input_dir $ output_dir $ program)

let bun_info =
  let doc = "invoke afl-fuzz on a program in a CI-friendly way" in
  Cmdliner.Term.(info ~version:"%%VERSION%%" ~doc "bun")

let () = Cmdliner.Term.(exit @@ eval (fuzz_t, bun_info))

