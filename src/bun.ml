
let program =
  let obligatory_file = Cmdliner.Arg.(some non_dir_file) in
  let doc = "Fuzz this program.  (Ideally it's a Crowbar test.)" in
  Cmdliner.Arg.(required & pos 0 obligatory_file None & info [] ~docv:"PROGRAM"
                  ~doc)

let program_argv =
  let doc = "Arguments to the program to be fuzzed.  These will be prepended \
             to the invocation, and the file to be considered as input last; \
             in other words, `bun myprogram --for-fun on-fire` will run \
             `afl-fuzz {afl arguments} -- myprogram --for-fun on-fire @@`." in
  Cmdliner.Arg.(value & pos_right 0 string [] & info [] ~docv:"PROGRAM_ARGS"
                  ~doc)

let parallel =
  let doc = "Start more fuzzer instances in parallel, if CPU is available." in
  Cmdliner.Arg.(value & flag & info ["p"] ~docv:"PARALLEL" ~doc)

let verbosity =
  let doc = "Report on intermediate progress." in
  Cmdliner.Arg.(value & flag_all & info ["v"] ~docv:"VERBOSE" ~doc)

let fpath_conv = Cmdliner.Arg.conv Fpath.(of_string, pp)

let input_dir =
  let doc = "Cache of inputs to use in fuzzing the program.  Will be passed \
  through to the program as the input parameter." in
  Cmdliner.Arg.(value & opt fpath_conv (Fpath.v "input")
                & info ["input"] ~docv:"INPUT" ~doc)

let output_dir =
  let doc = "Where to instruct the fuzzer to put its output." in
  Cmdliner.Arg.(value & opt fpath_conv (Fpath.v "output")
                & info ["output"] ~docv:"OUTPUT" ~doc)

let fuzzer =
  let doc = "The fuzzer to invoke." in
  Cmdliner.Arg.(value & opt file "/usr/local/bin/afl-fuzz"
                & info ["fuzzer"] ~docv:"FUZZER" ~doc ~env:(env_var "FUZZER"))

let got_cpu =
  let doc = "The command to run to see whether more cores are available.  It \
             should exit with 0 if more cores are available for fuzzing,
             and 1 if they are not." in
  Cmdliner.Arg.(value & opt file "/usr/local/bin/afl-gotcpu"
                & info ["got_cpu"] ~docv:"CPUCHECK" ~doc)

let try_another_core cpu =
  let cmd = Bos.Cmd.v cpu in
  Bos.OS.Cmd.(match run_out cmd |> out_null with
      | Ok (_, (_, `Exited 0)) -> true
      | Ok _ | Error _ -> false)

let is_running pid =
  let cmd = Bos.Cmd.(v "pmap" % string_of_int pid) in
  Bos.OS.Cmd.(match run_out cmd |> out_null with
      | Ok (_, (_, `Exited 0)) -> Ok true
      | Ok (_, (_, `Exited 42)) -> Ok false
      | Ok _ -> Ok false
      | Error e -> Error e)

let pids = ref []

let crash_detector pids _ =
  (* we received SIGCHLD -- at least one of the pids we launched has completed.
     if more are still running, there's no reason to panic,
     but if none remain, we should clean up as if we'd received SIGTERM. *)
  (* we can waitpid with WNOHANG in a loop I guess? *)
  (* an annoying thing is we can't return anything, so the pid table still has
     to be a gross global mutable thing *)
  ()


let spawn verbosity primary id fuzzer input output program program_argv : int =
  let parallelize ~primary num =
    match primary with
    | false -> ["-S"; string_of_int num]
    | true -> ["-M"; string_of_int num]
  in
  let argv = [fuzzer; "-i"; (Fpath.to_string input);
              "-o"; (Fpath.to_string output); ]
              @ (parallelize ~primary id) @
              ["--"; program; ] @ program_argv @ ["@@"] in
  if (List.length verbosity) > 0 then Printf.printf "Executing %s\n%!" @@
    String.concat " " argv;
  let null_fd = Unix.openfile (Fpath.to_string Bos.OS.File.null) [] 0o000 in
  let pid = Spawn.spawn ~stdout:null_fd ~prog:fuzzer ~argv () in
  Unix.close null_fd;
  if (List.length verbosity) > 0 then
    Printf.printf "%s launched: PID %d\n%!" fuzzer pid;
  pid

let fuzz verbosity fuzzer parallel got_cpu input output program program_argv
  : (unit, Rresult.R.msg) result =
  let fill_cores ~primary_pid start_id =
    let rec launch_more i (l : int list) : int list =
      match try_another_core got_cpu with
      | false -> l
      | true -> launch_more (i+1) @@
        spawn verbosity false i fuzzer input output program program_argv :: l 
    in
    match is_running primary_pid with
    | Error e -> Error e
    | Ok false ->
      let fail = Printf.sprintf "fuzzer (PID %d) died :(\n%!" primary_pid in
      Error (`Msg fail)
    | Ok true ->
      let other_pids = launch_more (start_id + 1) [] in
      Ok (primary_pid :: other_pids)
    (* monitor the process we just started with `mon`, and kill it when useful
         results have been obtained *)
  in
  match Bos.OS.Dir.create output with
  | Error e -> Error e
  | Ok _ ->
    match Bos.OS.Cmd.exists (Bos.Cmd.(v fuzzer)) with
    | Ok false ->
      Error (`Msg (fuzzer ^ " not found - please ensure it exists and is an executable file"))
    | Error (`Msg e) ->
      Error (`Msg ("couldn't try to find " ^ fuzzer ^ ": " ^ e))
    | Ok true ->
      (* always start at least one afl-fuzz *)
      let primary, id = true, 1 in
      let primary_pid = spawn verbosity primary id fuzzer input output program program_argv in
      match parallel with
      | false ->
        pids := [primary_pid];
        Common.mon verbosity pids false false
          Fpath.(output / string_of_int id / "fuzzer_stats")
      | true ->
        match fill_cores ~primary_pid id with
        | Error e -> Error e
        | Ok pid_list ->
          pids := pid_list;
          Common.mon verbosity pids false false Fpath.(output / "fuzzer_stats")

let fuzz_t = Cmdliner.Term.(const fuzz
                            $ verbosity $ fuzzer
                            $ parallel $ got_cpu (* bun/mon args *)
                            $ input_dir $ output_dir (* fuzzer flags *)
                            $ program $ program_argv)

let bun_info =
  let doc = "invoke afl-fuzz on a program in a CI-friendly way" in
  Cmdliner.Term.(info ~version:"%%VERSION%%" ~exits:default_exits ~doc "bun")

let () = Cmdliner.Term.(exit @@ match eval (fuzz_t, bun_info) with
    | `Ok (Ok ()) -> `Ok (Ok ())
    | `Ok (Error (`Msg s)) -> Printf.eprintf "%s\n%!" s;
      `Error `Exn (* not quite, but close enough I guess *)
    | a -> a
  )
