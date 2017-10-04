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

let pids = ref []

let crash_detector signal =
  (* we received SIGCHLD -- at least one of the pids we launched has completed.
     if more are still running, there's no reason to panic,
     but if none remain, we should clean up as if we'd received SIGTERM. *)
  (* we can waitpid with WNOHANG I guess? *)
  (* an annoying thing is we can't return anything, so the pid table still has
     to be a gross global mutable thing *)
  (* try 0 (only children in our process group) instead of -1 (any child) *)
  (* nope, that's even worse - afl-fuzz calls setsid, so that means we only get
     the stuff we *don't* want to catch *)
  Printf.printf "something signalled: %d\n%!" signal;
  List.iter (fun pid ->
      Printf.printf "was it pid %d?\n%!" pid;
      match Unix.(waitpid [WNOHANG] pid) with
      | 0, _ -> Printf.printf "nope\n%!"; () (* pid 0 means nothing was waiting *)
      | pid, _ when pid < 0 -> Printf.printf "an error: %d\n%!" pid; ()
      | pid, WSTOPPED d -> Printf.printf "yep, it was stopped: %d\n%!" d; ()
      | pid, WSIGNALED d -> Printf.printf "yep, it was signalled: %d\n%!" d; ()
      | pid, WEXITED code ->
        let other_pids = List.filter ((<>) pid) !pids in
        pids := other_pids;
        match !pids, code with
        | [], 0 ->
          Printf.printf "The last (or only) fuzzer (%d) has finished!\n%!" pid;
          (* print the crashes!!! *)
          exit 0
        | [], d ->
          Printf.printf "The last (or only) fuzzer (%d) has failed with code %d\n%!"
            pid d;
          (* failing here seems like the wrong thing to do, so let's see what
             happens if we don't *)
          exit 1
        | _, _ -> Printf.printf "yes, but I don't care\n%!"; ()
    ) !pids


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


let spawn verbosity env primary id fuzzer input output program program_argv : int =
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
  (* TODO: restore quietness when -v=0 *)
  let pid = Spawn.spawn ~env:("AFL_NO_UI=1"::env) ~prog:fuzzer ~argv () in
  Unix.sleep 2; (* give the spawned afl-fuzz a minute to finish its cpu check*)
  if (List.length verbosity) > 0 then
    Printf.printf "%s launched: PID %d\n%!" fuzzer pid;
  pid

let fuzz verbosity fuzzer parallel got_cpu input output program program_argv
  : (unit, Rresult.R.msg) result =
  let env = Unix.environment () |> Array.to_list in
  let fill_cores ~primary_pid start_id =
    let rec launch_more i : unit =
      match try_another_core got_cpu with
      | false -> ()
      | true ->
        pids :=
          (spawn verbosity env false i fuzzer input output program program_argv) ::
          !pids;
        launch_more (i+1)
    in
    launch_more (start_id + 1);
    Ok ()
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
      Sys.(set_signal sigchld (Signal_handle crash_detector));
      let primary, id = true, 1 in
      let primary_pid = spawn verbosity env primary id fuzzer input output program program_argv in
      pids := [primary_pid];
      match parallel with
      | false ->
        Common.mon verbosity pids false false
          Fpath.(output / string_of_int id / "fuzzer_stats")
      | true ->
        match fill_cores ~primary_pid id with
        | Error e -> Error e
        | Ok () ->
          Common.mon verbosity pids false false Fpath.(output / "fuzzer_stats")

let fuzz_t = Cmdliner.Term.(const fuzz
                            $ verbosity $ fuzzer
                            $ parallel $ got_cpu (* bun/mon args *)
                            $ input_dir $ output_dir
                            $ program $ program_argv) (* fuzzer flags *)

let bun_info =
  let doc = "invoke afl-fuzz on a program in a CI-friendly way" in
  Cmdliner.Term.(info ~version:"%%VERSION%%" ~exits:default_exits ~doc "bun")

let () = Cmdliner.Term.(exit @@ match eval (fuzz_t, bun_info) with
    | `Ok (Ok ()) -> `Ok (Ok ())
    | `Ok (Error (`Msg s)) -> Printf.eprintf "%s\n%!" s;
      `Error `Exn (* not quite, but close enough I guess *)
    | a -> a
  )
