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

let single_core =
  let doc = "Start only one fuzzer instance, even if more CPU cores are available." in
  Cmdliner.Arg.(value & flag & info ["s"; "single-core"] ~docv:"SINGLE_CORE" ~doc)

let verbosity =
  let doc = "Report on intermediate progress.  -vv passes through stdout from \
  the fuzzer" in
  Cmdliner.Arg.(value & flag_all & info ["v"] ~docv:"VERBOSE" ~doc)

let fpath_conv = Cmdliner.Arg.conv Fpath.(of_string, pp)

let input_dir =
  let doc = "Cache of inputs to use in fuzzing the program.  Will be passed \
  through to the program as the input parameter." in
  Cmdliner.Arg.(value & opt fpath_conv (Fpath.v "input")
                & info ["i"; "input"] ~docv:"INPUT" ~doc)

let output_dir =
  let doc = "Where to instruct the fuzzer to put its output." in
  Cmdliner.Arg.(value & opt fpath_conv (Fpath.v "output")
                & info ["o"; "output"] ~docv:"OUTPUT" ~doc)

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

let crash_detector output _sigchld =
  (* we received SIGCHLD -- at least one of the pids we launched has completed.
     if more are still running, there's no reason to panic,
     but if none remain (or if the pid completed because it found a crash),
     we should clean up as if we'd received SIGTERM. *)
  (* (currently we know it's sigchld because that's the only signal we installed
     this handler for, but if that changes we'll need to care what we were
     passed) *)
  List.iter (fun (pid, _id) ->
      match Unix.(waitpid [WNOHANG] pid) with
      | 0, _ -> () (* pid 0 means nothing was waiting *)
      | pid, _ when pid < 0 -> (* an error *) ()
      | _pid, WSTOPPED _ | _pid, WSIGNALED _ -> (* we don't care *) ()
      | pid, WEXITED code ->
        let other_pids, our_pids = List.partition (fun i -> (<>) pid (fst i)) !pids in
        pids := other_pids;
        match !pids, code with
        | [], 0 ->
          Printf.printf "The last (or only) fuzzer (%d) has finished!\n%!" pid;
          Common.Print.print_crashes output |> Rresult.R.get_ok;
          exit 0
        | [], d ->
          Printf.printf "The last (or only) fuzzer (%d) has failed with code %d\n%!"
            pid d;
          Common.Print.print_crashes output |> Rresult.R.get_ok;
          exit 1
        | _, _ ->
          (* other fuzzers are still active, but if we've crashed, we should
             still exit *)
          (* see whether this pid found a crash *)
          match List.assoc_opt pid our_pids with
          | None -> () (* we can't look up whether this pid found a crash. we
                          could check whether *any* pid found a crash, which
                          might be preferable; TODO *)
          | Some id ->
            match Common.Parse.get_stats_lines ~id:(string_of_int id) output with
            | Error _ | Ok [] -> () (* if it did, we can't know about it *)
            | Ok lines -> match Common.Parse.(get_stats lines |> lookup_crashes) with
              | Some 0 | None -> (* no crashes, so no further action needed here *) ()
              | Some _ -> (* all done, then! *)
                List.iter (fun (pid, _) ->
                    try Unix.kill Sys.sigterm ((-1) * pid) (* kill the whole
                                                              pgroup *)
                    with Unix.Unix_error(Unix.ESRCH, _, _) ->
                     (* it's OK if it's already dead *) ()
                  ) other_pids;
                (* instead of going immediately into cleanup and exit,
                   go back to normal program flow so we have a chance to
                   waitpid on the remaining stuff, so child processes can clean 
                   up (including any write tasks they may have pending) *)
                ()
    ) !pids


let how_many_cores cpu =
  (* The return code will tell us whether *any* cores are free, which is
     helpful, but we'd like also to know *how many* are free. *)
  let cpucheck = Bos.Cmd.v cpu in
  let more_processes = Bos.Cmd.(v "grep" % "more processes on") in
  match Bos.OS.Cmd.(run_out ~err:err_run_out cpucheck |> out_run_in) with
  | Error _ -> 0
  | Ok cpucheck_output ->
    let open Bos.OS.Cmd in
    match run_io more_processes cpucheck_output |> to_lines with
    | Error _ -> 0
    | Ok l ->
    try
      match List.map (fun l -> Astring.String.cut ~sep:"more processes on " l) l
            |> List.find (function | Some _ -> true | None -> false) with
      | None -> 0
      | Some (_, cores) -> Astring.String.fields cores |> List.hd |> int_of_string
    with
    | Not_found | Invalid_argument _ | Failure _ -> 0


let spawn verbosity env id fuzzer input output program program_argv : int =
  let parallelize num = ["-S"; string_of_int num] in
  let argv = [fuzzer; "-i"; (Fpath.to_string input);
              "-o"; (Fpath.to_string output); ]
              @ (parallelize id) @
              ["--"; program; ] @ program_argv @ ["@@"] in
  if (List.length verbosity) > 0 then Printf.printf "Executing %s\n%!" @@
    String.concat " " argv;
  let stdout = match (List.length verbosity) > 1 with
    | true ->
      Unix.stdout
    | false ->
      Unix.openfile (Fpath.to_string Bos.OS.File.null) [] 0o000
  in
  (* see afl-latest's docs/env_variables.txt for information on these --
     the variables we pass ask AFL to finish after it's "done" (the cycle
     counter would turn green in the UI) or it's found a crash *)
  let env = "AFL_EXIT_WHEN_DONE=1"::"AFL_NO_UI=1"::"AFL_BENCH_UNTIL_CRASH=1"::env in
  let pid = Spawn.spawn ~env ~stdout ~prog:fuzzer ~argv () in
  if (List.length verbosity) > 0 then
    Printf.printf "%s launched: PID %d\n%!" fuzzer pid;
  pid

let fuzz verbosity fuzzer single_core got_cpu input output program program_argv
  : (unit, Rresult.R.msg) result =
  let env = Unix.environment () |> Array.to_list in
  let max =
    match single_core, how_many_cores got_cpu with
    | true, n when n > 1 -> 1
    | _, n -> n
  in
  let fill_cores start_id =
    let rec launch_more max i : unit =
      match i <= max with
      | false -> ()
      | true ->
        pids :=
          ((spawn verbosity env i fuzzer input output program
             program_argv), i) ::
          !pids;
        launch_more max (i+1)
    in
    launch_more max (start_id + 1);
    Ok ()
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
      Sys.(set_signal sigchld (Signal_handle (crash_detector output)));
      let id = 1 in
      let primary_pid = spawn verbosity env id fuzzer input output program program_argv in
      pids := [primary_pid, id];
      match single_core with
      | true ->
        Common.mon verbosity pids false output
      | false ->
        Unix.sleep 1; (* make sure other CPU detection doesn't stomp ours *)
        match fill_cores id with
        | Error e -> Error e
        | Ok () ->
          Common.mon verbosity pids false output

let fuzz_t = Cmdliner.Term.(const fuzz
                            $ verbosity $ fuzzer
                            $ single_core $ got_cpu (* bun/mon args *)
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
