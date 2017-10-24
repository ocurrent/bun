let program =
  let doc = "Fuzz this program. (Ideally it's a Crowbar test; if it isn't, \
  ensure that it takes, as its last argument, a file for afl-fuzz to pass it.)"
  in
  Cmdliner.Arg.(required & pos 0 (some non_dir_file) None &
                info [] ~docv:"PROGRAM" ~doc)

let program_argv =
  let doc = "Arguments to the program to be fuzzed.  These will be prepended \
             to the invocation, and the file to be considered as input last; \
             in other words, `bun myprogram --for-fun on-fire` will run \
             `afl-fuzz {afl arguments} -- myprogram --for-fun on-fire @@`." in
  Cmdliner.Arg.(value & pos_right 0 string [] & info [] ~docv:"PROGRAM_ARGS"
                  ~doc)

let single_core =
  let doc = "Start only one fuzzer instance, even if more CPU cores are \
             available.  Even in this mode, the (lone) fuzzer will be invoked \
             with -S and an id; for more on implications, see the afl-fuzz \
             parallel_fuzzing.txt docuentation." in
  Cmdliner.Arg.(value & flag & info ["s"; "single-core"] ~docv:"SINGLE_CORE" ~doc)

let verbosity =
  let doc = "Verbosity. -v echoes what `bun` is invoking and is noisier in \
             error cases; -vv gets stdout from the underlying fuzzer." in
  Cmdliner.Arg.(value & flag_all & info ["v"] ~docv:"VERBOSE" ~doc)

let fpath_conv = Cmdliner.Arg.conv Fpath.(of_string, pp)

let input_dir =
  let doc = "Cache of inputs to use in fuzzing the program.  Will be passed \
  through to the fuzzer as the input parameter." in
  Cmdliner.Arg.(value & opt fpath_conv (Fpath.v "input")
                & info ["i"; "input"] ~docv:"INPUT" ~doc)

let output_dir =
  let doc = "Where to instruct the fuzzer to put its output." in
  Cmdliner.Arg.(value & opt fpath_conv (Fpath.v "output")
                & info ["o"; "output"] ~docv:"OUTPUT" ~doc)

let memory =
  let doc = "Memory limit to pass to the fuzzer." in
  Cmdliner.Arg.(value & opt int 200
                & info ["mem"; "m"] ~docv:"MEMORY" ~doc ~env:(env_var "MEMORY"))

let fuzzer =
  let doc = "The fuzzer to invoke." in
  Cmdliner.Arg.(value & opt file "/usr/local/bin/afl-fuzz"
                & info ["fuzzer"] ~docv:"FUZZER" ~doc ~env:(env_var "FUZZER"))

let gotcpu =
  let doc = "The command to run to see whether more cores are available. For \
             all practical purposes, it should be afl-gotcpu." in
  Cmdliner.Arg.(value & opt file "/usr/local/bin/afl-gotcpu"
                & info ["gotcpu"] ~docv:"GOTCPU" ~doc)

let whatsup =
  let doc = "The command to run to display information on the fuzzer stats \
  during operation.  This is usually afl-whatsup, but `ocaml-bun` is not \
             sensitive to its output, so you can use whatever you like." in
  Cmdliner.Arg.(value & opt file "/usr/local/bin/afl-whatsup" & info ["whatsup"]
                  ~docv:"WHATSUP" ~doc)

let pids = ref []

let terminate_child_processes =
  List.iter (fun (pid, _) ->
      try Unix.kill Sys.sigterm ((-1) * pid) (* kill the whole pgroup *)
      with Unix.Unix_error(Unix.ESRCH, _, _) -> () (* it's OK if it's already dead *)
    )

let term_handler _sigterm =
  Printf.printf "Terminating the remaining fuzzing processes in response to SIGTERM.\n";
  Printf.printf "It's likely that this job could benefit from more fuzzing time \
  - consider running it in an environment with more available cores or allowing \
  the fuzzers more time to explore the state space, if possible.\n%!";
  terminate_child_processes !pids

let crash_detector output _sigchld =
  (* we received SIGCHLD -- at least one of the pids we launched has completed.
     if more are still running, there's no reason to panic,
     but if none remain (or if the pid completed because it found a crash),
     we should clean up as if we'd received SIGTERM. *)
  List.iter (fun (pid, _id) ->
      match Unix.(waitpid [WNOHANG] pid) with
      | 0, _ -> () (* pid 0 means nothing was waiting *)
      | pid, _ when pid < 0 -> (* an error *) ()
      | _pid, WSTOPPED _ | _pid, WSIGNALED _ -> (* we don't care *) ()
      | pid, WEXITED code ->
        let other_pids, our_pids = List.partition (fun i -> (<>) pid (fst i)) !pids in
        pids := other_pids;
        match !pids, code with
        | [], 0 -> begin
          Printf.printf "The last (or only) fuzzer (%d) has finished!\n%!" pid;
          Common.Print.print_crashes output |> Rresult.R.get_ok;
          match Common.Parse.get_crash_files output with
          | Ok [] -> exit 0
          | _ -> exit 1
        end
        | [], d ->
          Printf.printf "The last (or only) fuzzer (%d) has failed with code %d\n%!"
            pid d;
          Common.Print.print_crashes output |> Rresult.R.get_ok;
          exit 1
        | _, _ ->
          (* other fuzzers are still active, but if we've crashed, we should
             still exit *)
          (* see whether this pid found a crash *)
          try
            let id = List.assoc pid our_pids in
            (* we can't look up whether this pid found a crash. we
                          could check whether *any* pid found a crash, which
                          might be preferable; TODO *)
            match Common.Parse.get_stats_lines ~id:(string_of_int id) output with
            | Error _ | Ok [] -> () (* if it did, we can't know about it *)
            | Ok lines -> match Common.Parse.(get_stats lines |> lookup_crashes) with
              | Some 0 | None -> (* no crashes, so no further action needed here *) ()
              | Some _ -> (* all done, then! *)
                terminate_child_processes other_pids;
                (* instead of going immediately into cleanup and exit,
                   go back to normal program flow so we have a chance to
                   waitpid on the remaining stuff, so child processes can clean 
                   up (including any write tasks they may have pending) *)
                ()
          with
          | Not_found -> ()
    ) !pids


let how_many_cores cpu =
  (* it's better to check once to see how many afl-fuzzes we can spawn, and then
     let afl-fuzz's own startup jitter plus a small delay from us 
     ensure they don't step on each others' toes when discovering CPU
     affinity. *)
  let er = Rresult.R.error_msg_to_invalid_arg in
  try
    Bos.OS.Cmd.(run_out ~err:err_run_out (Bos.Cmd.v cpu) |> out_run_in |> er) |>
    Common.Parse.get_cores |> er
  with
  | Not_found | Invalid_argument _ | Failure _ -> 0

let spawn verbosity env id fuzzer memory input output program program_argv : int =
  let argv = [fuzzer;
              "-m"; (string_of_int memory);
              "-i"; (Fpath.to_string input);
              "-o"; (Fpath.to_string output);
              "-S"; string_of_int id;
              "--"; program; ] @ program_argv @ ["@@"] in
  if (List.length verbosity) > 0 then Printf.printf "Executing %s\n%!" @@
    String.concat " " argv;
  let stdout = match (List.length verbosity) > 1 with
    | true -> Unix.stdout
    | false ->
      Unix.openfile (Fpath.to_string Bos.OS.File.null) [Unix.O_WRONLY] 0o000
  in
  (* see afl-latest's docs/env_variables.txt for information on these --
     the variables we pass ask AFL to finish after it's "done" (the cycle
     counter would turn green in the UI) or it's found a crash *)
  let env = "AFL_EXIT_WHEN_DONE=1"::"AFL_NO_UI=1"::"AFL_BENCH_UNTIL_CRASH=1"::
            env in
  let pid = Spawn.spawn ~env ~stdout ~prog:fuzzer ~argv () in
  if (List.length verbosity) > 0 then
    Printf.printf "%s launched: PID %d\n%!" fuzzer pid;
  pid

let fuzz verbosity single_core fuzzer whatsup gotcpu input output memory program program_argv
  : (unit, Rresult.R.msg) result =
  let env = Unix.environment () |> Array.to_list in
  let max =
    match single_core, how_many_cores gotcpu with
    | true, n when n > 1 -> 1
    | _, n -> n
  in
  let fill_cores start_id =
    let rec launch_more max i =
      if i > max then () else begin
        pids := ((spawn verbosity env i fuzzer memory input output program
                    program_argv), i) :: !pids;
        launch_more max (i+1)
      end
    in
    launch_more max (start_id + 1)
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
      Sys.(set_signal sigterm (Signal_handle term_handler));
      Sys.(set_signal sigchld (Signal_handle (crash_detector output)));
      let id = 1 in
      let primary_pid = spawn verbosity env id fuzzer memory input output
          program program_argv in
      pids := [primary_pid, id];
      match single_core with
      | true -> Common.mon verbosity whatsup pids output
      | false ->
        Unix.sleep 1; (* make sure other CPU detection doesn't stomp ours *)
        fill_cores id;
        Common.mon verbosity whatsup pids output

let fuzz_t = Cmdliner.Term.(const fuzz
                            $ verbosity $ single_core (* bun/mon args *)
                            $ fuzzer $ whatsup $ gotcpu (* external cmds *)
                            $ input_dir $ output_dir $ memory
                            $ program $ program_argv) (* fuzzer flags *)

let bun_info =
  let doc = "invoke afl-fuzz on a program in a CI-friendly way" in
  Cmdliner.Term.(info ~version:"%%VERSION%%" ~exits:default_exits ~doc "bun")

let () = Cmdliner.Term.exit @@ match Cmdliner.Term.eval (fuzz_t, bun_info) with
    | `Ok (Error (`Msg s)) -> Printf.eprintf "%s\n%!" s;
      `Error `Exn
    | a -> a
