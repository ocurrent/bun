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
             parallel_fuzzing.txt documentation." in
  Cmdliner.Arg.(value & flag & info ["s"; "single-core"] ~docv:"SINGLE_CORE" ~doc)

let max_cores =
  let doc = "Maximum number of instances to run -- of CPU cores to use. \
             If no value is given, all the cores found by GOTCPU \
             will be used." in
  Cmdliner.Arg.(value & opt (some int) None
                & info ["max-cores"] ~docv:"MAX_CORES" ~doc ~env:(env_var "MAX_CORES"))

let no_kill =
  let doc = "Allow afl-fuzz to continue attempting to find crashes after the
  first crash is discovered.  In this mode, individual afl-fuzz instances will
  not automatically terminate after discovering crashes, nor will bun kill all
  other instances once a single instance terminates for any reason." in
  Cmdliner.Arg.(value & flag & info ["n"; "no-kill"] ~docv:"NO_KILL" ~doc)

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
  Cmdliner.Arg.(value & opt file "afl-fuzz"
                & info ["fuzzer"] ~docv:"FUZZER" ~doc ~env:(env_var "FUZZER"))

let gotcpu =
  let doc = "The command to run to see whether more cores are available. For \
             all practical purposes, it should be afl-gotcpu." in
  Cmdliner.Arg.(value & opt file "afl-gotcpu"
                & info ["gotcpu"] ~docv:"GOTCPU" ~doc ~env:(env_var "GOTCPU"))

let whatsup =
  let doc = "The command to run to display information on the fuzzer stats \
  during operation.  This is usually afl-whatsup, but `ocaml-bun` is not \
             sensitive to its output, so you can use whatever you like." in
  Cmdliner.Arg.(value & opt file "afl-whatsup" & info ["whatsup"]
                  ~docv:"WHATSUP" ~doc ~env:(env_var "WHATSUP"))

let pids = ref []

let mon verbose whatsup output =
  match Bos.OS.Path.matches @@ Fpath.(output / "$(dir)" / "fuzzer_stats") with
  | Error (`Msg e) ->
    (* this is probably just a race -- keep trying *)
    (* (but TODO retry-bound this and print an appropriate message if it doesn't
       look like we were just too fast *)
    if (List.length verbose > 0) then
      Printf.eprintf "No fuzzer_stats in the output directory:%s\n%!" e;
    ignore @@ Unix.alarm 5;
    Unix.pause ()
  | Ok [] ->
    if (List.length verbose > 1) then
      Printf.eprintf "No fuzzer stats files found - waiting on the world to \
                      change\n%!";
    ignore @@ Unix.alarm 5;
    Unix.pause ()
  | Ok _ ->
    (* the caller will know if all children have died. *)
    (* no compelling reason to reimplement afl-whatsup at the moment.
       if that changes, check commit history for the `mon` binary and its
       associated code, which parses `fuzzer_stats` itself and doubles as a nice
       thing for `bun` to test itself on. *)
    let () =
      match Bos.OS.Cmd.run Bos.Cmd.(v whatsup % Fpath.to_string output) with
      | Error (`Msg e) -> if (List.length verbose > 0) then
          Printf.eprintf "error running whatsup: %s\n%!" e
      | Ok () -> ()
    in
    ignore @@ Unix.alarm 60;
    Unix.pause ()

let terminate_child_processes =
  List.iter (fun (pid, _) ->
      try Unix.kill (pid) Sys.sigterm (* kill the whole pgroup *)
      with Unix.Unix_error(Unix.ESRCH, _, _) -> () (* it's OK if it's already dead *)
    )

let term_handler _sigterm =
  Printf.printf "Terminating the remaining fuzzing processes in response to SIGTERM.\n";
  Printf.printf "It's likely that this job could benefit from more fuzzing time \
  - consider running it in an environment with more available cores or allowing \
  the fuzzers more time to explore the state space, if possible.\n%!";
  terminate_child_processes !pids

(* TODO: apparently printf in signal handlers is a no-no *)
let crash_detector no_kill output _sigchld =
  (* we received SIGCHLD -- at least one of the pids we launched has completed.
     if more are still running, there's no reason to panic,
     but if none remain (or if the pid completed because it found a crash and
     no_kill is not set), we should clean up as if we'd received SIGTERM. *)
  List.iter (fun (pid, _id) ->
      match Unix.(waitpid [WNOHANG] pid) with
      | 0, _ -> Printf.printf "All fuzzers have terminated.\n%!"; () (* pid 0 means nothing was waiting *)
      | pid, _ when pid < 0 -> (* an error *) ()
      | _pid, WSTOPPED _ -> (* we don't care *) ()
      | pid, status ->
        let other_pids, our_pids = List.partition (fun i -> (<>) pid (fst i)) !pids in
        pids := other_pids;
        match !pids, status with
        | [], WEXITED 0 -> begin
          Printf.printf "The last (or only) fuzzer (%d) has finished!\n%!" pid;
          Files.Print.print_crashes output |> Rresult.R.get_ok;
          match Files.Parse.get_crash_files output with
          | Ok [] -> exit 0
          | _ -> exit 1
        end
        | [], WEXITED d ->
          Printf.printf "The last (or only) fuzzer (%d) has failed with code %d\n%!"
            pid d;
          Files.Print.print_crashes output |> Rresult.R.get_ok;
          exit 1
        | [], WSIGNALED s ->
          Printf.printf "The last (or only) fuzzer (%d) was killed by signal %d\n%!"
            pid s;
          Files.Print.print_crashes output |> Rresult.R.get_ok;
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
            match Files.Parse.get_stats_lines ~id:(string_of_int id) output with
            | Error _ | Ok [] -> () (* if it did, we can't know about it *)
            | Ok lines -> match Files.Parse.(get_stats lines |> lookup_crashes) with
              | Some 0 | None -> (* no crashes, so no further action needed here *) ()
              | Some _ -> (* all done, then! *)
                match no_kill with
                | false -> terminate_child_processes other_pids
                (* instead of going immediately into cleanup and exit,
                   go back to normal program flow so we have a chance to
                   waitpid on the remaining stuff, so child processes can clean 
                   up (including any write tasks they may have pending) *)
                | true -> ()
          with
          | Not_found -> ()
    ) !pids


let spawn verbosity env id fuzzer memory input output program program_argv =
  let fuzzer = Fpath.to_string fuzzer in
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
      Unix.openfile (Fpath.to_string Bos.OS.File.null) [Unix.O_WRONLY] 0o200
  in
  (* see afl-latest's docs/env_variables.txt for information on these --
     the variables we pass ask AFL to finish after it's "done" (the cycle
     counter would turn green in the UI) or it's found a crash, plus the obvious
     (if sad) request not to show us its excellent UI *)
  let env = Spawn.Env.of_list ("AFL_EXIT_WHEN_DONE=1"::"AFL_NO_UI=1"::env) in
  let pid = Spawn.spawn ~env ~stdout ~prog:fuzzer ~argv () in
  if (List.length verbosity) > 0 then
    Printf.printf "%s launched: PID %d\n%!" fuzzer pid;
  pid

let fuzz verbosity no_kill single_core max_cores
         fuzzer whatsup gotcpu
         input output memory program program_argv
  : (unit, Rresult.R.msg) result =
  let open Rresult.R.Infix in
  let env = Unix.environment () |> Array.to_list |> fun env ->
            match no_kill with | false -> "AFL_BENCH_UNTIL_CRASH=1"::env
                               | true -> env
  in
  let cores =
    let limit = if single_core then Some 1 else max_cores in
    let available = Files.Parse.get_cores verbosity gotcpu in
    match limit with
    | None -> available
    | Some limit ->
      (* always launch at least 1 *)
      max 1 (min available limit)
  in
  Files.fixup_input input >>= fun () ->
  if (List.length verbosity) > 0 then
    Printf.printf "%d available cores detected!\n%!" cores;
  let fill_cores fuzzer start_id =
    let rec launch_more max i =
      if i > max then () else begin
        pids := ((spawn verbosity env i fuzzer memory input output program
                    program_argv), i) :: !pids;
        launch_more cores (i+1)
      end
    in
    launch_more cores start_id
  in
  Bos.OS.Cmd.find_tool Bos.Cmd.(v fuzzer) >>= function
  | None -> Error (`Msg (Fmt.strf "could not find %s to invoke it -- \
                                   try specifying the full path, or ensuring the binary \
                                   is in your PATH" fuzzer))
  | Some fuzzer ->
  Bos.OS.Dir.create output >>= fun _ ->
  (* always start at least one afl-fuzz *)
  Sys.(set_signal sigterm (Signal_handle term_handler));
  Sys.(set_signal sigchld (Signal_handle (crash_detector no_kill output)));
  Sys.(set_signal sigalrm (Signal_handle (fun _ -> mon verbosity whatsup output)));
  Sys.(set_signal sigusr1 (Signal_handle (fun _ -> Files.Print.print_crashes output |>
                                          fun _ -> ())));
  let id = 1 in
  match single_core with
  | true ->
    let primary_pid = spawn verbosity env id fuzzer memory input output
      program program_argv in
    pids := [primary_pid, id];
    let delay = 60 in
    Printf.printf "Fuzzers launched.  Waiting %d seconds for the first status update...\n%!" delay;
    ignore @@ Unix.alarm delay; (* Signal handler for sigalrm will call `mon` in 60s *)
    Ok (Unix.pause ())
  | false ->
    (* check once to see how many afl-fuzzes we can spawn, and then
       let afl-fuzz's own startup jitter plus a small delay from us 
       ensure they don't step on each others' toes when discovering CPU
       affinity. *)
    fill_cores fuzzer id;
    let delay = max 1 (60 - cores) in
    Printf.printf "Fuzzers launched.  Waiting %d seconds for the first status update...\n%!" delay;
    ignore @@ Unix.alarm delay;
    Ok (Unix.pause ())

let fuzz_t =
  Cmdliner.Term.(const fuzz
                 $ verbosity $ no_kill $ single_core $ max_cores (* bun/mon args *)
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
