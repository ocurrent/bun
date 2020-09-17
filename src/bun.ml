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

let no_main_instance =
  let doc = "Do not run a main instance (a main instance is required by afl++, but not afl)" in
  Cmdliner.Arg.(value & flag & info ["no-main-instance"] ~docv:"NO_MAIN" ~doc)


let single_core =
  let doc = "Start only one fuzzer instance, even if more CPU cores are \
             available.  Even in this mode, the (lone) fuzzer will be invoked \
             with -S/-M and an id; for more on implications, see the afl-fuzz \
             parallel_fuzzing.txt documentation." in
  Cmdliner.Arg.(value & flag & info ["s"; "single-core"] ~docv:"SINGLE_CORE" ~doc)

let max_cores =
  let doc = "Maximum number of instances to run -- of CPU cores to use. \
             If no value is given, all the cores found by GOTCPU \
             will be used." in
  Cmdliner.Arg.(value & opt (some int) None
                & info ["max-cores"] ~docv:"MAX_CORES" ~doc ~env:(env_var "MAX_CORES"))

let no_cgroups =
  let doc = "Do not use cgroups for managing child processes" in
  Cmdliner.Arg.(value & flag & info ["no-cgroups"] ~docv:"NO_CGROUPS" ~doc)

let no_kill =
  let doc = "Allow afl-fuzz to continue attempting to find crashes after the
  first crash is discovered.  In this mode, individual afl-fuzz instances will
  not automatically terminate after discovering crashes, nor will bun kill all
  other instances once a single instance terminates for any reason." in
  Cmdliner.Arg.(value & flag & info ["n"; "no-kill"] ~docv:"NO_KILL" ~doc)

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

(* Print progress reports from time to time. *)
let mon whatsup output =
  let open Lwt.Infix in
  (* Give things a chance to start... *)
  Lwt_unix.sleep 5.0 >>= fun () ->
  let rec loop () =
    Logs.info (fun f -> f "Checking progress...");
    match Bos.OS.Path.matches @@ Fpath.(output / "$(dir)" / "fuzzer_stats") with
    | Error (`Msg e) ->
      (* this is probably just a race -- keep trying *)
      (* (but TODO retry-bound this and print an appropriate message if it doesn't
         look like we were just too fast *)
      Logs.info (fun f -> f "No fuzzer_stats in the output directory:%s" e);
      Lwt_unix.sleep 5.0 >>= loop
    | Ok [] ->
      Logs.debug (fun f -> f "No fuzzer stats files found - waiting on the world to change");
      Lwt_unix.sleep 5.0 >>= loop
    | Ok _ ->
      (* the caller will know if all children have died. *)
      (* no compelling reason to reimplement afl-whatsup at the moment.
         if that changes, check commit history for the `mon` binary and its
         associated code, which parses `fuzzer_stats` itself and doubles as a nice
         thing for `bun` to test itself on. *)
      let () =
        match Bos.OS.Cmd.run Bos.Cmd.(v whatsup % Fpath.to_string output) with
        | Error (`Msg e) -> Logs.warn (fun f -> f "error running whatsup: %s" e)
        | Ok () -> ()
      in
      Lwt_unix.sleep 60.0 >>= loop
  in
  loop ()

let term_handler ~switch ~no_kill ~output _sigterm =
  Logs.app (fun f -> f
               "Terminating the remaining fuzzing processes in response to SIGTERM.@.\
                It's likely that this job could benefit from more fuzzing time @\n\
                - consider running it in an environment with more available cores or allowing @\n\
                the fuzzers more time to explore the state space, if possible.");
  if no_kill then (Files.Print.print_crashes output |> Rresult.R.get_ok);
  Lwt.async (fun () -> Lwt_switch.turn_off switch)

let pp_fuzzer f (id, proc) =
  Fmt.pf f "%d (pid=%d)" id proc#pid

let crash_detector output fuzzer status =
  match status with
  | Unix.WEXITED 0 -> begin
      Logs.app (fun f -> f "Fuzzer %a finished" pp_fuzzer fuzzer);
      Files.Print.print_crashes output |> Rresult.R.get_ok;
      match Files.Parse.get_crash_files output with
      | Ok [] -> Ok ()
      | _ -> Error `Crash_found
    end
  | WEXITED d ->
    Logs.warn (fun f -> f "Fuzzer %a has failed with code %d" pp_fuzzer fuzzer d);
    Files.Print.print_crashes output |> Rresult.R.get_ok;
    Error `Crash_found
  | WSIGNALED s ->
    Logs.warn (fun f -> f "Fuzzer %a was killed by signal %d" pp_fuzzer fuzzer s);
    Files.Print.print_crashes output |> Rresult.R.get_ok;
    Error `Crash_found
  | WSTOPPED _ -> assert false

let spawn ~main ~switch env id fuzzer memory input output program program_argv =
  let fuzzer = Fpath.to_string fuzzer in
  let argv = [fuzzer;
              "-m"; (string_of_int memory);
              "-i"; (Fpath.to_string input);
              "-o"; (Fpath.to_string output);
              (if main && id = 1 then "-M" else "-S"); string_of_int id;
              "--"; program; ] @ program_argv @ ["@@"] in
  Logs.info (fun f -> f "Executing %s" @@ String.concat " " argv);
  let stdout =
    match Logs.level () with
    | Some Logs.Debug  -> `Keep
    | _ -> `Dev_null
  in
  (* see afl-latest's docs/env_variables.txt for information on these --
     the variables we pass ask AFL to finish after it's "done" (the cycle
     counter would turn green in the UI) or it's found a crash, plus the obvious
     (if sad) request not to show us its excellent UI *)
  let env = Array.of_list ("AFL_EXIT_WHEN_DONE=1"::"AFL_NO_UI=1"::env) in
  let command = (fuzzer, Array.of_list argv) in
  let proc = Lwt_process.open_process_none ~env ~stdout command in
  Logs.info (fun f -> f "%s launched: PID %d" fuzzer proc#pid);
  Lwt_switch.add_hook (Some switch) (fun () ->
      if proc#state = Lwt_process.Running then (
        Logs.info (fun f -> f "Terminating fuzzer %a" pp_fuzzer (id, proc));
        proc#terminate
      );
      Lwt.return ());
  proc

let sigusr1_handler ~output _ =
  Logs.app (fun f -> f "USR1 signal received; showing progress...");
  match Files.Print.print_crashes output with
  | Ok () -> ()
  | Error (`Msg m) -> Logs.err (fun f -> f "print_crashes: %s" m)

let cgroups_killall cgroup_procs () =
  Logs.on_error_msg ~use:ignore
  @@
  let open Rresult.R.Infix in
  Bos.OS.File.read_lines cgroup_procs >>| fun procs ->
  let me = Unix.getpid () in
  procs |> List.map int_of_string
  |> List.filter (( <> ) me)
  |> List.iter @@ fun pid ->
  Logs.info (fun m -> m "Killing PID %d" pid);
  Unix.kill pid 9

let cgroups_init () =
  let open Rresult.R.Infix in
  let p = Fpath.v "/proc/self/cgroup" in
  Bos.OS.File.read_lines p >>= function
  | [] -> Rresult.R.error_msg "Empty /proc/self/cgroup file"
  | line :: _ -> (
      match Astring.String.cuts ~sep:":" line with
      | [ _; _; cgroup ] ->
          let cgroup = Astring.String.drop ~max:1 cgroup in
          let cgroup = Fpath.(v "/sys/fs/cgroup" // v cgroup / "afl") in
          let cgroup_procs = Fpath.(cgroup / "cgroup.procs") in
          Logs.debug (fun m -> m "Creating cgroup %a" Fpath.pp cgroup);
          Bos.OS.Dir.create ~path:false ~mode:0o755 cgroup >>| fun _ ->
          (* move ourselves into the newly created cgroup, rename doesn't work here,
             have to write file directly *)
          let f = open_out Fpath.(cgroup_procs |> to_string) in
          ( Fun.protect ~finally:(fun () -> close_out f) @@ fun () ->
            output_string f "0" );
          Logs.debug (fun m -> m "Moved to cgroup %a" Fpath.pp cgroup);
          at_exit (cgroups_killall cgroup_procs)
      | _ -> Rresult.R.error_msgf "Unable to parse /proc/self/cgroup %S" line )

let cgroups_init () =
  Rresult.R.trap_exn cgroups_init ()
  |> Rresult.R.error_exn_trap_to_msg |> Rresult.R.join
  |> Rresult.R.reword_error_msg ~replace:true (fun msg ->
         Rresult.R.msgf "Failed to initialize cgroups: %s" msg)

let fuzz () no_kill single_core max_cores no_cgroups no_main_instance fuzzer whatsup gotcpu input
    output memory program program_argv : (unit, Rresult.R.msg) result =
  let open Rresult.R.Infix in
  if not no_cgroups then
    Logs.on_error_msg ~use:ignore ~level:Logs.Info @@ cgroups_init ();
  let env =
    Unix.environment () |> Array.to_list |> fun env ->
    match no_kill with false -> "AFL_BENCH_UNTIL_CRASH=1" :: env | true -> env
  in
  let cores =
    let limit = if single_core then Some 1 else max_cores in
    let available = Files.Parse.get_cores gotcpu in
    match limit with
    | None -> available
    | Some limit ->
      (* always launch at least 1 *)
      max 1 (min available limit)
  in
  Files.fixup_input input >>= fun () ->
  Logs.info (fun f -> f "%d available cores detected!" cores);
  let main = not no_main_instance in
  let fill_cores ~switch fuzzer start_id =
    let rec launch_more max i =
      if i > max then [] else begin
        let fuzzer = (i, spawn ~main ~switch env i fuzzer memory input output program program_argv) in
        fuzzer :: launch_more cores (i+1)
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
    Lwt_main.run @@ begin
      let open Lwt.Infix in
      Lwt_switch.with_switch @@ fun switch ->
      let _ : Lwt_unix.signal_handler_id = Lwt_unix.(on_signal Sys.sigterm (term_handler ~switch ~no_kill ~output)) in
      let _ : Lwt_unix.signal_handler_id = Lwt_unix.(on_signal Sys.sigusr1 (sigusr1_handler ~output)) in
      let id = 1 in
      let fuzzers =
        match single_core with
        | true ->
          let proc = spawn ~main ~switch env id fuzzer memory input output program program_argv in
          let fuzzer = (id, proc) in
          Logs.app (fun f -> f "Fuzzer %a launched." pp_fuzzer fuzzer);
          [fuzzer]
        | false ->
          (* check once to see how many afl-fuzzes we can spawn, and then
             let afl-fuzz's own startup jitter plus a small delay from us 
             ensure they don't step on each others' toes when discovering CPU
             affinity. *)
          let fuzzers = fill_cores ~switch fuzzer id in
          Logs.app (fun f -> f "Fuzzers launched: %a." (Fmt.Dump.list pp_fuzzer) fuzzers);
          fuzzers
      in
      let results =
        fuzzers
        |> Lwt_list.map_p (fun fuzzer ->
            let _id, proc = fuzzer in
            proc#status >>= fun status ->
            if Lwt_switch.is_on switch then (
              match crash_detector output fuzzer status with
              | Error `Crash_found as e when not no_kill -> Lwt_switch.turn_off switch >|= fun () -> e
              | x -> Lwt.return x
            ) else (
              Logs.info (fun f -> f "Fuzzer %a shut down, as requested" pp_fuzzer fuzzer);
              Lwt.return (Ok ())
            )
          )
        >|= fun results ->
        try List.find ((<>) (Ok ())) results
        with Not_found -> Ok ()
      in
      let progress = mon whatsup output in
      Lwt.choose [progress; results] >|= function
      | Ok () -> Ok ()
      | Error `Crash_found -> Error (`Msg "All fuzzers finished, but some crashes were found!")
    end

let pp_header ppf x =
  let { Unix.tm_hour; tm_min; tm_sec; _ } = Unix.gmtime (Unix.gettimeofday ()) in
  Fmt.pf ppf "%02d:%02d.%02d:" tm_hour tm_min tm_sec;
  Logs_fmt.pp_header ppf x

let setup_log =
  let set style_renderer level =
    Fmt_tty.setup_std_outputs ?style_renderer ();
    Logs.set_level level;
    Logs.set_reporter (Logs_fmt.reporter ~pp_header ())
  in
  Cmdliner.Term.(const set $ Fmt_cli.style_renderer () $ Logs_cli.level ())

let fuzz_t =
  Cmdliner.Term.(const fuzz
                 $ setup_log $ no_kill $ single_core $ max_cores (* bun/mon args *)
                 $ no_cgroups $ no_main_instance
                 $ fuzzer $ whatsup $ gotcpu (* external cmds *)
                 $ input_dir $ output_dir $ memory
                 $ program $ program_argv) (* fuzzer flags *)

let bun_info =
  let doc = "invoke afl-fuzz on a program in a CI-friendly way" in
  Cmdliner.Term.(info ~version:"%%VERSION%%" ~exits:default_exits ~doc "bun")

let () = Cmdliner.Term.exit @@ match Cmdliner.Term.eval (fuzz_t, bun_info) with
  | `Ok (Error (`Msg s)) -> Logs.err (fun f -> f "%s" s);
    `Error `Exn
  | a -> a
