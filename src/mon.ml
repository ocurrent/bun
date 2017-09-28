let output_dir =
  let fpath_conv = Cmdliner.Arg.conv Fpath.(of_string, pp) in
  let doc = "Output directory for the fuzzer.  This should contain a fuzzer_stats \
             and is expected to be the -o argument to afl-fuzz." in
  Cmdliner.Arg.(required & pos 0 (some fpath_conv) None & info [] ~docv:"OUTPUT" ~doc)

let verbosity =
  let doc = "Report on intermediate progress." in
  Cmdliner.Arg.(value & flag_all & info ["v"] ~docv:"VERBOSE" ~doc)

let get_stats lines =
  (* did someone say shotgun parsers? *)
  (* separate on : , keep only length 2 lists *)
  let lines = List.map (Astring.String.fields ~empty:false ~is_sep:((=) ':'))
      lines |> List.filter (fun a -> 2 = List.length a) in
  (* drop whitespace *)
  let lines = List.map (List.map Astring.String.trim) lines in
  (* convert 2-length lists to tuples *)
  List.map (function hd::tl::[] -> hd,tl | _ -> assert false) lines

let try_kill pid =
  try
    (* cheap and dirty sanitization -- it would be a weird attack vector,
       admittedly *)
    Bos.OS.Cmd.run Bos.Cmd.(empty % "kill" % string_of_int (int_of_string pid))
  with
  | Invalid_argument _ -> Error (`Msg "fuzzer_pid is not a valid int; refusing \
                                       to kill")
let lookup s l = List.find_opt (fun (a,_) -> Astring.String.equal a s) l

let print_stats verbose lines =
  let default d = function
    | None -> ""
    | Some (_, p) -> p
  in
  match List.length verbose with
  | 0 -> ()
  | _ ->
    let execs = lookup "execs_per_sec" lines |> default "an unknowable number of" in
    Printf.printf "fuzzing hard at %s executions per second\n%!" execs

let print_crashes output_dir =
  (* TODO: find crashes, base64 encode them, and print them out on the console
  *)
  ()

let rec mon verbose output_dir : (unit, Rresult.R.msg) result =
  let stats = Fpath.(output_dir / "fuzzer_stats") in
  match Bos.OS.File.read_lines stats with
  | Error (`Msg e) ->
    Error (`Msg (Format.asprintf "Error reading stats file %a: %s" Fpath.pp stats e))
  | Ok lines ->
    let default d = function
      | None -> d
      | Some (_, p) -> try int_of_string p with Invalid_argument _ -> d
    in
    let lines = get_stats lines in
    let crashes = lookup "unique_crashes" lines in
    let cycles = lookup "cycles_done" lines in
    match lookup "fuzzer_pid" lines with
    | None -> Error (`Msg (Format.asprintf
                             "no PID for the fuzzer found in stats file %a"
                             Fpath.pp stats))
    | Some (_, pid) ->
      match (default 0 crashes, default 0 cycles) with
      | 0, 0 ->
        print_stats verbose lines;
        Unix.sleep 60;
        mon verbose stats
      | 0, cycles ->
        Printf.printf "%d cycles completed and no crashes found\n%!" cycles;
        try_kill pid
      | crashes, _ ->
        print_crashes output_dir;
        Printf.printf "%d crashes found! Killing %s...\n%!" crashes pid;
        try_kill pid

let mon_t = Cmdliner.Term.(const mon $ verbosity $ output_dir)

let mon_info =
  let doc = "monitor a running afl-fuzz instance, and kill it once it's tried \
             hard enough" in
  Cmdliner.Term.(info ~version:"%%VERSION%%" ~doc "mon")

let () = AflPersistent.run (fun () -> Cmdliner.Term.(exit @@ eval (mon_t,
                                                                   mon_info)))
