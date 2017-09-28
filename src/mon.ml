let statsfile =
  let fpath_conv = Cmdliner.Arg.conv Fpath.(of_string, pp) in
  let doc = "Where to look for fuzzing statistics.  This is likely some \
             output/fuzzer_stats which afl-fuzz is writing into." in
  Cmdliner.Arg.(required & pos 0 (some fpath_conv) None & info [] ~docv:"STATS" ~doc)

let pid =
  let doc = "Which PID to kill." in
  Cmdliner.Arg.(required & pos 1 (some int) None & info [] ~docv:"PID" ~doc)

let get_stats lines =
  (* did someone say shotgun parsers? *)
  (* separate on : , keep only length 2 lists *)
  let lines = List.map (Astring.String.fields ~empty:false ~is_sep:((=) ':'))
      lines |> List.filter (fun a -> 2 = List.length a) in
  (* drop whitespace *)
  let lines = List.map (List.map Astring.String.trim) lines in
  (* convert 2-length lists to tuples *)
  List.map (function hd::tl::[] -> hd,tl | _ -> assert false) lines

let mon stats pid : (unit, Rresult.R.msg) result =
  match Bos.OS.File.read_lines stats with
  | Error (`Msg e) ->
    Error (`Msg (Format.asprintf "Error reading stats file %a: %s" Fpath.pp stats e))
  | Ok lines ->
    let lookup s l = List.find_opt (fun (a,_) -> Astring.String.equal a s) l in
    let default d = function
      | None -> d
      | Some (_, p) -> try int_of_string p with Invalid_argument _ -> d
    in
    let lines = get_stats lines in
    let crashes = lookup "unique_crashes" lines in
    let cycles = lookup "cycles_done" lines in
    match (default 0 crashes, default 0 cycles) with
    | 0, 0 -> Ok ()
    | 0, cycles ->
      Printf.printf "%d cycles completed and no crashes found\n%!" cycles;
      Ok ()
    | crashes, _ ->
      Printf.printf "%d crashes found! Killing %d...\n%!" crashes pid;
      Bos.OS.Cmd.run Bos.Cmd.(empty % "kill" % string_of_int pid)

let mon_t = Cmdliner.Term.(const mon $ statsfile $ pid)

let mon_info =
  let doc = "monitor a running afl-fuzz instance, and kill it once it's tried \
             hard enough" in
  Cmdliner.Term.(info ~version:"%%VERSION%%" ~doc "mon")

let () = AflPersistent.run (fun () -> Cmdliner.Term.(exit @@ eval (mon_t,
                                                                   mon_info)))
