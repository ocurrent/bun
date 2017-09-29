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
    Bos.OS.Cmd.run Bos.Cmd.(empty % "kill" % string_of_int pid)
  with
  | Invalid_argument _ -> Error (`Msg "fuzzer_pid is not a valid int; refusing \
                                       to kill")
let lookup s l = List.find_opt (fun (a,_) -> Astring.String.equal a s) l

let lookup_pid l = match lookup "fuzzer_pid" l with
  | None -> None
  | Some (_, pid) -> try Some (int_of_string pid) with Invalid_argument _ -> None

let print_stats verbose lines =
  let default d = function
    | None -> d
    | Some (_, p) -> p
  in
  match List.length verbose with
  | 0 -> ()
  | _ ->
    let execs = lookup "execs_per_sec" lines |> default "an unknowable number of" in
    let paths = lookup "paths_found" lines |> default "an unknowable number of" in
    let stability = lookup "stability" lines |> default "an unknowable amount of" in
    Printf.printf "fuzzing hard at %s executions per second, having already \
                   discovered %s execution paths with %s stability\n%!"
      execs paths stability

let output_pasteable str id =
  Printf.sprintf "echo %s | base64 -d > crash_$(date -u +%%s).%d" str id

let get_base64 f =
  Bos.OS.Cmd.run_out @@
  Bos.Cmd.(v "base64" % (Fpath.to_string f)) |>
  Bos.OS.Cmd.to_string

let print_crashes output_dir =
  let crashes = Fpath.(output_dir / "crashes" / "id$(file)" ) in
  match Bos.OS.Path.matches crashes with
  | Error (`Msg e) ->
    Error (`Msg(Format.asprintf "Failure finding crashes in \
                                 directory %a: %s" Fpath.pp crashes e))
  | Ok crashes ->
    Printf.printf "%d crashes found! Take a look; copy/paste to save for \
                   reproduction:\n%!" (List.length crashes);
    try
      (* TODO: capture stdout and reprint it with more helpful surrounding
         context (something copy/pasteable directly to make a file) *)
      List.iteri (fun i c ->
          match get_base64 c with
          | Ok base64 ->
              Printf.printf "---- %s -----\n%s\n-----\n%!"
              (Fpath.to_string c) (output_pasteable base64 i)
          | Error _ -> ()
        ) crashes;
      Ok ()
    with
    | Invalid_argument e -> Error (`Msg (Format.asprintf "Failed to base64 a \
                                                          crash file: %s" e))

let rec mon verbose pid humane oneshot stats output_dir : (unit, Rresult.R.msg) result =
  let stats = match stats with
    | None -> Fpath.(output_dir / "fuzzer_stats")
    | Some stats -> stats
  in
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
    match lookup_pid lines, pid with
    | None, _ -> Error (`Msg (Format.asprintf
                             "no PID for the fuzzer found in stats file %a"
                             Fpath.pp stats))
    | Some file_pid, Some pid when (0 <> compare file_pid pid) ->
      (* fuzzer_stats look to be from another run, not the thing we launched
         or were asked to monitor. *)
      (* for now, just wait a bit and try again, but TODO this can lead us to
         block forever if we were supposed to be monitoring this process... *)
      if humane && oneshot then begin
        print_stats verbose lines;
        Ok ()
      end else begin
        Unix.sleep 1;
        mon verbose (Some pid) humane oneshot (Some stats) output_dir
      end
    | Some file_pid, _ -> (* either no pid specified or it matches the one in the file *)
      match (default 0 crashes, default 0 cycles) with
      | 0, 0 ->
        print_stats verbose lines;
        if oneshot then Ok () else begin
          Unix.sleep 60;
          mon verbose pid humane oneshot (Some stats) output_dir
        end
      | 0, cycles ->
        Printf.printf "%d cycles completed and no crashes found\n%!" cycles;
        if humane then Ok () else try_kill file_pid
      | _, _ ->
        let _ = print_crashes output_dir in
        Printf.printf "Killing %d...\n%!" file_pid;
        if humane then Ok () else try_kill file_pid
