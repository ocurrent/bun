module Parse = struct
  let get_stats lines =
    (* did someone say shotgun parsers? *)
    (* separate on : , keep only length 2 lists *)
    let lines = List.map (Astring.String.fields ~empty:false ~is_sep:((=) ':'))
        lines |> List.filter (fun a -> 2 = List.length a) in
    (* drop whitespace *)
    let lines = List.map (List.map Astring.String.trim) lines in
    (* convert 2-length lists to tuples *)
    List.map (function hd::tl::[] -> hd,tl | _ -> assert false) lines

  let lookup s l =
    try Some (List.find (fun (a,_) -> Astring.String.equal a s) l) with Not_found -> None

  let lookup_int s l = match lookup s l with
    | None -> None
    | Some (_, i) -> try Some (int_of_string i) with Invalid_argument _ -> None

  let lookup_crashes l = lookup_int "unique_crashes" l
  let lookup_pid l = lookup_int "fuzzer_pid" l

  let get_crash_files ?(id = "$(file)") output_dir =
    let crashes = Fpath.(output_dir / id / "crashes" / "id$(file)" ) in
    Bos.OS.Path.matches crashes

  let get_stats_lines ~id output =
    Bos.OS.File.read_lines Fpath.(output / id / "fuzzer_stats")

  let get_cores gotcpus =
    let process_preamble = "more processes on " in
    let more_processes = Bos.Cmd.(v "grep" % process_preamble) in
    let (>>=) = Rresult.R.bind in
      Bos.OS.Cmd.(run_io more_processes gotcpus |> to_lines) >>= fun l ->
      match List.map (Astring.String.cut ~sep:process_preamble) l
            |> List.find (function | Some _ -> true | None -> false) with
      | None -> Ok 0
      | Some (_, cores) ->
        Ok (Astring.String.fields cores |> List.hd |> int_of_string)

end

module Print = struct
  let base64 f =
    Bos.OS.Cmd.run_out @@
    Bos.Cmd.(v "base64" % "-w" % "0" % (Fpath.to_string f)) |>
    Bos.OS.Cmd.to_string

  let output_pasteable str id =
    Printf.sprintf "echo %s | base64 -d > crash_%d.$(date -u +%%s)" str id

  let print_crashes output_dir =
    match Parse.get_crash_files output_dir with
    | Error (`Msg e) ->
      Error (`Msg (Format.asprintf "Failure finding crashes in \
                                    directory %a: %s" Fpath.pp output_dir e))
    | Ok [] ->
      Printf.printf "No crashes found!\n%!"; Ok ()
    | Ok crashes ->
      Printf.printf "Crashes found! Take a look; copy/paste to save for \
                     reproduction:\n%!";
      try
        List.iteri (fun i c ->
            match base64 c with
            | Error _ -> ()
            | Ok base64 ->
              Printf.printf "%s\n%!" (output_pasteable base64 i)
          ) crashes;
        Ok ()
      with
      | Invalid_argument e -> Error (`Msg (Format.asprintf "Failed to base64 a \
                                                            crash file: %s" e))
end

let rec mon verbose whatsup (pids : (int * int) list ref) output : (unit, Rresult.R.msg) result =
  match Bos.OS.Path.matches @@ Fpath.(output / "$(dir)" / "fuzzer_stats") with
  | Error (`Msg e) ->
    (* this is probably just a race -- keep trying *)
    (* (but TODO retry-bound this and print an appropriate message if it doesn't
       look like we were just too fast *)
    if (List.length verbose > 0) then
      Printf.eprintf "No fuzzer_stats in the output directory:%s\n%!" e;
    Unix.sleep 5;
    mon verbose whatsup pids output
  | Ok [] ->
    if (List.length verbose > 1) then
      Printf.eprintf "No fuzzer stats files found - waiting on the world to \
                      change\n%!";
    Unix.sleep 1;
    mon verbose whatsup pids output
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
    Unix.sleep 60;
    mon verbose whatsup pids output
