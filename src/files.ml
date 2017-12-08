let find_fuzzer fuzzer =
  let open Rresult.R.Infix in
  Fpath.of_string fuzzer >>= fun fuzzer ->
  match Fpath.is_abs fuzzer with
  | true -> Ok fuzzer
  | false ->
    if Fpath.segs fuzzer |> List.length <> 1 then
      Bos.OS.Dir.current () >>| fun cwd -> Fpath.append cwd fuzzer
    else begin
      Bos.OS.Env.req_var "PATH" >>= fun path ->
      let path = Astring.String.fields ~empty:false ~is_sep:((=) ':') path |>
                 List.map Fpath.of_string |>
                 List.fold_left (fun l -> function | Ok a -> a::l | _ -> l) []|>
                 List.rev in
      try
        let dir = (List.find (fun dir ->
            Fpath.(append dir fuzzer)
            |> Bos.OS.File.exists
            |> Rresult.R.error_msg_to_invalid_arg))
            path in
        Ok (Fpath.append dir fuzzer)
      with
      | Invalid_argument s -> Rresult.R.error_msg s
      | Not_found -> Error (`Msg (Fmt.strf
                                    "could not find %a to invoke it - \
                                    try specifying the full path, or ensuring it \
                                    is in your PATH"
                                    Fpath.pp fuzzer))
    end

module Parse = struct
  let get_stats lines =
    (* did someone say shotgun parsers? *)
    List.map (Astring.String.fields ~empty:false ~is_sep:((=) ':')) lines |>
    List.map (List.map Astring.String.trim) |>
    List.fold_left (fun acc -> function | hd::tl::[]-> (hd, tl)::acc
                                        | _ -> acc) [] |> List.rev

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

  let get_cores verbosity gotcpus =
    let process_preamble = "more processes on " in
    let more_processes = Bos.Cmd.(v "grep" % process_preamble) in
    let (>>=) = Rresult.R.bind in
    Bos.OS.Cmd.(run_io more_processes gotcpus |> to_lines) >>= fun l ->
    match List.map (Astring.String.cut ~sep:process_preamble) l
          |> List.find (function | Some _ -> true | None -> false) with
    | None -> Ok 0
    | Some (_, cores) ->
      if (List.length verbosity > 1) then
        Printf.printf "cores line: %s\n%!" cores;
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
