open Crowbar

let () =
  add_test ~name:"negation" [float] (fun f -> check (not (f = -. f)))
