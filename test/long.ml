open Crowbar

let () =
  add_test ~name:"good ol' rev" [list bytes] (fun l -> check_eq
                                                  ~cmp:(fun a b -> match List.compare_lengths a b with
                                                     | 0 -> List.fold_left2 (fun a x y -> match a with
                                                         | 0 -> String.compare x y
                                                         | n -> n) 0 a b
                                                     | n -> n) l (List.rev @@ List.rev l))
