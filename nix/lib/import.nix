{
  importApply,
  withSystem,
  localFlake,
  inputs,
}: let
  inherit (inputs) nixpkgs;
  importFromPath = path:
    with builtins;
      listToAttrs (
        map
        (fn: {
          name = nixpkgs.lib.strings.removeSuffix ".nix" fn;
          value =
            importApply (path + "/${fn}")
            {
              inherit withSystem importApply localFlake inputs;
            };
        })
        (filter
          (fn: let
            entry = readDir path;
            type = entry.${fn};
          in
            type == "directory" || nixpkgs.lib.strings.hasSuffix ".nix" fn)
          (attrNames (readDir path)))
      );
  importFromPathList = path: builtins.attrValues (importFromPath path);
in {
  inherit importFromPath importFromPathList;
}
