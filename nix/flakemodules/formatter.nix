_args: {inputs, ...}: {
  imports = [inputs.treefmt-nix.flakeModule];
  perSystem = {
    treefmt = {
      projectRootFile = "flake.nix";
      flakeCheck = true;
      programs = {
        alejandra.enable = true;
        mdformat.enable = true;
        shellcheck.enable = true;
        shfmt.enable = true;
        toml-sort.enable = true;
        yamlfmt.enable = true;
        deno.enable = true;
      };
      settings.global.excludes = [".envrc" "opencode/*" "opencode/**/*"];
    };
  };
}
