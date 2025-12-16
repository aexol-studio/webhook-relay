_args: {inputs, ...}: {
  imports = [inputs.devenv.flakeModule];
  perSystem = {
    config,
    lib,
    self',
    pkgs,
    system,
    ...
  }: let
    helixShell = {
      # https://devenv.sh/reference/options/
      packages = with pkgs; [
        # Protobuf compiler for gRPC code generation
        protobuf
      ];
      git-hooks.hooks.treefmt = {
        enable = true;
        packageOverrides.treefmt = config.treefmt.build.wrapper;
      };

      enterShell = ''
        ${config.packages.helix-config}/bin/helix-config
      '';
      languages = {
        rust = {
          enable = true;
          toolchainFile = ../../rust-toolchain.toml;
        };
      };
    };
  in {
    devenv = {
      shells = {
        inherit helixShell;
        default = helixShell;
      };
    };
  };
}
