_args: {inputs, ...}: {
  imports = [
    inputs.pkgs-by-name-for-flake-parts.flakeModule
  ];
  perSystem = {
    pkgs,
    lib,
    ...
  }: {
    pkgsDirectory = ../packages;
  };
}
