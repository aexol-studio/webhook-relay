{
  pkgs,
  inputs,
  system,
  lib,
  ...
} @ args: let
  webhookRelay = pkgs.callPackage ./webhook-relay.nix (args // {inherit inputs system lib;});
in
  pkgs.dockerTools.buildImage {
    name = "webhook-relay-server";
    tag = "latest";
    copyToRoot = pkgs.buildEnv {
      name = "image-root";
      pathsToLink = ["/bin" "/etc"];
      paths = [
        pkgs.cacert
        (pkgs.runCommand "server-bin" {} ''
          mkdir -p $out/bin
          cp ${webhookRelay}/bin/x86_64-unknown-linux-musl/server $out/bin/server
        '')
      ];
    };
    config = {
      Cmd = ["/bin/server"];
      Env = [
        "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"
      ];
    };
  }
