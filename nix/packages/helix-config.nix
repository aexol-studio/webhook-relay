{pkgs, ...}:
with pkgs; let
  cfg = (formats.toml {}).generate "config.toml" {
    theme = "pop-dark";
    editor.cursor-shape = {
      normal = "block";
      insert = "bar";
      select = "underline";
    };
  };
  languages =
    (formats.toml {}).generate
    "languages.toml" {
      language = [
        {
          name = "json";
          auto-format = true;
          formatter = {
            command = "treefmt";
            args = ["-q" "--stdin" ".json"];
          };
        }
        {
          name = "markdown";
          auto-format = true;
          formatter = {
            command = "treefmt";
            args = [
              "-q"
              "--stdin"
              ".md"
            ];
          };
        }
        {
          name = "nix";
          auto-format = true;
          formatter = {
            command = "treefmt";
            args = ["-q" "--stdin" ".nix"];
          };
          language-servers = ["nil"];
        }
        {
          name = "yaml";
          auto-format =
            true;
          file-types = ["yaml" "yml"];
          formatter = {
            command = "treefmt";
            args = ["-q" "--stdin" ".yml"];
          };
        }
      ];
    };
in
  writeShellScriptBin "helix-config" ''
    rm -rf .helix
    mkdir -p .helix
    ln -s ${cfg} .helix/config.toml
    ln -s ${languages} .helix/languages.toml
  ''
