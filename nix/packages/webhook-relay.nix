{
  inputs,
  system,
  lib,
  ...
}: let
  inherit (inputs) nixpkgs rust-overlay crane;

  # Base pkgs for the host system
  pkgs = import nixpkgs {
    inherit system;
    overlays = [(import rust-overlay)];
  };

  # Cross-compilation pkgs for Windows (for getting the cross toolchain)
  pkgsCrossWindows = pkgs.pkgsCross.mingwW64;

  # Cross-compilation pkgs for static Linux (musl)
  pkgsCrossMusl = pkgs.pkgsCross.musl64;

  # Source files - include everything needed for cargo build
  src = lib.fileset.toSource {
    root = ../..;
    fileset = lib.fileset.unions [
      ../../Cargo.toml
      ../../Cargo.lock
      ../../rust-toolchain.toml
      ../../.cargo
      ../../proto
      ../../api
      ../../server
      ../../client
      ../../common
      ../../mcp-client
      ../../tests
    ];
  };

  # macOS SDK version for cross-compilation
  macOSSDKVersion = "14";

  # Fetch macOS SDK from storage box (requires ~/.netrc with credentials)
  # netrc format: machine u519201-sub1.your-storagebox.de login u519201-sub1 password <password>
  macOSSDK = pkgs.stdenvNoCC.mkDerivation {
    pname = "macos-sdk";
    version = macOSSDKVersion;

    src = builtins.fetchurl {
      url = "https://u519201-sub1.your-storagebox.de/MacOSX${macOSSDKVersion}.sdk.tar.xz";
      sha256 = "sha256-3Wc3PjIm5+nJt04VCDwFOvRRnWM/pppq/HQ/dtJIWOM=";
    };

    nativeBuildInputs = [pkgs.xz];

    unpackPhase = ''
      mkdir -p $out
      tar -xJf $src -C $out --strip-components=1
    '';

    dontBuild = true;
    dontInstall = true;
    dontFixup = true;
  };

  # Darwin target triple
  darwinTargetTriple = "x86_64-apple-darwin";

  # Rust toolchain from rust-toolchain.toml with all cross-compilation targets
  rustToolchainWithTargets =
    (pkgs.rust-bin.fromRustupToolchainFile ../../rust-toolchain.toml).override
    {
      targets = [
        "x86_64-pc-windows-gnu"
        "x86_64-unknown-linux-musl"
        "x86_64-apple-darwin"
      ];
    };

  # Single crane lib with our toolchain
  craneLib = (crane.mkLib pkgs).overrideToolchain (_: rustToolchainWithTargets);

  # ============================================================================
  # Common build arguments
  # ============================================================================
  commonArgs = {
    inherit src;
    strictDeps = true;
    pname = "webhook-relay";
    version = "0.1.0";
    doCheck = false;
  };

  # ============================================================================
  # Linux Package (native build)
  # ============================================================================
  commonArgsLinux =
    commonArgs
    // {
      nativeBuildInputs = [
        pkgs.protobuf
        pkgsCrossMusl.stdenv.cc
      ];
      CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
      cargoExtraArgs = "--locked -p server -p client -p mcp-client";

      # Configure the linker for musl static compilation
      CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = "${pkgsCrossMusl.stdenv.cc}/bin/x86_64-unknown-linux-musl-gcc";
      CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS = "-C target-feature=+crt-static";

      # Tell cc crate to use the musl cross compiler
      CC_x86_64_unknown_linux_musl = "${pkgsCrossMusl.stdenv.cc}/bin/x86_64-unknown-linux-musl-gcc";
      CXX_x86_64_unknown_linux_musl = "${pkgsCrossMusl.stdenv.cc}/bin/x86_64-unknown-linux-musl-g++";
      AR_x86_64_unknown_linux_musl = "${pkgsCrossMusl.stdenv.cc}/bin/x86_64-unknown-linux-musl-ar";

      # ring crate needs these for assembly
      HOST_CC = "${pkgs.stdenv.cc}/bin/cc";
    };

  cargoArtifactsLinux = craneLib.buildDepsOnly commonArgsLinux;

  linuxPackage = craneLib.buildPackage (
    commonArgsLinux
    // {
      cargoArtifacts = cargoArtifactsLinux;
    }
  );

  # ============================================================================
  # Windows Package (cross-compilation)
  # ============================================================================
  commonArgsWindows =
    commonArgs
    // {
      nativeBuildInputs = [
        pkgs.protobuf
        pkgsCrossWindows.stdenv.cc
      ];

      buildInputs = [
        pkgsCrossWindows.windows.pthreads
      ];

      CARGO_BUILD_TARGET = "x86_64-pc-windows-gnu";
      cargoExtraArgs = "--locked -p server -p client -p mcp-client";

      # Configure the linker for Windows cross-compilation
      CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER = "${pkgsCrossWindows.stdenv.cc}/bin/x86_64-w64-mingw32-gcc";
      CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUSTFLAGS = "-L ${pkgsCrossWindows.windows.pthreads}/lib";

      # Tell cc crate to use the cross compiler
      CC_x86_64_pc_windows_gnu = "${pkgsCrossWindows.stdenv.cc}/bin/x86_64-w64-mingw32-gcc";
      CXX_x86_64_pc_windows_gnu = "${pkgsCrossWindows.stdenv.cc}/bin/x86_64-w64-mingw32-g++";
      AR_x86_64_pc_windows_gnu = "${pkgsCrossWindows.stdenv.cc}/bin/x86_64-w64-mingw32-ar";

      # ring crate needs these for assembly
      HOST_CC = "${pkgs.stdenv.cc}/bin/cc";
    };

  cargoArtifactsWindows = craneLib.buildDepsOnly commonArgsWindows;

  windowsPackage = craneLib.buildPackage (
    commonArgsWindows
    // {
      cargoArtifacts = cargoArtifactsWindows;
    }
  );

  # ============================================================================
  # Darwin Package (cross-compilation with cargo-zigbuild)
  # ============================================================================

  # Zigbuild cargo command - used for both deps and final build
  # Must capture JSON output for crane's install hook
  zigbuildCargoCommand = ''
    export HOME=$(mktemp -d)
    cargoBuildLog=$(mktemp cargoBuildLogXXXX.json)
    cargo zigbuild --profile release --message-format json-render-diagnostics --locked -p server -p client -p mcp-client --target ${darwinTargetTriple} >"$cargoBuildLog"
  '';

  commonArgsDarwin =
    commonArgs
    // {
      nativeBuildInputs = [
        pkgs.protobuf
        pkgs.cargo-zigbuild
        pkgs.zig
      ];

      CARGO_BUILD_TARGET = darwinTargetTriple;
      cargoExtraArgs = "--locked -p server -p client -p mcp-client --target ${darwinTargetTriple}";

      # Environment for cargo-zigbuild
      SDKROOT = macOSSDK;
      MACOSX_DEPLOYMENT_TARGET = macOSSDKVersion;
      ZIG_LIB_DIR = "${pkgs.zig}/lib/zig";
      CARGO_TARGET_X86_64_APPLE_DARWIN_RUSTFLAGS = "-C link-arg=-F${macOSSDK}/System/Library/Frameworks -C link-arg=-L${macOSSDK}/usr/lib";

      # Disable incremental compilation to help with fingerprint consistency
      CARGO_INCREMENTAL = "0";

      # Override to use cargo zigbuild
      buildPhaseCargoCommand = zigbuildCargoCommand;
    };

  # Build deps using zigbuild
  cargoArtifactsDarwin = craneLib.buildDepsOnly commonArgsDarwin;

  darwinPackage = craneLib.buildPackage (
    commonArgsDarwin
    // {
      cargoArtifacts = cargoArtifactsDarwin;
    }
  );

  # ============================================================================
  # Combined Package (Linux, Windows, and Darwin)
  # ============================================================================
  combinedPackage = pkgs.stdenvNoCC.mkDerivation {
    pname = "webhook-relay";
    version = "0.1.0";

    dontUnpack = true;

    installPhase = ''
      runHook preInstall

      mkdir -p $out/bin/x86_64-unknown-linux-musl
      mkdir -p $out/bin/x86_64-pc-windows-gnu
      mkdir -p $out/bin/x86_64-apple-darwin

      # Copy Linux binaries (statically linked with musl)
      cp ${linuxPackage}/bin/server ${linuxPackage}/bin/client ${linuxPackage}/bin/mcp-client $out/bin/x86_64-unknown-linux-musl

      # Copy Windows binaries
      cp ${windowsPackage}/bin/server.exe ${windowsPackage}/bin/client.exe ${windowsPackage}/bin/mcp-client.exe $out/bin/x86_64-pc-windows-gnu

      # Copy Darwin binaries
      cp ${darwinPackage}/bin/server ${darwinPackage}/bin/client ${darwinPackage}/bin/mcp-client $out/bin/x86_64-apple-darwin

      runHook postInstall
    '';
  };
in
  combinedPackage
