# Erlang/Elixir packages
{ pkgs, versions }:
let
  lib = pkgs.lib;
  major = builtins.elemAt (builtins.splitVersion versions.erlang) 0;
  erlang = pkgs."beam${major}Packages".erlang.overrideAttrs (old: {
    buildInputs = (old.buildInputs or [ ])
      ++ lib.optional pkgs.stdenv.hostPlatform.isDarwin
        pkgs.apple-sdk_27;
  });

  packages = pkgs.beam29Packages.overrideScope (final: _prev: {
    inherit erlang;

    elixir = let
      tools = lib.take 2 (builtins.splitVersion versions.elixir);
      version = lib.strings.join "_" tools;
    in final."elixir_${version}";
  });
in
{
  inherit packages;

  # Warn about version mismatch. The reason why it do not use exact versions to
  # build Erlang and Elixir is that ASDF do not have enough information to be
  # reproducible. It stores only version number, not hash of the source that
  # version was built from. Nix requires that hash to be fully reproducible.
  #
  # In theory we could force build from source and just flunk when the hash
  # mismatch, but that would be more work than needed and potentially could
  # cause issues with fetching package from cache. That makes it way simpler to
  # handle.
  warnings = let
    checkVersion = pkg: let
      # This magic is needed to strip metadata values used by ASDF version
      # picker
      asdf = builtins.head (lib.strings.splitString "-" versions.${pkg});
      nix = packages.${pkg}.version;
    in lib.optionals (asdf != nix) [
        "Potential ${pkg} version mismatch between .tool-versions (${asdf}) and Devenv (${nix})"
      ];
  in
    (checkVersion "erlang") ++ (checkVersion "elixir");
}
