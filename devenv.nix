{ pkgs, lib, ... }:
let
  versions = import ./nix/tool-versions.nix ./.tool-versions;
  beam = import ./nix/beam.nix { inherit pkgs versions; };
in
{
  name = "arinsal";

  languages.rust = {
    enable = true;
    toolchainFile = ./rust-toolchain.toml;
  };

  packages = with pkgs; [
    cargo-audit
    cargo-bloat
    cargo-outdated
    cargo-nextest
    ncurses
    beam.packages.erlang
    beam.packages.elixir
  ];

  warnings = beam.warnings;
}
