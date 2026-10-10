/**
  Parse the content of an asdf `.tool-versions` file into an attrset.

  Type: string -> attrs

  Every non-empty, non-comment line holds a tool name and one or more versions,
  separated by whitespace. The result maps each tool name to its versions:
  a single version becomes a string, several versions become a list of strings.
  The last line for a tool name wins.

  Example:
    (import ./nix/tool-versions.nix) ''
      erlang 29.1.1
      elixir 1.20.4-otp-29
    ''
    => { elixir = "1.20.4-otp-29"; erlang = "29.1.1"; }
*/
path:
let
  content = builtins.readFile path;
  # Drop a trailing carriage return, so CRLF input parses the same as LF input.
  stripCr = line:
    let
      match = builtins.match "(.*)\r" line;
    in
    if match == null then line else builtins.head match;

  # Split a line on runs of whitespace, and drop the empty matches that leading
  # or trailing whitespace produces.
  fieldsOf = line:
    builtins.filter (field: field != "")
      (builtins.filter builtins.isString (builtins.split "[[:space:]]+" line));

  parseLine = raw:
    let
      line = stripCr raw;
      fields = fieldsOf line;
    in
    if builtins.match "[[:space:]]*" line != null then
      null # Empty or whitespace-only line.
    else if builtins.match "[[:space:]]*#.*" line != null then
      null # Comment line.
    else if builtins.length fields < 2 then
      builtins.throw "tool-versions: malformed line, expected '<tool> <version>': \"${line}\""
    else
      let
        versions = builtins.tail fields;
      in
      {
        name = builtins.head fields;
        value = if builtins.length versions == 1 then builtins.head versions else versions;
      };

  lines = builtins.filter builtins.isString (builtins.split "\n" content);
  entries = builtins.filter (entry: entry != null) (map parseLine lines);
in
builtins.foldl' (result: entry: result // { ${entry.name} = entry.value; }) { } entries
