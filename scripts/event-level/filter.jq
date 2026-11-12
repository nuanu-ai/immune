# The event level's filter, run by Apple's jq as root (collect.sh). One line of eslogger in,
# one line out that keeps only what the reader uses: this is a list of what is kept, not of
# what is removed.
#
# A program start (exec) keeps eslogger's own names and nesting: the numbers that count
# losses, the time, its image, arguments, working directory, ids, signer and parent image.
# The environment and file descriptors above all never reach a disk. A field eslogger no
# longer gives is written as null, and the reader takes a missing field it needs as a change
# of format.
#
# A file created or renamed (create, rename) keeps less, since there are many: schema_version,
# seq_num and time, the path of the program that did it (process.executable.path), and the
# file as one path, `destination`, with a rename's `source`. eslogger gives a destination as
# an existing file, `existing_file.path`, or as a new path, `new_path.dir.path` and
# `new_path.filename`, which are joined here. A file event whose shape this does not know, or
# whose path eslogger marks as truncated, is written as its kind with nothing in it, the
# numbers kept, so the reader counts it as an unreadable file event and never as nothing.
#
# jq runs with --raw-input, so a line that is not a JSON object, or has no event, is dropped
# and the stream goes on; the gap it leaves in the sequence numbers is counted as a loss.
# Nothing here decides what matters: it only keeps fields.
def path_of: if type == "object" and (.path | type) == "string" and .path_truncated != true
    then .path else error("not a path") end;
def destination:
    if (.existing_file | type) == "object" then .existing_file | path_of
    elif (.new_path | type) == "object" and (.new_path.filename | type) == "string"
        and (.new_path.filename | length) > 0
        then (.new_path.dir | path_of) as $dir
        | if ($dir | endswith("/")) then $dir else $dir + "/" end + .new_path.filename
    else error("no destination") end;
fromjson?
| objects
| . as $m
| (try ($m.event | keys_unsorted[0]) catch null) as $kind
| select($kind != null)
| if $kind == "create" or $kind == "rename" then
    {schema_version, seq_num, time}
    + (try (
        {process: {executable: {path: ($m.process.executable | path_of)}},
         event: {($kind): ($m.event[$kind] | {destination: (.destination | destination)}
           + if $kind == "rename" then {source: (.source | path_of)} else {} end)}}
      ) catch {event: {($kind): {}}})
  else
    try (
      {schema_version, version, seq_num, global_seq_num, time}
      + if $kind == "exec" then
          {process: {executable: {path: $m.process.executable.path}},
           event: {exec: {
             args: $m.event.exec.args,
             cwd: {path: $m.event.exec.cwd.path},
             target: ($m.event.exec.target | {
               executable: {path: .executable.path},
               audit_token: (.audit_token | if type == "object" then {pid, euid} else . end),
               ppid, signing_id, team_id, is_platform_binary})}}}
        else {event: {($kind): {}}} end
    ) catch empty
  end
