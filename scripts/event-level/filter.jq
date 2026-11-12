# The event level's filter, run by Apple's jq as root (collect.sh). One line of eslogger in,
# one line out that keeps only what the reader uses, under eslogger's own names and nesting:
# the numbers that count losses, the time, the kind of event, and for a program start its
# image, arguments, working directory, ids, signer and parent image. Everything else, the
# environment and file descriptors above all, never reaches a disk: this is a list of what
# is kept, not of what is removed. A field eslogger no longer gives is written as null, and
# the reader takes a missing field it needs as a change of format. jq runs with
# --raw-input, so a line that is not a JSON object, or has no event, is dropped and the
# stream goes on; the gap it leaves in the sequence numbers is counted as a lost start.
fromjson?
| objects
| . as $m
| (try ($m.event | keys_unsorted[0]) catch null) as $kind
| select($kind != null)
| try (
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
