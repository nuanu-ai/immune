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
# Who a process is, beside its pid: the pid's version from its audit token and its start time,
# for the process a program start creates (event.exec.target), for the process that acted
# (process) in a program start and in a file event, and the pid and pid version of the
# parent (event.exec.target.parent_audit_token) and of the process responsible for the one
# started (responsible_audit_token). The users and groups of an audit token (euid, egid, ruid,
# rgid) are kept for the process started and the process that acted, and the process group
# (group_id) of the one started. A program start also keeps the script it names
# (event.exec.script.path) and the code-signing flags of the program started; of the process
# that acted, in a program start and in a file event, the signer is kept: signing_id, team_id,
# is_platform_binary and codesigning_flags.
#
# Every value kept has one of four shapes, each through one helper below: a text, a whole
# number the reader holds exactly (0 to 2^53 - 1), true or false, or a list of texts. A value
# of any other shape is written as null, so nothing else is ever carried under these names. An
# audit token is an object, of which the named numbers are kept, or the eight numbers of
# audit_token_t, kept as they are; `token` is the one definition for every token kept.
#
# A file created or renamed (create, rename) keeps less, since there are many: schema_version,
# seq_num and time, the path of the program that did it (process.executable.path) and who it
# is, and the file as one path, `destination`, with a rename's `source`. eslogger gives a
# destination as an existing file, `existing_file.path`, or as a new path, `new_path.dir.path`
# and `new_path.filename`, which are joined here. A file event whose shape this does not know,
# or whose path eslogger marks as truncated, is written as its kind with nothing in it, the
# numbers kept, so the reader counts it as an unreadable file event and never as nothing.
#
# jq runs with --raw-input. A line it cannot read as JSON (a lone UTF-16 surrogate such as
# \ud800, a raw control character), a line that is not an object or has no event, and one it
# cannot shape for any other reason, is written as the marker {"unreadable":true}: the reader
# counts it as a line that could not be read, apart from what the kernel dropped, and the
# stream goes on. Nothing here decides what matters: it only keeps fields.
def text: if type == "string" then . else null end;
def whole: if type == "number" and . >= 0 and . <= 9007199254740991 and . == floor
    then . + 0 else null end;
def flag: if type == "boolean" then . else null end;
def texts: if type == "array" and all(.[]; type == "string") then . else null end;
# A value under a path, or null when a step on the way is not an object.
def at(f): try f catch null;
def path_of: if type == "object" and (.path | type) == "string" and .path_truncated != true
    then .path else error("not a path") end;
def destination:
    if (.existing_file | type) == "object" then .existing_file | path_of
    elif (.new_path | type) == "object" and (.new_path.filename | type) == "string"
        and (.new_path.filename | length) > 0
        then (.new_path.dir | path_of) as $dir
        | if ($dir | endswith("/")) then $dir else $dir + "/" end + .new_path.filename
    else error("no destination") end;
def token: if type == "object" then {pid: (.pid | whole), pidversion: (.pidversion | whole)}
    elif type == "array" and length == 8 and all(.[]; whole != null) then map(whole)
    else null end;
# A token with its users and groups.
def owned: if type == "object"
    then token + {euid: (.euid | whole), egid: (.egid | whole), ruid: (.ruid | whole),
        rgid: (.rgid | whole)}
    else token end;
# Who a process is, when it started, and who signed it.
def who: {audit_token: (at(.audit_token) | owned), start_time: (at(.start_time) | text),
    signing_id: (at(.signing_id) | text), team_id: (at(.team_id) | text),
    is_platform_binary: (at(.is_platform_binary) | flag),
    codesigning_flags: (at(.codesigning_flags) | whole)};
def marker: {unreadable: true};
# The kind is the event's one key. A message that is not an object, or whose event is not an
# object with a key, has no kind as text: taking it, or making a key of it below, fails, and the
# line is the marker.
try (
  fromjson
  | . as $m
  | ($m.event | keys_unsorted[0]) as $kind
  | if $kind == "create" or $kind == "rename" then
        {schema_version: ($m.schema_version | whole), seq_num: ($m.seq_num | whole),
          time: ($m.time | text)}
        + (try (
            {process: ({executable: {path: ($m.process.executable | path_of)}}
               + ($m.process | who)),
             event: {($kind): ($m.event[$kind] | {destination: (.destination | destination)}
               + if $kind == "rename" then {source: (.source | path_of)} else {} end)}}
          ) catch {event: {($kind): {}}})
      else
        {schema_version: ($m.schema_version | whole), version: ($m.version | whole),
          seq_num: ($m.seq_num | whole), global_seq_num: ($m.global_seq_num | whole),
          time: ($m.time | text)}
        + if $kind == "exec" then
            {process: ({executable: {path: (at($m.process.executable.path) | text)}}
               + (at($m.process) | who)),
             event: {exec: (at($m.event.exec) | {
               args: (at(.args) | texts),
               cwd: {path: (at(.cwd.path) | text)},
               script: (at(.script)
                 | if type == "object" then (try {path: path_of} catch null) else null end),
               target: (at(.target) | {
                 executable: {path: (at(.executable.path) | text)},
                 audit_token: (at(.audit_token) | owned),
                 start_time: (at(.start_time) | text),
                 parent_audit_token: (at(.parent_audit_token) | token),
                 responsible_audit_token: (at(.responsible_audit_token) | token),
                 group_id: (at(.group_id) | whole),
                 ppid: (at(.ppid) | whole),
                 signing_id: (at(.signing_id) | text),
                 team_id: (at(.team_id) | text),
                 is_platform_binary: (at(.is_platform_binary) | flag),
                 codesigning_flags: (at(.codesigning_flags) | whole)})})}}
          else {event: {($kind): {}}} end
    end
) catch marker
