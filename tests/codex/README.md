`session.jsonl` and `later.jsonl` are sessions of Codex CLI in the shape it writes them, with invented content. The `.zst` files are those sessions compressed by the reference implementation of zstd, the `zstd` command 1.5.7, as Codex CLI compresses a session it has not changed for seven days:

```
zstd -19 session.jsonl -o session.jsonl.zst
zstd -19 later.jsonl -o later.jsonl.zst
```

Each is one frame of one compressed block, with a content checksum.

`long-line.jsonl.zst` holds three lines: the first of `later.jsonl`, a line of Codex CLI's shape whose working folder is 64 MiB long, and the first of `session.jsonl`. It was made the same way:

```
{
  head -n 1 later.jsonl
  printf '{"type":"turn_context","payload":{"cwd":"/Users/example/dev/'
  head -c 67108864 /dev/zero | tr '\0' a
  printf '"}}\n'
  head -n 1 session.jsonl
} | zstd -19 -o long-line.jsonl.zst
```

The tests in `src/agent_folders.rs` read them. Where a test needs a frame whose content or header it chooses, it writes a frame of one raw block by hand, to RFC 8878.
