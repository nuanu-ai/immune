# Threats

A threat is knowledge from outside: a vulnerability, or an indicator from an incident report. This page is the contract for how Immune takes threats in, matches them against what it found on the Mac, and answers. It covers what is built and names what is planned.

Built: CISA's catalogue of exploited vulnerabilities, fetched whole at every check; OSV's vulnerability data for npm and crates.io, matched against the projects' lockfiles with four answers; a list of indicators matched against part of what Immune reads. Planned: matching installed software, Homebrew, servers' packages and other ecosystems, and the four answers for indicators. Until then the status says that no vulnerability is matched against those, so whether one affects them is unknown, and lists it among the limits of this version.

## What is asked of the network

These are the only requests Immune makes. What is asked never depends on what is on the Mac: the requests are fixed, or computed from public data only, so every user sends the same ones and nothing about their Mac leaks. Matching happens on the Mac.

| Source | Address | When | Size cap | Time limit |
|---|---|---|---|---|
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | every check | 8 MiB | 300 s |
| OSV, crates.io | `https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip` | every check | 64 MiB | 300 s |
| OSV, npm | `https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip` | when its last good reading is over 24 hours old | 512 MiB | 900 s |

Each goes through the system's curl, with the ETag the source last sent when there is one:

```
/usr/bin/curl --disable --silent --show-error --fail --proto =https --compressed
  --max-filesize <cap> --connect-timeout 30 --max-time <limit> [--output <file>]
  --write-out '%{stderr}\n%{http_code} %header{etag}\n' [--header 'If-None-Match: <etag>']
  <address>
```

`--disable` keeps `~/.curlrc` out. A redirect is not followed. "Not modified" is believed only in answer to Immune's own ETag. The body is held to the cap after decompression too. npm's archive is about 220 MB, 93% of it reports of malicious packages.

The feeds are fetched before the store is locked for the check, under a lock of their own, so a long download holds up no watcher's reading and no status. A second check stops at that lock and writes nothing. The time limits keep a check inside the app's 30 minutes. For tests and offline use, `--threats-input <file>`, `--osv-crates-input <file>` and `--osv-npm-input <file>` read saved copies, and `--curl <path>` runs another curl.

## Feed content is untrusted

The catalogue is parsed with `serde_json` under its 8 MiB cap. Anything not in the catalogue's shape fails the whole reading, since a reading that dropped an entry would mark it gone. A CVE id is taken only as `CVE-<digits>-<digits>`. An ETag goes back to the server only if it is plain visible ASCII of at most 256 characters.

An OSV archive is unpacked by `/usr/bin/bsdtar`, which macOS ships, with an empty environment and nothing on stdin, to stdout only, so nothing in it becomes a path or a command. Its listing is read under 64 MiB, its records under 1 GiB in all and 4 MiB each. Every entry must be `<id>.json` at the top level, and the records must match the listing one for one. A record out of its fixed shape fails the whole reading; unknown fields are ignored.

A reading that fails changes nothing: the data read before stays in force, with its age, and the reason is named. A failed reading is never "nothing new". The status tells it as one item: since when the data is old, and why in plain words, from curl's exit code (curl(1), EXIT CODES), the HTTP status or a body that was not the data. The person is told it is theirs to fix only when that is certain: a full disk, a certificate this Mac does not trust, or a proxy that asks for a password or fails its own handshake. A refusal, a timeout, a name that does not resolve or a body that is not the data is told as what it is, with nothing put on the person. The downloads use a proxy only when the environment names one and do not read the macOS proxy settings. No path or command ever comes from a feed, and its text is escaped wherever it is shown and returned only in `_text` fields.

## The catalogue

CISA's Known Exploited Vulnerabilities catalogue is one JSON file of about 1.8 MB under CC0, needing no account. An entry carries `cveID`, `vendorProject`, `product`, `vulnerabilityName`, `dateAdded` and more, and no versions.

- The first reading is a baseline: one journal entry, `threats_first_read`, with the count.
- After it, an id in this reading that is not in the list is `threat_added`, including one that left and came back. An entry that left the catalogue is `threat_gone` and is kept with the time it left.
- The report line says how many exploited vulnerabilities the catalogue holds and how many came and went since the last reading. The pages list them newest first.
- A catalogue entry is matched against the Mac only through lockfile dependencies: an OSV record linked to it that affects a lockfile entry is a finding. Nothing else is matched against it yet.

The catalogue's raw copy is kept and copied only when it changed. OSV's archives are too large for that (npm's would take about 80 GB a year): only the latest archive read whole is kept, as `feeds/<feed>.zip` next to the store, with one line per record it read (id, `modified`, SHA-256 of its text). An archive that failed to read is kept as `feeds/<feed>.failed.zip` until a reading succeeds. The SHA-256 lets anyone check a raw copy with `shasum -a 256`; nothing is trusted because of it.

## Tables

| Table | One row is |
|---|---|
| `threat` | one catalogue entry: the source, the CVE id, vendor, product, name and date added as given, when it was first seen and when it left |
| `feed_reading` | one attempt to read a source: when, the outcome (`read`, `unchanged`, or `failed` with a reason), the ETag, the SHA-256 and place of the raw copy, how many entries it held |
| `advisory` | one OSV record: the feed, the id, `modified` and `withdrawn` as given, the kind (malicious, informational or vulnerability), the summary, GitHub's label, CVSS vectors, aliases and CWE ids, when it was first seen and when it left |
| `advisory_affects` | one package a record affects in its feed's ecosystem: the name as given and as compared, ranges and versions as given |
| `vulnerability_answer` | one answer per record, checkout and package, with its reason, what it rests on and since when it holds |
| `vulnerability_answer_past` | an answer that changed or went, with when it stopped holding |
| `vulnerability_place` | per checkout and ecosystem: whether its lockfiles were read in full in the latest check, and whether the data is current |
| `vulnerability_linked` | a record linked to a catalogue CVE through its aliases, or through the aliases of a record it names |

## Matching

Matching is by mechanism, never by product. A matcher works for a kind of identifier, such as an ecosystem's lockfile or a distribution's packages. A hand-made mapping from a product named in words to a place is data, stays small, and never supports "does not affect me, known for certain".

### Lockfiles, built

- What is matched. Every package of a `package-lock.json` (versions 2 and 3), a `pnpm-lock.yaml` (versions 5.0 to 5.4, 6.0 and 9.0, every document in the file) and a `Cargo.lock` that the latest check read, by its real name, against the data of its ecosystem.
- Only an entry from the ecosystem's public registry is compared. One from git, a path or another registry is "don't know". crates.io names are compared as Cargo compares them, npm names exactly. pnpm does not record which registry a package came from: an entry with an integrity hash alone is taken as npm's public registry, and a host in a key of versions 5 and 6 means another registry.
- A package whose name or version cannot be established, and every bundled dependency (pnpm writes no version for one), makes the project's reading partial. A lockfile of another version is a kind with no reader, named as such.
- How. The OSV schema's `IsVulnerable` algorithm on SemVer precedence, with versions ordered by the `semver` crate. A version is parsed strictly and never coerced. Withdrawn records, records gone from the feed and RustSec's informational advisories are not answered.
- What is kept. Every check computes an answer per record, checkout and package, with what it rests on: the lockfile lines with their versions, the record's `modified`, the feed reading and when it was made. An answer that changes keeps the one before in `vulnerability_answer_past`.
- Findings. A malicious package or an exploited vulnerability is a finding; every other match is an "affects me" answer in a list and raises nothing. `lockfiles.malicious-package` (T1195.001, critical, high) is for a package a malicious record names: a `MAL-` id or CWE-506. `lockfiles.malicious-name-removed` (T1195.001, high, low) is for when every such record names only npm's placeholder version `0.0.1-security`. `lockfiles.exploited-vulnerability` (no technique, critical, medium) is for a record linked to the catalogue. A package with both raises only the malicious finding. These findings are about a state: each stays while the dependency matches and is cleared when it goes.
- Commands. `immune vulnerabilities [--json]` lists the "affects me" answers, malicious and exploited first, then by the source's label, at most 200 with the total. `immune vulnerability <id> [--json]` gives the answer for one record id or CVE id in every checkout whose lockfiles were read. An id the data does not hold is said to be unknown, never "not affected".
- Status. `immune status --json` has a part `vulnerabilities` beside what needs a look, never counted in it. Its numbers count distinct records: `affected_records`, `affected_packages`, `affected_projects`, `affected_records_by_label`. The app's panel leaves them out; they are in the report.
- Sources. Wherever a record's text is shown, its source is named with the record's id: the GitHub Advisory Database, RustSec, OpenSSF's Malicious Packages.

### Planned, in this order

1. A distribution's packages against that distribution's own security data, keyed by release and source package and compared in dpkg order: Ubuntu's records from OSV, and the Debian security tracker's JSON fetched whole. A distribution package is never compared with an upstream version range. The readers already collect what this needs: a server's release, each package's source package, and the package of the running kernel.
2. Software outside package managers, through general identifiers: a Homebrew formula's source repository, packages read inside a container image, upstream ranges from the CVE record.
3. A change of an answer as an event in the journal, and the user's acceptance of an answer.

Inside a container `uname -r` gives the host's kernel, and no package of the container owns it. When this is built, a full reading of the kernel's package that found none must lead to "don't know" for kernel vulnerabilities, never to "not affected".

## Four answers

An answer is per vulnerability and place, a place being a scope and a kind. Built for lockfiles; planned for the rest.

- Affects me: an exact match, on a fact that is observed or declared. It wins over every reason below.
- Don't know, with a reason from a closed list. For lockfiles there are six, and an answer takes the first that applies in this order: `not_from_registry`, `version_cannot_be_compared`, `data_does_not_cover_this_version`, `place_not_read`, `feed_not_read`, `no_matcher`.
- Does not affect me, known for certain. Only with full and fresh coverage of the place, every feed reading it rests on successful and current, data that covers this release, and no fact resting only on `mentioned`. For lockfiles that means: the checkout's lockfiles read in full for the ecosystem in the latest check; the feed read within 2 hours for crates.io and 26 hours for npm, and its newest record changed within 7 days; every entry strict SemVer from the registry. The reason is `fixed` or `not_in_range`. Whether the feed is current is judged again when the answer is asked: `immune vulnerability <id>`, the totals and the pages give `unknown` with `feed_not_read` once the data it rests on is not current at that time, whatever the check that wrote the answer found. It speaks for what the lockfiles declare, not for what is installed in `node_modules` or deployed.
- Does not affect me, no signs: everything else. For lockfiles, a catalogue CVE that no record of the data names.

In the JSON of `immune vulnerability`, an answer is `affected`; `unknown` with a `reason`; or `not_affected` with a `certainty` of `known`, which carries OpenVEX's `fixed` or `vulnerable_code_not_present`, or of `no_signs`. In `immune vulnerabilities --json`, `exploited` is `null` while the list of vulnerabilities used in attacks has never been downloaded: a record not on a list that was never read is not known to be off it.

## Indicators

An incident report publishes indicators: hashes of files, domains, addresses, URLs. A list of them is a threat of a second kind, taken from a file the user or their agent gives. Text in such a list is untrusted like any feed: nothing in it is ever visited, downloaded or run, and it is never printed raw.

- The list. `indicators.json` next to the store, or the file given with `immune run --indicators <file>`; no list there is not applicable. It is a JSON array of `{"kind", "value", "note_text"}` with no other field, under 8 MiB. A kind is a STIX 2.1 object path as a pattern writes it: `file:hashes.'SHA-256'`, `domain-name:value`, `ipv4-addr:value`, `url:value`. A list out of this shape fails as a whole, and the list read before is used.
- What is matched against what. A SHA-256 against the checksum of every watched file. A domain, an IPv4 address or a URL as a whole string inside the files Immune opens as text in checkouts: the lockfiles it reads and the editor's task file. A domain is compared without case. An IPv4 address is also matched against the connections a sample sees, using the list the last check read.
- A match in a file is a fact, `matches_indicator`, written as a STIX comparison, and a new one is a finding (`indicator.match`), at the first reading too. An indicator that leaves the list retracts its match and leaves the finding as it is. A match in a connection is a finding about the program, once per process and indicator, resting on a journal entry; it is not a fact.
- What is not matched is named. A kind of that shape with no matcher, and an IPv4 block, are kept and named. So is each matched kind's missing place: a hash against files of checkouts and of installed software other than watched files, a domain or a URL against connections (a sample sees addresses, and no name is resolved). They are listed as readings with no reader, never as "no match".

Planned: a hash against the files of checkouts and of installed software, a domain or a URL against connections, names and paths of files, markers in code, and the four answers for an indicator list.

## Open

- Lockfile packages of an ecosystem with no data set are skipped and get no answer: the reason `no_matcher` is in the list but never given.
- The catalogue's own count and version fields are not checked against its list.
- A catalogue that shrinks sharply is taken as it is: each entry that left is a `threat_gone` event.
- The catalogue's server has been seen answering a conditional request with the whole file instead of "not modified". The reading is still correct and the raw copy is not duplicated.
