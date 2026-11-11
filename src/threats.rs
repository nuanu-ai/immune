//! The threat list: the CISA catalogue of known exploited vulnerabilities, read whole on
//! every run. The contract is in docs/threats.md.
//!
//! What is asked of the network never depends on the estate: the request is built from the
//! catalogue's address and the ETag the catalogue itself sent last time, and from nothing
//! else in the store. The catalogue's content is untrusted: it is parsed under a size cap,
//! no path or command is ever taken from it, and its text is escaped wherever it is shown.
//!
//! Threats are not facts and no answer is given about any of them yet.

use crate::store;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};

pub const SOURCE: &str = "cisa-kev";
pub const URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
/// The curl every Mac has. No other is looked for.
pub const CURL: &str = "/usr/bin/curl";
/// The raw copy's name in the store's folder.
pub const RAW: &str = "cisa-kev.json";
/// The catalogue was about 1.8 MB in 2026. Anything larger than this is not read, however
/// it arrives: compressed or not, from the network or from a file.
pub const MAX_BYTES: u64 = 8 * 1024 * 1024;

/// One entry of the catalogue, its text as the catalogue gives it.
pub struct Entry {
    pub id: String,
    pub vendor: String,
    pub product: String,
    pub name: String,
    pub date_added: String,
}

/// What one attempt to read the catalogue brought.
pub enum Fetched {
    Body {
        bytes: Vec<u8>,
        etag: Option<String>,
    },
    /// The catalogue answered that it has not changed since the ETag it was asked with.
    Unchanged,
    Failed(String),
}

/// The arguments curl is run with. They are the same for every user who holds the same
/// version of the catalogue: nothing about the estate is in them.
pub fn request(etag: Option<&str>) -> Vec<String> {
    curl_args(URL, MAX_BYTES, 300, None, etag)
}

/// The arguments of one request to a feed: its address, its cap, how long it may take, the
/// file the body goes to instead of stdout, and the ETag the feed itself sent last. The other
/// feeds use the same invocation, so this is the one place it is written.
pub fn curl_args(
    url: &str,
    cap: u64,
    max_time: u32,
    output: Option<&Path>,
    etag: Option<&str>,
) -> Vec<String> {
    let (max, time) = (cap.to_string(), max_time.to_string());
    let mut args: Vec<String> = [
        // First, or curl reads ~/.curlrc, which could change what is asked.
        "--disable",
        "--silent",
        "--show-error",
        "--fail",
        "--proto",
        "=https",
        "--compressed",
        "--max-filesize",
        &max,
        "--connect-timeout",
        "30",
        "--max-time",
        &time,
    ]
    .iter()
    .map(|a| a.to_string())
    .collect();
    if let Some(output) = output {
        args.push("--output".to_string());
        args.push(output.display().to_string());
    }
    // The status and the ETag go to stderr, after anything curl says there. curl itself
    // turns each `\n` into a new line.
    args.push("--write-out".to_string());
    args.push("%{stderr}\\n%{http_code} %header{etag}\\n".to_string());
    if let Some(etag) = etag {
        args.push("--header".to_string());
        args.push(format!("If-None-Match: {etag}"));
    }
    args.push(url.to_string());
    args
}

/// What curl's exit and the status line it wrote to stderr say of one request.
pub enum Answer {
    /// The body came, with the ETag the server sent if it is a plain one.
    Body(Option<String>),
    /// "Not modified", in answer to the program's own ETag.
    NotModified,
    Failed(String),
}

/// Reads curl's answer. "Not modified" is believed only when the request carried an ETag.
pub fn answer(status: std::process::ExitStatus, said: &[u8], asked_with_etag: bool) -> Answer {
    let said = String::from_utf8_lossy(said);
    let mut lines = said.lines().map(str::trim).filter(|l| !l.is_empty());
    if !status.success() {
        let why = lines.next().unwrap_or_default();
        return Answer::Failed(format!("curl failed, {status}: {why}"));
    }
    let last = lines.next_back().unwrap_or_default();
    let (code, sent) = last.split_once(' ').unwrap_or((last, ""));
    match code {
        "200" => Answer::Body(valid_etag(sent.trim())),
        "304" if asked_with_etag => Answer::NotModified,
        other => Answer::Failed(format!("the server answered HTTP {other}")),
    }
}

/// Fetches the catalogue with curl. The body is read from curl's output under the cap, so
/// a body that decompresses to more than the cap is not read either.
pub fn fetch(curl: &Path, etag: Option<&str>) -> Fetched {
    let child = Command::new(curl)
        .args(request(etag))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(e) => return Fetched::Failed(format!("cannot run {}: {e}", curl.display())),
    };
    let body = capped(child.stdout.take().expect("stdout is piped"));
    let mut said = Vec::new();
    let _ = child
        .stderr
        .take()
        .expect("stderr is piped")
        .read_to_end(&mut said);
    let status = match child.wait() {
        Ok(status) => status,
        Err(e) => return Fetched::Failed(format!("curl did not finish: {e}")),
    };
    let bytes = match body {
        Ok(bytes) => bytes,
        Err(reason) => return Fetched::Failed(reason),
    };
    match answer(status, &said, etag.is_some()) {
        Answer::Body(etag) => Fetched::Body { bytes, etag },
        Answer::NotModified => Fetched::Unchanged,
        Answer::Failed(reason) => Fetched::Failed(reason),
    }
}

/// An ETag goes back to the server in a header, so only a plain one is kept.
fn valid_etag(etag: &str) -> Option<String> {
    let plain =
        !etag.is_empty() && etag.len() <= 256 && etag.bytes().all(|b| (0x21..=0x7e).contains(&b));
    plain.then(|| etag.to_string())
}

/// Reads a saved copy of the catalogue instead of fetching it.
pub fn read_file(path: &Path) -> Fetched {
    match std::fs::File::open(path) {
        Ok(file) => match capped(file) {
            Ok(bytes) => Fetched::Body { bytes, etag: None },
            Err(reason) => Fetched::Failed(reason),
        },
        Err(e) => Fetched::Failed(format!("cannot read {}: {e}", path.display())),
    }
}

fn capped(from: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    from.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("could not be read: {e}"))?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(format!("larger than the cap of {MAX_BYTES} bytes"));
    }
    Ok(bytes)
}

/// The entries of the catalogue, in its order, each id once. Anything that is not the
/// catalogue's shape fails the whole reading: a reading that dropped an entry would mark
/// it gone.
pub fn parse(bytes: &[u8]) -> Result<Vec<Entry>, String> {
    let doc: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| format!("not JSON: {e}"))?;
    let list = doc
        .get("vulnerabilities")
        .and_then(serde_json::Value::as_array)
        .ok_or("no list of vulnerabilities")?;
    if list.is_empty() {
        return Err("the list of vulnerabilities is empty".to_string());
    }
    let mut seen = BTreeSet::new();
    let mut entries = Vec::new();
    for (i, item) in list.iter().enumerate() {
        let text = |key: &str| {
            item.get(key)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let id = text("cveID");
        if !cve_id(&id) {
            return Err(format!("entry {} has no valid CVE id", i + 1));
        }
        if !seen.insert(id.clone()) {
            continue;
        }
        entries.push(Entry {
            vendor: text("vendorProject"),
            product: text("product"),
            name: text("vulnerabilityName"),
            date_added: text("dateAdded"),
            id,
        });
    }
    Ok(entries)
}

/// `CVE-<digits>-<digits>`. The id is a key and will be part of what is asked of public
/// indexes, so nothing else is taken.
fn cve_id(id: &str) -> bool {
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    match id.strip_prefix("CVE-").and_then(|r| r.split_once('-')) {
        Some((year, number)) => digits(year) && digits(number),
        None => false,
    }
}

/// One reading of the catalogue as the store keeps it.
#[derive(Default)]
pub struct Reading {
    pub outcome: &'static str,
    pub reason: Option<String>,
    pub etag: Option<String>,
    pub sha256: Option<String>,
    pub raw_path: Option<String>,
    pub entries: Option<usize>,
}

pub fn put_reading(tx: &Transaction, run_id: &str, at: i64, r: &Reading) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO feed_reading (source, run_id, at, outcome, reason, etag, sha256,
                                   raw_path, entries)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            SOURCE,
            run_id,
            at,
            r.outcome,
            r.reason,
            r.etag,
            r.sha256,
            r.raw_path,
            r.entries.map(|n| n as i64)
        ],
    )?;
    Ok(())
}

/// The latest reading that read the catalogue, and when it was taken.
pub fn last_good(conn: &Connection) -> rusqlite::Result<Option<(i64, Reading)>> {
    conn.query_row(
        "SELECT at, etag, sha256, raw_path FROM feed_reading
         WHERE source = ?1 AND outcome != 'failed' ORDER BY id DESC LIMIT 1",
        [SOURCE],
        |r| {
            Ok((
                r.get(0)?,
                Reading {
                    etag: r.get(1)?,
                    sha256: r.get(2)?,
                    raw_path: r.get(3)?,
                    ..Reading::default()
                },
            ))
        },
    )
    .optional()
}

/// How many threats the catalogue held at its latest reading that read it.
pub fn held(conn: &Connection) -> rusqlite::Result<usize> {
    conn.query_row(
        "SELECT COUNT(*) FROM threat WHERE source = ?1 AND gone_at IS NULL",
        [SOURCE],
        |r| r.get::<_, i64>(0),
    )
    .map(|n| n as usize)
}

/// Brings the threat list in line with a reading of the whole catalogue. A threat is new
/// when its id is in the reading and not in the list, which includes one that left and came
/// back. A threat that is no longer in the catalogue is kept with the time it left. What it
/// changed is in the journal, where `status::catalogue` counts it.
pub fn record(tx: &Transaction, run_id: &str, at: i64, entries: &[Entry]) -> rusqlite::Result<()> {
    let first = !tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM threat WHERE source = ?1)",
        [SOURCE],
        |r| r.get::<_, bool>(0),
    )?;
    let present: BTreeMap<String, String> = tx
        .prepare("SELECT id, name FROM threat WHERE source = ?1 AND gone_at IS NULL")?
        .query_map([SOURCE], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    for e in entries {
        tx.execute(
            "INSERT INTO threat (source, id, vendor, product, name, date_added, first_run,
                                 first_seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT (source, id) DO UPDATE SET
                 vendor = excluded.vendor, product = excluded.product, name = excluded.name,
                 date_added = excluded.date_added, gone_at = NULL, gone_run = NULL",
            params![
                SOURCE,
                e.id,
                e.vendor,
                e.product,
                e.name,
                e.date_added,
                run_id,
                at
            ],
        )?;
        if !first && !present.contains_key(&e.id) {
            store::journal_threat(tx, at, run_id, "threat_added", SOURCE, Some(&e.id), &e.name)?;
        }
    }
    let ids: BTreeSet<&str> = entries.iter().map(|e| e.id.as_str()).collect();
    for (id, name) in present.iter().filter(|(id, _)| !ids.contains(id.as_str())) {
        tx.execute(
            "UPDATE threat SET gone_at = ?1, gone_run = ?2 WHERE source = ?3 AND id = ?4",
            params![at, run_id, SOURCE, id],
        )?;
        store::journal_threat(tx, at, run_id, "threat_gone", SOURCE, Some(id), name)?;
    }
    if first {
        let count = entries.len().to_string();
        store::journal_threat(tx, at, run_id, "threats_first_read", SOURCE, None, &count)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{parse, valid_etag};

    fn catalogue(ids: &[serde_json::Value]) -> Vec<u8> {
        let list: Vec<serde_json::Value> = ids
            .iter()
            .map(|id| serde_json::json!({ "cveID": id, "vendorProject": "Examplesoft" }))
            .collect();
        serde_json::json!({ "vulnerabilities": list })
            .to_string()
            .into_bytes()
    }

    #[test]
    fn an_entry_whose_id_is_not_a_plain_cve_id_fails_the_whole_reading() {
        // The id is the key of the threat list and will be part of what is asked of public
        // indexes: no path, no markup, nothing but the CVE id's own shape is taken.
        for id in [
            serde_json::json!(null),
            serde_json::json!(20990001),
            serde_json::json!(""),
            serde_json::json!("CVE-"),
            serde_json::json!("CVE-2099"),
            serde_json::json!("CVE-2099-"),
            serde_json::json!("CVE--0001"),
            serde_json::json!("cve-2099-0001"),
            serde_json::json!("CVE-2099-0001/../x"),
            serde_json::json!("CVE-20x9-0001"),
        ] {
            let bytes = catalogue(&[serde_json::json!("CVE-2099-0002"), id.clone()]);
            assert_eq!(
                parse(&bytes).err().as_deref(),
                Some("entry 2 has no valid CVE id"),
                "{id}"
            );
        }
        let ok = parse(&catalogue(&[serde_json::json!("CVE-2099-123456")])).unwrap();
        assert_eq!(ok[0].id, "CVE-2099-123456");
        assert_eq!(ok[0].vendor, "Examplesoft");
    }

    #[test]
    fn an_id_listed_twice_is_one_threat() {
        // Counted twice, one new threat would be reported as two.
        let id = serde_json::json!("CVE-2099-0001");
        let entries = parse(&catalogue(&[id.clone(), id])).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn an_etag_that_is_not_plain_is_never_sent_back() {
        // The ETag comes from the server and goes back to it in a header on the next run.
        assert_eq!(
            valid_etag("W/\"5f2c-61a\"").as_deref(),
            Some("W/\"5f2c-61a\"")
        );
        for bad in ["", "\"a b\"", "\"a\tb\"", "\"\u{7f}\"", "\"é\""] {
            assert_eq!(valid_etag(bad), None, "{bad:?}");
        }
        assert_eq!(valid_etag(&"a".repeat(256)).map(|e| e.len()), Some(256));
        assert_eq!(valid_etag(&"a".repeat(257)), None);
    }
}
