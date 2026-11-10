//! The resolver: which machine entities are one machine under several names. Plain code,
//! no model. It runs after the readers on their live `known_as` assertions and writes
//! `same_as` links of its own. It never changes what a reader wrote. Its links are worked
//! out again on every run, so a link goes when its evidence goes.
//!
//! The rule, kept here so that it can be replaced: two machines are the same when they are
//! known by the same name or address. Names compare without case, addresses exactly; a
//! trailing dot is ignored. A port, as known hosts write one other than 22, is part of the
//! name, as ssh keys known hosts by host and port: machines behind one address with
//! forwarded ports are different machines, and none of them is the machine on port 22.
//! Loopback says nothing about which machine is meant and is not evidence.
//!
//! A server names itself in its sweep file, and unrelated servers share default host names
//! and private addresses. So what a sweep file reports about its own server is evidence
//! only when it names one machine: a full name that is not a default, or an address that
//! is not private. A bare host name or a private address is kept, and links nothing. And a
//! value that two sweep files report about themselves is evidence only when the two report
//! exactly the same names and addresses; otherwise it links nothing at all.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

/// Domains every machine may give itself by default, or that are private to one network.
const DEFAULT_DOMAINS: [&str; 4] = ["localdomain", "localdomain6", "local", "internal"];

pub const READER: &str = "resolver";
pub const KIND: &str = "machines under several names";

/// One live `known_as` assertion.
pub struct Known {
    pub entity: String,
    pub value: String,
    pub basis: String,
    pub reader: String,
}

/// Two entities that are one machine, with what they share.
pub struct Link {
    pub a: String,
    pub b: String,
    pub shared: Vec<String>,
    /// As strong as the weaker side of the best shared name.
    pub basis: String,
}

/// What a name or address is compared by, or `None` when it is not evidence.
pub fn key(value: &str) -> Option<String> {
    let v = value.trim();
    let (v, port) = match v.strip_prefix('[') {
        Some(rest) => match rest.split_once(']') {
            Some((host, after)) => (host, after.strip_prefix(':')),
            None => (rest, None),
        },
        None => (v, None),
    };
    let v = v.trim_end_matches('.');
    if v.is_empty() {
        return None;
    }
    let host = if let Ok(ip) = v.parse::<IpAddr>() {
        if ip.is_loopback() || ip.is_unspecified() {
            return None;
        }
        ip.to_string()
    } else {
        let name = v.to_lowercase();
        if name == "localhost" || name.ends_with(".localhost") {
            return None;
        }
        name
    };
    Some(match port {
        Some(port) => format!("[{host}]:{port}"),
        None => host,
    })
}

/// Whether a name or address a server gives itself names that one machine: a name with a
/// domain that is not a default one, or an address outside the private ranges. A tailnet
/// address is unique inside its tailnet and names one machine.
fn names_one_machine(value: &str) -> bool {
    let Some(key) = key(value) else {
        return false;
    };
    match key.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => !v4.is_private(),
        Ok(IpAddr::V6(v6)) => v6.segments()[0] & 0xfe00 != 0xfc00,
        Err(_) => {
            key.contains('.')
                && !DEFAULT_DOMAINS
                    .iter()
                    .any(|d| key.ends_with(&format!(".{d}")))
        }
    }
}

fn rank(basis: &str) -> u8 {
    match basis {
        "observed" => 1,
        "declared" => 2,
        "mentioned" => 3,
        _ => 4,
    }
}

/// Every pair of entities that share a name or address, each pair once, `a` before `b`.
pub fn links(known: &[Known]) -> Vec<Link> {
    // What each sweep file says its server is.
    let mut own: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for k in known.iter().filter(|k| k.reader == crate::servers::READER) {
        if let Some(key) = key(&k.value) {
            own.entry(k.entity.as_str()).or_default().insert(key);
        }
    }
    let ambiguous = |key: &str| {
        let sets: Vec<&BTreeSet<String>> = own.values().filter(|s| s.contains(key)).collect();
        sets.windows(2).any(|w| w[0] != w[1])
    };
    // Key -> entity -> its strongest basis for that key.
    let mut by_key: BTreeMap<String, BTreeMap<&str, &str>> = BTreeMap::new();
    for k in known {
        if k.reader == crate::servers::READER && !names_one_machine(&k.value) {
            continue;
        }
        let Some(key) = key(&k.value).filter(|key| !ambiguous(key)) else {
            continue;
        };
        let basis = by_key
            .entry(key)
            .or_default()
            .entry(k.entity.as_str())
            .or_insert(k.basis.as_str());
        if rank(&k.basis) < rank(basis) {
            *basis = k.basis.as_str();
        }
    }
    let mut pairs: BTreeMap<(&str, &str), Link> = BTreeMap::new();
    for (key, entities) in &by_key {
        let list: Vec<(&&str, &&str)> = entities.iter().collect();
        for (i, (a, basis_a)) in list.iter().enumerate() {
            for (b, basis_b) in &list[i + 1..] {
                let weaker = if rank(basis_a) > rank(basis_b) {
                    basis_a
                } else {
                    basis_b
                };
                let link = pairs.entry((a, b)).or_insert_with(|| Link {
                    a: a.to_string(),
                    b: b.to_string(),
                    shared: Vec::new(),
                    basis: weaker.to_string(),
                });
                link.shared.push(key.clone());
                if rank(weaker) < rank(&link.basis) {
                    link.basis = weaker.to_string();
                }
            }
        }
    }
    pairs.into_values().collect()
}

/// The machines as groups of entities joined by links, each group and the list sorted.
pub fn groups(
    ids: impl IntoIterator<Item = String>,
    links: &[(String, String)],
) -> Vec<Vec<String>> {
    let mut parent: BTreeMap<String, String> = ids.into_iter().map(|id| (id.clone(), id)).collect();
    fn root(parent: &mut BTreeMap<String, String>, id: &str) -> String {
        let mut r = id.to_string();
        while let Some(p) = parent.get(&r).filter(|p| **p != r) {
            r = p.clone();
        }
        parent.insert(id.to_string(), r.clone());
        r
    }
    for (a, b) in links {
        let (ra, rb) = (root(&mut parent, a), root(&mut parent, b));
        if ra != rb {
            let (low, high) = if ra < rb { (ra, rb) } else { (rb, ra) };
            parent.insert(high, low);
        }
    }
    let ids: Vec<String> = parent.keys().cloned().collect();
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for id in ids {
        let r = root(&mut parent, &id);
        out.entry(r).or_default().push(id);
    }
    out.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::names_one_machine;

    #[test]
    fn what_a_server_says_about_itself_names_it_only_when_no_unrelated_machine_says_the_same() {
        // Default names and private addresses repeat across unrelated servers; a link
        // through them folds one server into another and makes a server never read look read.
        for value in [
            "web-1",
            "localhost.localdomain",
            "localhost6.localdomain6",
            "raspberrypi.local",
            "ip-172-31-5-10.eu-west-1.compute.internal",
            "10.0.0.5",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.10",
            "fc00::1",
            "fdff:ffff::1",
            "127.0.0.1",
        ] {
            assert!(!names_one_machine(value), "{value} names one machine");
        }
        for value in [
            "web-host.example.org",
            "Build-Box.example-tail.ts.net.",
            "100.64.0.7",
            "100.127.255.254",
            "172.15.255.255",
            "172.32.0.1",
            "11.0.0.1",
            "203.0.113.10",
            "fbff::1",
            "fe00::1",
            "2001:db8::1",
        ] {
            assert!(
                names_one_machine(value),
                "{value} does not name one machine"
            );
        }
    }
}
