//! The resolver: which machine entities are one machine under several names. Plain code,
//! no model. It runs after the readers on their live `known_as` assertions and writes
//! `same_as` links of its own. It never changes what a reader wrote. Its links are worked
//! out again on every run, so a link goes when its evidence goes.
//!
//! The rule, kept here so that it can be replaced: two machines are the same when they are
//! known by the same name or address. Names compare without case, addresses exactly; a
//! trailing dot and a port are ignored. Loopback says nothing about which machine is meant
//! and is not evidence.

use std::collections::BTreeMap;
use std::net::IpAddr;

pub const READER: &str = "resolver";
pub const KIND: &str = "machines under several names";

/// One live `known_as` assertion.
pub struct Known {
    pub entity: String,
    pub value: String,
    pub basis: String,
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
    let v = match v.strip_prefix('[') {
        Some(rest) => rest.split_once(']').map_or(rest, |(h, _)| h),
        None => v,
    };
    let v = match v.rsplit_once(':') {
        Some((host, port))
            if !host.contains(':')
                && !port.is_empty()
                && port.bytes().all(|b| b.is_ascii_digit()) =>
        {
            host
        }
        _ => v,
    };
    let v = v.trim_end_matches('.');
    if v.is_empty() {
        return None;
    }
    if let Ok(ip) = v.parse::<IpAddr>() {
        return (!ip.is_loopback() && !ip.is_unspecified()).then(|| ip.to_string());
    }
    let name = v.to_lowercase();
    (name != "localhost" && !name.ends_with(".localhost")).then_some(name)
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
    // Key -> entity -> its strongest basis for that key.
    let mut by_key: BTreeMap<String, BTreeMap<&str, &str>> = BTreeMap::new();
    for k in known {
        let Some(key) = key(&k.value) else { continue };
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
