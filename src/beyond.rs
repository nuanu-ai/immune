//! What is beyond this Mac, told apart for a person: servers, the owner's other devices and
//! other people's devices, never one count of machines.
//!
//! How they are told apart. Every machine the store knows was named by a trace on this Mac:
//! the ssh configuration, the known hosts, a file of the server check, or the tailnet. A
//! machine the tailnet names and no other trace does, that nothing was ever read on, is a
//! device and not a server when the tailnet says so: another user's device, a colleague's
//! laptop or phone; or one of the owner's own untagged peers whose system the server check
//! cannot read at all, a phone, a tablet, a TV or a desktop system (`tailnet::DEVICE_SYSTEMS`).
//! Every other machine is a server: one the owner logs in to over SSH, or one their private
//! network shows as theirs or as the network's own. An own peer running Linux or a BSD that
//! nothing else names stays a server never checked: the owner can say it is retired or not
//! theirs. A peer whose system the tailnet does not give stays a server too, and that is
//! counted, never guessed.
//!
//! What holds on any stack: macOS ships OpenSSH, which keeps its traces in the same files on
//! every Mac. Devices are known only from Tailscale, the one private network read, and only
//! where its status gives each peer's user; on a network of another kind none is known, and
//! none is counted. A machine under the owner's word that stands, retired or not theirs, is
//! apart from all three.

use crate::{owner, resolver, store, tailnet};
use rusqlite::Connection;
use std::collections::BTreeMap;

/// The machines beyond this Mac, each as the group of entities the resolver found to be one.
pub struct Beyond {
    pub servers: Vec<Vec<String>>,
    /// The owner's own devices the server check cannot read.
    pub own_devices: Vec<Vec<String>>,
    /// Other people's devices.
    pub other_devices: Vec<Vec<String>>,
    /// Servers known only from the tailnet, which gives no system for them.
    pub system_not_given: usize,
    /// The system the tailnet gives, by entity, for machines it alone names.
    pub platform: BTreeMap<String, String>,
}

/// Whose a machine is and its system, as the tailnet says, where it does.
type Said = (Option<String>, Option<String>);

/// What the tailnet alone says of each machine no other trace names and nothing was read
/// on: whose it is and its system, where it says.
fn tailnet_only(conn: &Connection) -> rusqlite::Result<BTreeMap<String, Said>> {
    conn.prepare(
        "SELECT a.subject,
                (SELECT r.object FROM assertion r WHERE r.layer = 'live' AND r.reader = ?1
                   AND r.subject = a.subject AND r.predicate = 'relation_to_owner' LIMIT 1),
                (SELECT p.object FROM assertion p WHERE p.layer = 'live' AND p.reader = ?1
                   AND p.subject = a.subject AND p.predicate = 'runs_platform' LIMIT 1)
         FROM (SELECT DISTINCT subject FROM assertion
               WHERE layer = 'live' AND reader = ?1) a
         WHERE NOT EXISTS (SELECT 1 FROM assertion o
                           WHERE o.layer = 'live' AND o.subject = a.subject
                             AND o.reader NOT IN (?1, ?2))
           AND NOT EXISTS (SELECT 1 FROM coverage c WHERE c.scope = a.subject)",
    )?
    .query_map([tailnet::READER, resolver::READER], |r| {
        Ok((r.get(0)?, (r.get(1)?, r.get(2)?)))
    })?
    .collect()
}

/// The machines beyond `this`, the entity of this Mac, told apart.
pub fn split(conn: &Connection, this: &str) -> rusqlite::Result<Beyond> {
    let theirs = store::other_users_devices(conn)?;
    let only = tailnet_only(conn)?;
    let own = |m: &String| {
        only.get(m).is_some_and(|(relation, platform)| {
            relation.as_deref() == Some(tailnet::OWN)
                && tailnet::system(platform.as_deref()) == tailnet::System::Device
        })
    };
    let not_given = |m: &String| {
        only.get(m).is_some_and(|(_, platform)| {
            tailnet::system(platform.as_deref()) == tailnet::System::NotGiven
        })
    };
    let standing = owner::standing(conn)?;
    let mut out = Beyond {
        servers: Vec::new(),
        own_devices: Vec::new(),
        other_devices: Vec::new(),
        system_not_given: 0,
        platform: only
            .iter()
            .filter_map(|(m, (_, p))| p.clone().map(|p| (m.clone(), p)))
            .collect(),
    };
    for group in store::machine_groups(conn)? {
        if group.iter().any(|m| m == this) {
            continue;
        }
        let word = standing.iter().find(|s| group.iter().any(|m| s.covers(m)));
        if word.is_some_and(|w| w.seen.is_none()) {
            continue;
        }
        if store::only_someone_elses(&group, &theirs) {
            out.other_devices.push(group);
        } else if group.iter().all(own) {
            out.own_devices.push(group);
        } else {
            out.system_not_given += usize::from(group.iter().all(not_given));
            out.servers.push(group);
        }
    }
    Ok(out)
}
