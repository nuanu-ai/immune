//! What is beyond this Mac, told apart for a person: servers and other devices, never one
//! count of machines.
//!
//! How they are told apart. Every machine the store knows was named by a trace on this Mac:
//! the ssh configuration, the known hosts, a file of the server check, or the tailnet. A
//! machine the tailnet says belongs to another user, that no other trace names and that
//! nothing was ever read on, is another device: a colleague's laptop or phone, not the
//! owner's to check. Every other machine is a server: one he logs in to over SSH, or one his
//! private network shows as his or as the network's own.
//!
//! What holds on any stack: macOS ships OpenSSH, which keeps its traces in the same files on
//! every Mac. Other devices are known only from Tailscale, the one private network read, and
//! only where its status gives each peer's user; on a network of another kind none is known,
//! and none is counted. The owner's own devices in the tailnet that he does not log in to,
//! such as his phone, cannot be told from a server he reaches another way, so they are
//! counted as servers that were never checked. A machine under the owner's word that stands,
//! retired or not his, is apart from both.

use crate::{owner, store};
use rusqlite::Connection;

/// The machines beyond this Mac, each as the group of entities the resolver found to be one.
pub struct Beyond {
    pub servers: Vec<Vec<String>>,
    pub other_devices: Vec<Vec<String>>,
}

/// The machines beyond `this`, the entity of this Mac, told apart.
pub fn split(conn: &Connection, this: &str) -> rusqlite::Result<Beyond> {
    let theirs = store::other_users_devices(conn)?;
    let standing = owner::standing(conn)?;
    let mut out = Beyond {
        servers: Vec::new(),
        other_devices: Vec::new(),
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
        } else {
            out.servers.push(group);
        }
    }
    Ok(out)
}
