//! A property list read by CoreFoundation, which every Mac has and Apple maintains: the same
//! parser the preferences system reads a preferences file with, in its XML, binary and old
//! text forms. Nothing of the format is parsed here.
//!
//! What is taken is the value at a few top-level keys, each made canonical here by an exact
//! encoding of what CoreFoundation parsed, so that the same value reads the same whether the
//! file is binary, XML or text, and whatever else the file holds. A string is taken as its
//! UTF-16 code units, which is what a `CFString` holds: written as XML it would pass through
//! UTF-8, where an unpaired surrogate has no form and two different strings could come out
//! alike. Nothing is normalised: two strings whose code units differ are two values, whatever
//! they look like. An array and a dictionary are taken element by element, the dictionary's
//! entries in the order of their encoded keys. Any other value (a number, a date, data, a
//! boolean) is written alone as a binary property list by CoreFoundation, which keeps it whole:
//! XML keeps a date only to the second. This encoding is our own because it is not a format
//! anyone reads back; only a checksum of it leaves this file. Ownership of CoreFoundation
//! objects is as `codesign.rs` describes it; no error object is asked for, so none is owned.

use std::ffi::c_void;

use crate::codesign::{Owned, cf_string};

type CFTypeRef = *const c_void;
type CFIndex = isize;

#[repr(C)]
struct CFRange {
    location: CFIndex,
    length: CFIndex,
}

/// `kCFPropertyListImmutable`.
const IMMUTABLE: usize = 0;
/// `kCFPropertyListBinaryFormat_v1_0`.
const BINARY: CFIndex = 200;
/// How deep into arrays and dictionaries a value is followed. A login hook is one string; a
/// value nested deeper is not read, and the reading says so, rather than run out of stack on a
/// file written to do that.
pub const DEPTH: usize = 32;
/// How many values one key's value may hold, itself and everything inside it, counted each
/// time it is met. A binary property list can refer to one array from many places, and
/// CoreFoundation shares it rather than copy it, so a file of a few hundred bytes can hold a
/// value that, walked as a tree, has more leaves than memory: this is what keeps the walk
/// bounded. A login hook is one string, one value; ten thousand is far beyond any real one and
/// is walked in milliseconds.
pub const NODES: usize = 10_000;
/// How many bytes the encoding of one key's value may come to. A hook is a path, under 1,024
/// bytes on macOS and so under about 2 KiB here; one MiB is far beyond it and bounds memory.
pub const BYTES: usize = 1 << 20;

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFGetTypeID(cf: CFTypeRef) -> usize;
    fn CFDictionaryGetTypeID() -> usize;
    fn CFDictionaryGetValue(dict: CFTypeRef, key: CFTypeRef) -> CFTypeRef;
    fn CFDictionaryGetCount(dict: CFTypeRef) -> CFIndex;
    fn CFDictionaryGetKeysAndValues(dict: CFTypeRef, keys: *mut CFTypeRef, values: *mut CFTypeRef);
    fn CFArrayGetTypeID() -> usize;
    fn CFArrayGetCount(array: CFTypeRef) -> CFIndex;
    fn CFArrayGetValueAtIndex(array: CFTypeRef, index: CFIndex) -> CFTypeRef;
    fn CFStringGetTypeID() -> usize;
    fn CFStringGetLength(string: CFTypeRef) -> CFIndex;
    fn CFStringGetCharacters(string: CFTypeRef, range: CFRange, buffer: *mut u16);
    fn CFDataGetTypeID() -> usize;
    fn CFDataCreate(allocator: CFTypeRef, bytes: *const u8, length: CFIndex) -> CFTypeRef;
    fn CFDataGetLength(data: CFTypeRef) -> CFIndex;
    fn CFDataGetBytePtr(data: CFTypeRef) -> *const u8;
    fn CFPropertyListCreateWithData(
        allocator: CFTypeRef,
        data: CFTypeRef,
        options: usize,
        format: *mut CFIndex,
        error: *mut CFTypeRef,
    ) -> CFTypeRef;
    fn CFPropertyListCreateData(
        allocator: CFTypeRef,
        list: CFTypeRef,
        format: CFIndex,
        options: usize,
        error: *mut CFTypeRef,
    ) -> CFTypeRef;
}

/// Why a file was not taken as preferences, in the program's own words: what the parser said
/// is not kept, since the file may have been written to say anything.
pub const NOT_A_PLIST: &str = "not a property list macOS can read";
pub const NOT_A_DICTIONARY: &str = "a property list that is not a dictionary of preferences";
/// Why the value at one key was not read, its neighbours being read.
pub const TOO_DEEP: &str = "a value nested deeper than this build reads";
pub const NOT_ENCODED: &str = "a value CoreFoundation could not write back";
pub const NO_KEY: &str = "the key could not be looked up";
pub const TOO_LARGE: &str = "its value is larger than this version reads";

/// For each of `keys` the file holds at its top, in the order given, the value there in the
/// exact encoding above, or why that one value was not read. A key the dictionary does not
/// hold is left out: the file was read whole and it is not there. A file that is not a
/// property list, or whose top is not a dictionary, is an error with why.
#[allow(clippy::type_complexity)]
pub fn values<'k>(
    bytes: &[u8],
    keys: &[&'k str],
) -> Result<Vec<(&'k str, Result<Vec<u8>, &'static str>)>, &'static str> {
    // SAFETY: the bytes are valid for their length; the call copies them. Owned: `Create`.
    let data = Owned::take(unsafe {
        CFDataCreate(std::ptr::null(), bytes.as_ptr(), bytes.len() as CFIndex)
    })
    .ok_or(NOT_A_PLIST)?;
    // SAFETY: `data` is live; neither the format nor an error is asked for, which the header
    // allows. Owned: `Create`.
    let list = Owned::take(unsafe {
        CFPropertyListCreateWithData(
            std::ptr::null(),
            data.0,
            IMMUTABLE,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    })
    .ok_or(NOT_A_PLIST)?;
    // SAFETY: plain functions of CoreFoundation on a live object.
    if unsafe { CFGetTypeID(list.0) != CFDictionaryGetTypeID() } {
        return Err(NOT_A_DICTIONARY);
    }
    let mut out = Vec::new();
    for key in keys {
        // A key that cannot be looked up was not read: never taken as one that is not there.
        let Some(name) = cf_string(key) else {
            out.push((*key, Err(NO_KEY)));
            continue;
        };
        // SAFETY: `list` is a live dictionary and `name` a live string. The value is lent: it
        // is used only while `list` lives and is never released.
        let value = unsafe { CFDictionaryGetValue(list.0, name.0) };
        if value.is_null() {
            continue;
        }
        let mut bytes = Vec::new();
        let mut budget = Budget {
            nodes: NODES,
            bytes: BYTES,
        };
        let encoded = encode(value, 0, &mut budget, &mut bytes).map(|()| bytes);
        out.push((*key, encoded));
    }
    Ok(out)
}

/// What is left of what one key's value may cost: `NODES` and `BYTES`.
struct Budget {
    nodes: usize,
    bytes: usize,
}

impl Budget {
    /// Takes `nodes` values and `bytes` bytes, or says the value is larger than this version
    /// reads.
    fn spend(&mut self, nodes: usize, bytes: usize) -> Result<(), &'static str> {
        if nodes > self.nodes || bytes > self.bytes {
            return Err(TOO_LARGE);
        }
        self.nodes -= nodes;
        self.bytes -= bytes;
        Ok(())
    }

    /// Whether `nodes` values and `bytes` bytes are still within it, asked before anything that
    /// size is made; what is made is taken when it is.
    fn fits(&self, nodes: usize, bytes: usize) -> Result<(), &'static str> {
        if nodes > self.nodes || bytes > self.bytes {
            return Err(TOO_LARGE);
        }
        Ok(())
    }
}

/// Appends `n` as eight bytes.
fn count(out: &mut Vec<u8>, n: usize) {
    out.extend_from_slice(&(n as u64).to_be_bytes());
}

/// Appends a live property list value in the exact encoding: a tag, a count, then what it
/// holds. Lent values are used only while their container lives and are never released. Every
/// value met, and every byte, is taken from `budget`, and nothing is made before it is known
/// to fit: a value referred to from many places is counted each time, as it is walked.
fn encode(
    value: CFTypeRef,
    depth: usize,
    budget: &mut Budget,
    out: &mut Vec<u8>,
) -> Result<(), &'static str> {
    if depth > DEPTH {
        return Err(TOO_DEEP);
    }
    // The value itself: a tag and a count.
    budget.spend(1, 9)?;
    // SAFETY: plain functions of CoreFoundation on a live object.
    let id = unsafe { CFGetTypeID(value) };
    if id == unsafe { CFStringGetTypeID() } {
        // SAFETY: `value` is a live string.
        let length = unsafe { CFStringGetLength(value) }.max(0);
        budget.spend(0, 2 * length as usize)?;
        // SAFETY: `value` is a live string; the buffer holds exactly its length in code units.
        let units = unsafe {
            let mut units = vec![0u16; length as usize];
            CFStringGetCharacters(
                value,
                CFRange {
                    location: 0,
                    length,
                },
                units.as_mut_ptr(),
            );
            units
        };
        out.push(b's');
        count(out, units.len());
        for unit in units {
            out.extend_from_slice(&unit.to_be_bytes());
        }
    } else if id == unsafe { CFArrayGetTypeID() } {
        // SAFETY: `value` is a live array; each index is below its count.
        let n = unsafe { CFArrayGetCount(value) }.max(0);
        budget.fits(n as usize, 0)?;
        out.push(b'a');
        count(out, n as usize);
        for i in 0..n {
            let item = unsafe { CFArrayGetValueAtIndex(value, i) };
            encode(item, depth + 1, budget, out)?;
        }
    } else if id == unsafe { CFDictionaryGetTypeID() } {
        // SAFETY: `value` is a live dictionary; both buffers hold exactly its count.
        let n = unsafe { CFDictionaryGetCount(value) }.max(0) as usize;
        // Its entries must fit before their buffers are made.
        budget.fits(2 * n, 0)?;
        let mut keys = vec![std::ptr::null(); n];
        let mut values = vec![std::ptr::null(); n];
        unsafe { CFDictionaryGetKeysAndValues(value, keys.as_mut_ptr(), values.as_mut_ptr()) };
        let mut entries = Vec::with_capacity(n);
        for (k, v) in keys.into_iter().zip(values) {
            let (mut key, mut held) = (Vec::new(), Vec::new());
            encode(k, depth + 1, budget, &mut key)?;
            encode(v, depth + 1, budget, &mut held)?;
            entries.push((key, held));
        }
        // Keys are distinct, so their encodings are: the order is the same for every reading.
        entries.sort();
        out.push(b'd');
        count(out, n);
        for (key, held) in entries {
            out.extend_from_slice(&key);
            out.extend_from_slice(&held);
        }
    } else {
        // Data, the one other value that can be long, is measured before it is copied.
        if id == unsafe { CFDataGetTypeID() } {
            // SAFETY: `value` is live data.
            budget.fits(0, unsafe { CFDataGetLength(value) }.max(0) as usize)?;
        }
        let leaf = binary(value).ok_or(NOT_ENCODED)?;
        budget.spend(0, leaf.len())?;
        out.push(b'b');
        count(out, leaf.len());
        out.extend_from_slice(&leaf);
    }
    Ok(())
}

/// A value of a property list written alone as a binary property list.
fn binary(value: CFTypeRef) -> Option<Vec<u8>> {
    // SAFETY: `value` is a live property list object; no error is asked for. Owned: `Create`.
    let data = Owned::take(unsafe {
        CFPropertyListCreateData(std::ptr::null(), value, BINARY, 0, std::ptr::null_mut())
    })?;
    // SAFETY: `data` is a live data object; its bytes are valid for its length while it lives,
    // and they are copied before it is released.
    let bytes = unsafe {
        let length = CFDataGetLength(data.0).max(0) as usize;
        std::slice::from_raw_parts(CFDataGetBytePtr(data.0), length).to_vec()
    };
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML_HOOK: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>GuestEnabled</key>
	<false/>
	<key>LoginHook</key>
	<string>/Library/Scripts/example.sh</string>
</dict>
</plist>
"#;

    /// The same preferences in the old text form the parser also reads, with another value
    /// beside the hook.
    const TEXT_HOOK: &str = "{ GuestEnabled = 1; LoginHook = \"/Library/Scripts/example.sh\"; }";

    /// The same hook in the binary form macOS writes preferences in, beside another setting:
    /// an invented file converted by `plutil -convert binary1`.
    const BINARY_HOOK: &str = "62706c6973743030d2010203045c6c617374557365724e616d65594c6f67\
        696e486f6f6b57736f6d656f6e655f101b2f4c6962726172792f53637269\
        7074732f6578616d706c652e7368080d1a242c0000000000000101000000\
        00000000050000000000000000000000000000004a";

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn a_hook_reads_the_same_in_every_form_macos_reads_and_whatever_else_the_file_holds() {
        // A preferences file is binary or XML as macOS last wrote it, and other settings in it
        // change for their own reasons: only the hook itself may count.
        let keys = ["LoginHook", "LogoutHook"];
        let xml = values(XML_HOOK.as_bytes(), &keys).unwrap();
        let text = values(TEXT_HOOK.as_bytes(), &keys).unwrap();
        let binary = values(&unhex(BINARY_HOOK), &keys).unwrap();
        assert_eq!(xml.len(), 1);
        assert_eq!(xml[0].0, "LoginHook");
        assert!(xml[0].1.is_ok());
        assert_eq!(xml, text);
        assert_eq!(xml, binary);
        let other = XML_HOOK.replace("example.sh", "other.sh");
        assert_ne!(values(other.as_bytes(), &keys).unwrap(), xml);
    }

    #[test]
    fn a_file_that_is_not_preferences_is_said_and_never_read_as_holding_no_hook() {
        // A file that cannot be parsed would otherwise read as one with no hook in it: calm
        // about a file that was not read.
        assert_eq!(
            values(b"\x00\x01 not a plist", &["LoginHook"]),
            Err(NOT_A_PLIST)
        );
        assert_eq!(
            values(b"(\"LoginHook\", \"x\")", &["LoginHook"]),
            Err(NOT_A_DICTIONARY)
        );
    }

    /// A binary property list of one dictionary that holds `key`, in ASCII, at a string of the
    /// UTF-16 code units given: the form macOS writes a string that is not ASCII in.
    fn utf16(key: &str, units: &[u16]) -> Vec<u8> {
        assert!(key.len() < 15 && units.len() < 15);
        let mut out = b"bplist00".to_vec();
        let mut offsets = vec![out.len() as u8];
        out.extend_from_slice(&[0xD1, 1, 2]);
        offsets.push(out.len() as u8);
        out.push(0x50 | key.len() as u8);
        out.extend_from_slice(key.as_bytes());
        offsets.push(out.len() as u8);
        out.push(0x60 | units.len() as u8);
        for u in units {
            out.extend_from_slice(&u.to_be_bytes());
        }
        let table = out.len() as u64;
        out.extend_from_slice(&offsets);
        out.extend_from_slice(&[0, 0, 0, 0, 0, 0, 1, 1]);
        out.extend_from_slice(&3u64.to_be_bytes());
        out.extend_from_slice(&0u64.to_be_bytes());
        out.extend_from_slice(&table.to_be_bytes());
        out
    }

    fn hook(bytes: &[u8]) -> Vec<u8> {
        let mut read = values(bytes, &["LoginHook"]).unwrap();
        assert_eq!(read.len(), 1, "{read:?}");
        read.remove(0).1.unwrap()
    }

    #[test]
    fn two_strings_whose_code_units_differ_never_hash_alike() {
        // A string goes through no conversion that could merge two: unpaired surrogates, the
        // replacement character, and the two Unicode forms of one letter all stay apart.
        let slash = u16::from(b'/');
        let strings: [&[u16]; 6] = [
            &[slash, 0xD800],
            &[slash, 0xDBFF],
            &[slash, 0xDC00],
            &[slash, 0xFFFD],
            &[slash, 0x00E9],
            &[slash, u16::from(b'e'), 0x0301],
        ];
        let read: Vec<Vec<u8>> = strings
            .iter()
            .map(|u| hook(&utf16("LoginHook", u)))
            .collect();
        for (i, a) in read.iter().enumerate() {
            for b in &read[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn one_string_hashes_one_way_whether_the_file_keeps_it_as_ascii_utf16_or_xml() {
        // macOS writes a string in ASCII when it can and in UTF-16 otherwise; XML holds UTF-8.
        let xml = |s: &str| XML_HOOK.replace("/Library/Scripts/example.sh", s);
        let ascii: Vec<u16> = "/x.sh".encode_utf16().collect();
        assert_eq!(
            hook(&utf16("LoginHook", &ascii)),
            hook(xml("/x.sh").as_bytes())
        );
        let accented: Vec<u16> = "/caf\u{e9}.sh".encode_utf16().collect();
        assert_eq!(
            hook(&utf16("LoginHook", &accented)),
            hook(xml("/caf\u{e9}.sh").as_bytes())
        );
    }

    #[test]
    fn different_values_in_a_hook_dictionary_are_not_reported_as_unchanged() {
        let xml = |value: &str| {
            XML_HOOK.replace(
                "<string>/Library/Scripts/example.sh</string>",
                &format!("<dict><key>data</key><data>{value}</data></dict>"),
            )
        };
        assert_ne!(hook(xml("AAEC").as_bytes()), hook(xml("AAED").as_bytes()));
    }

    #[test]
    fn a_value_that_cannot_be_read_is_named_and_the_keys_beside_it_are_still_read() {
        // One value nested too deep does not make the file unread: the hook beside it counts.
        let deep = format!(
            "{}<string>x</string>{}",
            "<array>".repeat(DEPTH + 2),
            "</array>".repeat(DEPTH + 2)
        );
        let file = XML_HOOK.replace(
            "<key>GuestEnabled</key>\n\t<false/>",
            &format!("<key>LogoutHook</key>{deep}"),
        );
        let read = values(file.as_bytes(), &["LoginHook", "LogoutHook"]).unwrap();
        assert_eq!(read.len(), 2, "{read:?}");
        assert_eq!(read[0].0, "LoginHook");
        assert!(read[0].1.is_ok());
        assert_eq!(read[1], ("LogoutHook", Err(TOO_DEEP)));
    }

    /// An invented binary property list whose `LoginHook` is a chain of `d` arrays, each
    /// holding `k` references to the next, k^d leaves in a few hundred bytes, and whose
    /// `LogoutHook` is a short path.
    fn shared(k: u8, d: u8) -> Vec<u8> {
        let mut objects: Vec<Vec<u8>> = vec![
            vec![0xD2, 1, 2, 3, 4 + d],
            [&[0x59][..], b"LoginHook"].concat(),
            [&[0x5A][..], b"LogoutHook"].concat(),
        ];
        for level in 0..d {
            let mut array = vec![0xA0 | k];
            array.extend(std::iter::repeat_n(3 + level + 1, k as usize));
            objects.push(array);
        }
        objects.push(vec![0xA0]);
        objects.push([&[0x55][..], b"/x.sh"].concat());
        let mut out = b"bplist00".to_vec();
        let mut offsets = Vec::new();
        for o in &objects {
            offsets.push(out.len() as u16);
            out.extend_from_slice(o);
        }
        let table = out.len() as u64;
        for o in offsets {
            out.extend_from_slice(&o.to_be_bytes());
        }
        out.extend_from_slice(&[0, 0, 0, 0, 0, 0, 2, 1]);
        out.extend_from_slice(&(objects.len() as u64).to_be_bytes());
        out.extend_from_slice(&0u64.to_be_bytes());
        out.extend_from_slice(&table.to_be_bytes());
        out
    }

    #[test]
    fn a_small_value_that_refers_to_one_array_many_times_is_named_too_large_and_its_neighbour_is_read()
     {
        // 8^12 leaves in under 200 bytes: walked as a tree it would never end. The walk stops
        // at its budget, says so for that key, and the key beside it is read. The budget is
        // counted in values, not in time: a walk without it does not end, and how many values
        // it allows is pinned by the 11,111 below.
        let file = shared(8, 12);
        assert!(file.len() < 256, "{}", file.len());
        let read = values(&file, &["LoginHook", "LogoutHook"]).unwrap();
        assert_eq!(read[0], ("LoginHook", Err(TOO_LARGE)));
        assert_eq!(read[1].0, "LogoutHook");
        assert!(read[1].1.is_ok());
        // 11,111 values exceed the node budget even though they fit in the byte budget.
        assert!(matches!(hook_of(&shared(10, 4)), Err(TOO_LARGE)));
        // These UTF-16 code units alone would take over one MiB.
        let long = format!("/{}", "x".repeat(600_000));
        let xml = XML_HOOK.replace("/Library/Scripts/example.sh", &long);
        assert!(matches!(hook_of(xml.as_bytes()), Err(TOO_LARGE)));
        // A real hook fits.
        assert!(hook_of(XML_HOOK.as_bytes()).is_ok());
    }

    fn hook_of(bytes: &[u8]) -> Result<Vec<u8>, &'static str> {
        values(bytes, &["LoginHook"]).unwrap().remove(0).1
    }
}
