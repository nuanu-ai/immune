//! SHA-256, so that a reading records a hash of its raw copy that anyone can check with
//! `shasum -a 256`. It names content; nothing is verified or trusted because of it.
//!
//! The hashing is not ours: it is CommonCrypto, the system's own library, which every Mac
//! has and Apple maintains. This file only calls it. Cryptography is never written here.

use std::ffi::c_void;

unsafe extern "C" {
    /// `CC_SHA256` from CommonCrypto: writes the 32-byte digest of the `len` bytes at `data`
    /// into `md` and returns `md`.
    fn CC_SHA256(data: *const c_void, len: u32, md: *mut u8) -> *mut u8;
}

/// The hash of `data` as 64 lowercase hex digits.
pub fn hex(data: &[u8]) -> String {
    // The system call takes a 32-bit length. Every input here is read under a size cap far
    // below that, so a longer one is a mistake in the caller, not a case to hash wrongly.
    let len = u32::try_from(data.len()).expect("input to hash is under 4 GiB");
    let mut digest = [0u8; 32];
    // SAFETY: `data` is valid for `len` bytes and `digest` for the 32 bytes the call writes.
    unsafe { CC_SHA256(data.as_ptr().cast(), len, digest.as_mut_ptr()) };
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::hex;

    #[test]
    fn the_hash_a_reading_records_is_sha_256_so_anyone_can_check_the_raw_copy() {
        // The published test vectors, including messages that need a second block.
        let cases: [(&[u8], &str); 4] = [
            (
                b"",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                b"abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
            (
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
            ),
        ];
        for (message, digest) in cases {
            assert_eq!(hex(message), digest);
        }
    }
}
