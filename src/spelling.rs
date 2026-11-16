//! The key two spellings of a path are compared by: folded in case and put into one Unicode form,
//! as a Mac's volumes compare names by default. It is asked of CoreFoundation, which every Mac
//! has and Apple keeps in step with Unicode; this file only calls it. The key is used only to
//! find what a caller meant and to tell that it is spelled otherwise, never as a name: whether a
//! volume ignores case cannot be told without looking at the disk.
//!
//! Constants are copied from `CFString.h` in the macOS SDK.

use crate::codesign::{Owned, cf_string};
use std::ffi::c_void;

type CFTypeRef = *const c_void;
type CFIndex = isize;

/// `kCFStringNormalizationFormD` and `kCFStringNormalizationFormC`.
const FORM_D: CFIndex = 0;
const FORM_C: CFIndex = 2;
/// `kCFCompareCaseInsensitive`.
const CASE_INSENSITIVE: usize = 1;

#[repr(C)]
struct CFRange {
    location: CFIndex,
    length: CFIndex,
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFStringCreateMutableCopy(
        allocator: CFTypeRef,
        max_length: CFIndex,
        string: CFTypeRef,
    ) -> CFTypeRef;
    fn CFStringNormalize(string: CFTypeRef, form: CFIndex);
    fn CFStringFold(string: CFTypeRef, options: usize, locale: CFTypeRef);
    fn CFStringGetLength(string: CFTypeRef) -> CFIndex;
    fn CFStringGetCharacters(string: CFTypeRef, range: CFRange, buffer: *mut u16);
}

/// `s` folded in case and in Unicode's composed form: decomposed, folded, composed again, as
/// Unicode's canonical caseless match does it. Two spellings of one name on a volume that
/// ignores case and form have one key.
pub fn key(s: &str) -> String {
    let Some(text) = cf_string(s) else {
        return s.to_lowercase();
    };
    // SAFETY: `text` is a live string; the copy is owned (`Create`) and changed only here.
    let Some(copy) = Owned::take(unsafe { CFStringCreateMutableCopy(std::ptr::null(), 0, text.0) })
    else {
        return s.to_lowercase();
    };
    // SAFETY: `copy` is a live mutable string this code owns; a null locale is the default fold.
    let units = unsafe {
        CFStringNormalize(copy.0, FORM_D);
        CFStringFold(copy.0, CASE_INSENSITIVE, std::ptr::null());
        CFStringNormalize(copy.0, FORM_C);
        let length = CFStringGetLength(copy.0);
        let mut units = vec![0u16; length.max(0) as usize];
        CFStringGetCharacters(
            copy.0,
            CFRange {
                location: 0,
                length,
            },
            units.as_mut_ptr(),
        );
        units
    };
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    #[test]
    fn two_spellings_of_one_name_on_a_mac_volume_have_one_key_and_other_names_do_not() {
        // Composed and decomposed é, and two cases, are one name on a volume that ignores case
        // and form; a different letter is not.
        let composed = "Caf\u{e9}/Editor";
        for other in [
            "Cafe\u{301}/Editor",
            "CAF\u{c9}/editor",
            "cafe\u{301}/EDITOR",
        ] {
            assert_eq!(super::key(composed), super::key(other), "{other}");
        }
        assert_ne!(super::key(composed), super::key("Cafe/Editor"));
        assert_eq!(super::key("Caf\u{c9}"), "caf\u{e9}");
    }
}
