//! Which characters are hidden when printed as they are, asked of ICU, the Unicode library
//! every Mac has in `/usr/lib/libicucore.dylib` and Apple maintains with each release of
//! Unicode. This file only calls it; no table of characters is kept here.
//!
//! Apple builds ICU without versioned symbol names, so `u_charType` is the name to link.
//! Every constant is copied from `unicode/uchar.h` and `unicode/umachine.h` in the macOS SDK.

use std::ffi::c_int;

/// `UChar32`, a code point.
type UChar32 = i32;
/// `UBool`.
type UBool = i8;

/// `UCharCategory` values.
const U_LINE_SEPARATOR: i8 = 13;
const U_PARAGRAPH_SEPARATOR: i8 = 14;
const U_CONTROL_CHAR: i8 = 15;
const U_FORMAT_CHAR: i8 = 16;
/// The `UProperty` value of `Default_Ignorable_Code_Point`.
const UCHAR_DEFAULT_IGNORABLE_CODE_POINT: c_int = 5;

#[link(name = "icucore")]
unsafe extern "C" {
    /// The general category of `c`, as a `UCharCategory`.
    fn u_charType(c: UChar32) -> i8;
    /// Whether `c` has the binary property `which`, a `UProperty`.
    fn u_hasBinaryProperty(c: UChar32, which: c_int) -> UBool;
}

/// Whether a character, printed as it is, could rearrange or hide what is shown: a control,
/// a format character, a line or paragraph separator, or a default-ignorable code point,
/// which a renderer draws as nothing.
pub fn hidden(c: char) -> bool {
    let c = c as UChar32;
    // SAFETY: both functions take any code point and only read ICU's built-in data.
    let category = unsafe { u_charType(c) };
    matches!(
        category,
        U_CONTROL_CHAR | U_FORMAT_CHAR | U_LINE_SEPARATOR | U_PARAGRAPH_SEPARATOR
    ) || unsafe { u_hasBinaryProperty(c, UCHAR_DEFAULT_IGNORABLE_CODE_POINT) } != 0
}
