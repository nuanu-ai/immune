//! Which characters are hidden when printed as they are, and how many columns of a terminal the
//! others take, asked of ICU, the Unicode library
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
/// `UCharCategory` values of the marks drawn on the character before them.
const U_NON_SPACING_MARK: i8 = 6;
const U_ENCLOSING_MARK: i8 = 7;
/// The `UProperty` value of `East_Asian_Width`, and its values `F` and `W` (`UEastAsianWidth`).
const UCHAR_EAST_ASIAN_WIDTH: c_int = 0x1004;
const U_EA_FULLWIDTH: i32 = 3;
const U_EA_WIDE: i32 = 5;

#[link(name = "icucore")]
unsafe extern "C" {
    /// The general category of `c`, as a `UCharCategory`.
    fn u_charType(c: UChar32) -> i8;
    /// Whether `c` has the binary property `which`, a `UProperty`.
    fn u_hasBinaryProperty(c: UChar32, which: c_int) -> UBool;
    /// The value of the enumerated property `which` of `c`.
    fn u_getIntPropertyValue(c: UChar32, which: c_int) -> i32;
}

/// How many columns of a terminal a character that is not hidden takes: none for a mark drawn on
/// the character before it, two for one Unicode's East Asian Width gives as wide or full width,
/// one for every other, the ambiguous ones included, as a terminal outside East Asia draws them.
pub fn columns(c: char) -> usize {
    let c = c as UChar32;
    // SAFETY: both functions take any code point and only read ICU's built-in data.
    if matches!(
        unsafe { u_charType(c) },
        U_NON_SPACING_MARK | U_ENCLOSING_MARK
    ) {
        return 0;
    }
    match unsafe { u_getIntPropertyValue(c, UCHAR_EAST_ASIAN_WIDTH) } {
        U_EA_FULLWIDTH | U_EA_WIDE => 2,
        _ => 1,
    }
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
