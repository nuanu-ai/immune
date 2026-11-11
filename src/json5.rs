//! Whether a file is JSON with comments and trailing commas, asked of the reader macOS ships:
//! Foundation's `NSJSONSerialization` with `NSJSONReadingJSON5Allowed` (macOS 12 and later).
//! JSON5 is a superset of what editors call JSON with comments, so whatever such a file says,
//! this reads; what it cannot read is an error with Foundation's own reason. No comment or
//! comma is stripped here: this file only calls Foundation. What the file says is not taken
//! from the value Foundation returns: of two equal keys it keeps the first and an editor the
//! last, so its value cannot stand in for the editor's.
//!
//! The option and the method are from `NSJSONSerialization.h` in the macOS SDK. Foundation is
//! Objective-C, so the method is called through the runtime's `objc_msgSend`, cast to the
//! method's exact signature, inside an autorelease pool that owns what it returns. The error
//! is toll-free bridged to CFError, whose C functions read it before the pool is popped.

use std::ffi::{c_char, c_void};

type CFTypeRef = *const c_void;
type CFIndex = isize;

/// `NSJSONReadingJSON5Allowed`.
const JSON5_ALLOWED: usize = 1 << 3;
const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
/// `NSDebugDescriptionErrorKey`: where the reader stopped is only said there.
const DEBUG_DESCRIPTION: &str = "NSDebugDescription";

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(cf: CFTypeRef);
    fn CFGetTypeID(cf: CFTypeRef) -> usize;
    fn CFStringGetTypeID() -> usize;
    fn CFDataCreate(allocator: CFTypeRef, bytes: *const u8, length: CFIndex) -> CFTypeRef;
    fn CFStringCreateWithBytes(
        allocator: CFTypeRef,
        bytes: *const u8,
        length: CFIndex,
        encoding: u32,
        is_external: u8,
    ) -> CFTypeRef;
    fn CFStringGetCString(s: CFTypeRef, buffer: *mut c_char, size: CFIndex, encoding: u32) -> u8;
    fn CFErrorCopyUserInfo(error: CFTypeRef) -> CFTypeRef;
    fn CFDictionaryGetValue(dict: CFTypeRef, key: CFTypeRef) -> CFTypeRef;
}

#[link(name = "Foundation", kind = "framework")]
unsafe extern "C" {
    /// Named so that Foundation, and with it the class, is loaded.
    static NSFoundationVersionNumber: f64;
}

#[link(name = "objc")]
unsafe extern "C" {
    fn objc_getClass(name: *const c_char) -> *const c_void;
    fn sel_registerName(name: *const c_char) -> *const c_void;
    fn objc_msgSend();
    fn objc_autoreleasePoolPush() -> *mut c_void;
    fn objc_autoreleasePoolPop(pool: *mut c_void);
}

/// `+[NSJSONSerialization JSONObjectWithData:options:error:]`.
type JsonObjectWithData = unsafe extern "C" fn(
    class: *const c_void,
    selector: *const c_void,
    data: CFTypeRef,
    options: usize,
    error: *mut CFTypeRef,
) -> CFTypeRef;

/// An autorelease pool, popped once when dropped.
struct Pool(*mut c_void);

impl Drop for Pool {
    fn drop(&mut self) {
        // SAFETY: the token came from the push in `reads`, on this thread, popped once.
        unsafe { objc_autoreleasePoolPop(self.0) };
    }
}

/// A CoreFoundation object this code owns: what a `Create` or `Copy` call returned.
struct Owned(CFTypeRef);

impl Owned {
    fn take(object: CFTypeRef) -> Option<Owned> {
        (!object.is_null()).then(|| Owned(object))
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: non-null, see `take`, and released once.
        unsafe { CFRelease(self.0) };
    }
}

/// Whether Foundation reads the bytes as JSON5, and so as JSON with comments, with an object
/// or a list at the top; else its reason, which says where it stopped and quotes nothing.
pub fn reads(bytes: &[u8]) -> Result<(), String> {
    // SAFETY: both names are NUL-terminated literals; the static is only read.
    let (class, selector) = unsafe {
        let _ = std::ptr::read_volatile(&raw const NSFoundationVersionNumber);
        (
            objc_getClass(c"NSJSONSerialization".as_ptr()),
            sel_registerName(c"JSONObjectWithData:options:error:".as_ptr()),
        )
    };
    if class.is_null() {
        return Err("Foundation's JSON reader is not available".to_string());
    }
    // SAFETY: the bytes are valid for their length and copied. Owned: `Create`.
    let data = Owned::take(unsafe {
        CFDataCreate(std::ptr::null(), bytes.as_ptr(), bytes.len() as CFIndex)
    })
    .ok_or("the file could not be handed to Foundation")?;
    // SAFETY: a push is paired with the pop when `_pool` drops, after the error is read.
    let _pool = Pool(unsafe { objc_autoreleasePoolPush() });
    let mut error: CFTypeRef = std::ptr::null();
    // SAFETY: `objc_msgSend` is called with the method's exact signature: a class, a
    // selector, an NSData (CFData is toll-free bridged), an NSUInteger and an NSError**.
    // What it returns, and the error, are autoreleased and live until the pool is popped.
    let object = unsafe {
        let send: JsonObjectWithData = std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
        send(class, selector, data.0, JSON5_ALLOWED, &mut error)
    };
    if object.is_null() {
        return Err(describe(error));
    }
    Ok(())
}

/// Foundation's debug description of the error: what is wrong and at which line and column.
fn describe(error: CFTypeRef) -> String {
    let unknown = || "Foundation could not read it and gave no reason".to_string();
    if error.is_null() {
        return unknown();
    }
    // SAFETY: NSError is toll-free bridged to CFError. Owned: `Copy` and `Create`; the value
    // got from the dictionary is lent by it and read while it is held.
    unsafe {
        let info = Owned::take(CFErrorCopyUserInfo(error));
        let key = Owned::take(CFStringCreateWithBytes(
            std::ptr::null(),
            DEBUG_DESCRIPTION.as_ptr(),
            DEBUG_DESCRIPTION.len() as CFIndex,
            K_CF_STRING_ENCODING_UTF8,
            0,
        ));
        let (Some(info), Some(key)) = (info, key) else {
            return unknown();
        };
        let text = CFDictionaryGetValue(info.0, key.0);
        if text.is_null() || CFGetTypeID(text) != CFStringGetTypeID() {
            return unknown();
        }
        let mut buffer = [0 as c_char; 512];
        if CFStringGetCString(
            text,
            buffer.as_mut_ptr(),
            buffer.len() as CFIndex,
            K_CF_STRING_ENCODING_UTF8,
        ) == 0
        {
            return unknown();
        }
        std::ffi::CStr::from_ptr(buffer.as_ptr())
            .to_string_lossy()
            .into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_trailing_commas_and_text_that_looks_like_a_comment_are_read() {
        let text = "{\n  // a comment\n  \"a\": \"http://x/*y*/\", /* block */\n  \"b\": [1, 2.5, true, null,],\n}";
        assert_eq!(reads(text.as_bytes()), Ok(()));
    }

    #[test]
    fn what_foundation_cannot_read_is_an_error_saying_where() {
        let e = reads(b"{\"a\": 1} garbage").unwrap_err();
        assert!(e.contains("line 1, column 9"), "{e}");
        assert!(reads(b"").is_err());
        assert!(reads(b"\"just text\"").is_err());
    }
}
