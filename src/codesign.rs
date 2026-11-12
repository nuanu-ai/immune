//! Who signed a piece of code on disk and whether its seal still verifies, asked of Apple's
//! Security framework, which every Mac has and Apple maintains. This file only calls it:
//! no signature, certificate or hash is parsed or checked here.
//!
//! The tool `/usr/bin/codesign` does the same work, but tells why a seal is broken only in
//! text meant for people. The framework returns the reason as a status code from
//! `CSCommon.h`, which is a closed set, and it can test a signature against Apple's own
//! requirement language without validating every file again. Every constant below is copied
//! from `CSCommon.h`, `SecStaticCode.h` and `SecCode.h` in the macOS SDK.
//!
//! Ownership of CoreFoundation objects. A function named with `Create` or `Copy`, and an
//! out-parameter the header marks `CF_RETURNS_RETAINED`, hands the caller an object it owns;
//! each one is put into an `Owned` at the call and released exactly once when that is
//! dropped. A function named with `Get` lends an object that belongs to its container: it
//! is never released here and never outlives the container's `Owned`.
//!
//! The header warns that validation "is only secure if the code is not subject to concurrent
//! modification". An application that is updated while it is verified may fail and pass
//! again at the next reading; that is what a verdict here is worth.

use std::ffi::{c_char, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

type CFTypeRef = *const c_void;
type CFIndex = isize;
type OSStatus = i32;
type SecCSFlags = u32;

const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
/// `kCFNumberSInt64Type`.
const K_CF_NUMBER_SINT64_TYPE: CFIndex = 4;

/// `kSecCSSigningInformation`: the certificates and the team.
const SIGNING_INFORMATION: SecCSFlags = 1 << 1;
/// `kSecCSBasicValidateOnly`: the signature itself, not the executable's pages or the
/// resources, so that a requirement is tested without validating every file.
const BASIC_VALIDATE_ONLY: SecCSFlags = (1 << 1) | (1 << 2);
/// `kSecCSCheckAllArchitectures`: a change confined to a slice that runs only under
/// Rosetta is found too.
const CHECK_ALL_ARCHITECTURES: SecCSFlags = 1 << 0;
/// `kSecCSCheckNestedCode`: frameworks and helpers inside the bundle are verified as to
/// their full content; without it a resource changed inside a nested framework passes.
const CHECK_NESTED_CODE: SecCSFlags = 1 << 3;
/// `kSecCSStrictValidate`: what `codesign --verify` does by default.
const STRICT_VALIDATE: SecCSFlags = 1 << 4;
/// `kSecCSNoNetworkAccess`: the program asks the network only for the threat list, so no
/// revocation or notarization check is made.
const NO_NETWORK_ACCESS: SecCSFlags = 1 << 29;
/// The seal: every file, every architecture, nested code included, offline.
pub const SEAL_FLAGS: SecCSFlags =
    CHECK_ALL_ARCHITECTURES | CHECK_NESTED_CODE | STRICT_VALIDATE | NO_NETWORK_ACCESS;
/// `kSecCodeSignatureAdhoc` in `kSecCodeInfoFlags`: signed without a signer.
const SIGNATURE_ADHOC: i64 = 0x0002;

/// Apple's own code.
const APPLE: &str = "anchor apple";
/// Signed for the Mac App Store: Apple's generic anchor and the Mac App Store leaf.
const APP_STORE: &str =
    "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists";
/// Signed with a Developer ID: the Developer ID intermediate and the application leaf.
const DEVELOPER_ID: &str = "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists";

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(cf: CFTypeRef);
    fn CFGetTypeID(cf: CFTypeRef) -> usize;
    fn CFStringGetTypeID() -> usize;
    fn CFNumberGetTypeID() -> usize;
    fn CFDataGetTypeID() -> usize;
    fn CFURLCreateFromFileSystemRepresentation(
        allocator: CFTypeRef,
        buffer: *const u8,
        length: CFIndex,
        is_directory: u8,
    ) -> CFTypeRef;
    fn CFStringCreateWithBytes(
        allocator: CFTypeRef,
        bytes: *const u8,
        length: CFIndex,
        encoding: u32,
        is_external: u8,
    ) -> CFTypeRef;
    fn CFStringGetCString(s: CFTypeRef, buffer: *mut c_char, size: CFIndex, encoding: u32) -> u8;
    fn CFDictionaryGetValue(dict: CFTypeRef, key: CFTypeRef) -> CFTypeRef;
    fn CFNumberGetValue(number: CFTypeRef, kind: CFIndex, value: *mut c_void) -> u8;
    fn CFDataGetLength(data: CFTypeRef) -> CFIndex;
    fn CFDataGetBytePtr(data: CFTypeRef) -> *const u8;
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecCodeInfoIdentifier: CFTypeRef;
    static kSecCodeInfoFlags: CFTypeRef;
    static kSecCodeInfoTeamIdentifier: CFTypeRef;
    static kSecCodeInfoUnique: CFTypeRef;
    fn SecStaticCodeCreateWithPath(
        path: CFTypeRef,
        flags: SecCSFlags,
        code: *mut CFTypeRef,
    ) -> OSStatus;
    fn SecStaticCodeCheckValidityWithErrors(
        code: CFTypeRef,
        flags: SecCSFlags,
        requirement: CFTypeRef,
        errors: *mut CFTypeRef,
    ) -> OSStatus;
    fn SecRequirementCreateWithString(
        text: CFTypeRef,
        flags: SecCSFlags,
        requirement: *mut CFTypeRef,
    ) -> OSStatus;
    fn SecCodeCopySigningInformation(
        code: CFTypeRef,
        flags: SecCSFlags,
        information: *mut CFTypeRef,
    ) -> OSStatus;
}

/// A CoreFoundation object this code owns, released once when dropped.
struct Owned(CFTypeRef);

impl Owned {
    /// Takes ownership of what a `Create` or `Copy` call returned, if it returned anything.
    fn take(object: CFTypeRef) -> Option<Owned> {
        // Lazily: an `Owned` of null, made and dropped, would release null.
        (!object.is_null()).then(|| Owned(object))
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: `self.0` is non-null and owned by this value alone, see `take`.
        unsafe { CFRelease(self.0) };
    }
}

/// A string as a CoreFoundation string this code owns.
fn cf_string(s: &str) -> Option<Owned> {
    // SAFETY: the bytes are valid for their length; the call copies them. Owned: `Create`.
    Owned::take(unsafe {
        CFStringCreateWithBytes(
            std::ptr::null(),
            s.as_ptr(),
            s.len() as CFIndex,
            K_CF_STRING_ENCODING_UTF8,
            0,
        )
    })
}

/// A value of a dictionary, lent by it, when it is of the given type.
fn get(dict: &Owned, key: CFTypeRef, type_id: usize) -> Option<CFTypeRef> {
    // SAFETY: `dict` is a live dictionary and `key` a constant of the framework. The value is
    // lent: it is used only while `dict` lives and is never released.
    let value = unsafe { CFDictionaryGetValue(dict.0, key) };
    (!value.is_null() && unsafe { CFGetTypeID(value) } == type_id).then_some(value)
}

/// What a string lent by a dictionary says, in UTF-8.
fn string(value: CFTypeRef) -> Option<String> {
    let mut buffer = [0 as c_char; 256];
    // SAFETY: `value` is a live string and the buffer is valid for its length; the call
    // writes a NUL-terminated string or fails.
    let ok = unsafe {
        CFStringGetCString(
            value,
            buffer.as_mut_ptr(),
            buffer.len() as CFIndex,
            K_CF_STRING_ENCODING_UTF8,
        )
    };
    if ok == 0 {
        return None;
    }
    // SAFETY: the call succeeded, so the buffer holds a NUL-terminated string.
    let text = unsafe { std::ffi::CStr::from_ptr(buffer.as_ptr()) };
    Some(text.to_string_lossy().into_owned())
}

/// The value of a number lent by a dictionary. Flags are a 32-bit word, which a 64-bit
/// integer holds without loss, so the call's report of a lossy conversion is not needed.
fn number(value: CFTypeRef) -> i64 {
    let mut out: i64 = 0;
    // SAFETY: `value` is a live number and `out` is valid for the 64-bit integer written.
    unsafe {
        CFNumberGetValue(
            value,
            K_CF_NUMBER_SINT64_TYPE,
            (&raw mut out).cast::<c_void>(),
        )
    };
    out
}

/// The bytes of a data object lent by a dictionary, as lowercase hex.
fn hex(value: CFTypeRef) -> String {
    // SAFETY: `value` is a live data object; its bytes are valid for its length while it lives.
    let bytes = unsafe {
        let length = CFDataGetLength(value).max(0) as usize;
        std::slice::from_raw_parts(CFDataGetBytePtr(value), length)
    };
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The status codes of `CSCommon.h` a seal is most often broken with, with the header's own
/// words. Any other is named by its number.
const REASONS: [(OSStatus, &str); 6] = [
    (-67062, "code object is not signed at all"),
    (-67054, "a sealed resource is missing or invalid"),
    (
        -67023,
        "invalid resource directory (directory or signature have been modified)",
    ),
    (
        -67030,
        "invalid Info.plist (plist or signature have been modified)",
    ),
    (-67014, "unsealed contents present in the bundle root"),
    (-67010, "main executable failed strict validation"),
];

/// The literal of a seal that does not verify, from the status the framework returned.
pub fn does_not_verify(status: OSStatus) -> String {
    let why = REASONS
        .iter()
        .find(|(code, _)| *code == status)
        .map_or_else(
            || format!("code signing error {status}"),
            |(_, w)| w.to_string(),
        );
    format!("does not verify: {why}")
}

/// The literal of a seal that verifies.
pub const VERIFIES: &str = "verifies";

/// Code on disk, as the framework sees it.
pub struct Code(Owned);

impl Code {
    /// The code at `path`: a bundle or a single executable. `Err` is the status the
    /// framework returned when it could not make sense of the path at all.
    pub fn at(path: &Path) -> Result<Code, OSStatus> {
        let bytes = path.as_os_str().as_bytes();
        // SAFETY: the bytes are valid for their length; the call copies them. Owned: `Create`.
        let url = Owned::take(unsafe {
            CFURLCreateFromFileSystemRepresentation(
                std::ptr::null(),
                bytes.as_ptr(),
                bytes.len() as CFIndex,
                // Whether it is a folder: the framework looks at the path itself.
                0,
            )
        })
        .ok_or(-67068)?;
        let mut code: CFTypeRef = std::ptr::null();
        // SAFETY: `url` is a live URL and `code` a valid out-parameter. Owned: the header marks
        // it `CF_RETURNS_RETAINED`, and it is set only on success.
        let status = unsafe { SecStaticCodeCreateWithPath(url.0, 0, &mut code) };
        match Owned::take(code) {
            Some(code) if status == 0 => Ok(Code(code)),
            _ => Err(status),
        }
    }

    /// Validates the code with these flags against an optional requirement and returns the
    /// framework's status: 0 when it holds.
    fn check(&self, flags: SecCSFlags, requirement: Option<&Owned>) -> OSStatus {
        let requirement = requirement.map_or(std::ptr::null(), |r| r.0);
        // SAFETY: `self.0` is a live static code and `requirement` a live requirement or null.
        // No error object is asked for, so there is nothing to release.
        unsafe {
            SecStaticCodeCheckValidityWithErrors(self.0.0, flags, requirement, std::ptr::null_mut())
        }
    }

    /// Whether the signature satisfies a requirement written in Apple's language, without
    /// validating the executable or the resources again.
    fn satisfies(&self, text: &str) -> bool {
        let Some(source) = cf_string(text) else {
            return false;
        };
        let mut requirement: CFTypeRef = std::ptr::null();
        // SAFETY: `source` is a live string and `requirement` a valid out-parameter. Owned:
        // the header marks it `CF_RETURNS_RETAINED`; it is set only when the text compiles,
        // so the status adds nothing to it.
        unsafe { SecRequirementCreateWithString(source.0, 0, &mut requirement) };
        let Some(requirement) = Owned::take(requirement) else {
            return false;
        };
        self.check(BASIC_VALIDATE_ONLY | NO_NETWORK_ACCESS, Some(&requirement)) == 0
    }

    /// Who signed the code, as the literal of `signed_by`: `apple`, `app store`, `developer
    /// id`, or `other certificate`, each followed by `, team <id>` where the signature names
    /// a team; `ad hoc, cdhash <hex>`, since an ad hoc signature has no signer and is told
    /// apart only by its code directory; or `unsigned`. `None` when the framework gives no
    /// signing information at all.
    pub fn signer(&self) -> Option<String> {
        let mut info: CFTypeRef = std::ptr::null();
        // SAFETY: `self.0` is a live static code and `info` a valid out-parameter. Owned: the
        // header marks it `CF_RETURNS_RETAINED`.
        let status =
            unsafe { SecCodeCopySigningInformation(self.0.0, SIGNING_INFORMATION, &mut info) };
        let info = Owned::take(info)?;
        if status != 0 {
            return None;
        }
        // SAFETY: the keys are constants of the framework, valid for the life of the process.
        let (identifier, flags, team, unique) = unsafe {
            (
                kSecCodeInfoIdentifier,
                kSecCodeInfoFlags,
                kSecCodeInfoTeamIdentifier,
                kSecCodeInfoUnique,
            )
        };
        // SAFETY: the type ids are plain functions of CoreFoundation.
        let (string_id, number_id, data_id) =
            unsafe { (CFStringGetTypeID(), CFNumberGetTypeID(), CFDataGetTypeID()) };
        // The header: unsigned code gives a dictionary without an identifier.
        if get(&info, identifier, string_id).is_none() {
            return Some("unsigned".to_string());
        }
        let flags = get(&info, flags, number_id).map_or(0, number);
        if flags & SIGNATURE_ADHOC != 0 {
            let cdhash = get(&info, unique, data_id).map(hex).unwrap_or_default();
            return Some(format!("ad hoc, cdhash {cdhash}"));
        }
        let class = if self.satisfies(APPLE) {
            "apple"
        } else if self.satisfies(APP_STORE) {
            "app store"
        } else if self.satisfies(DEVELOPER_ID) {
            "developer id"
        } else {
            "other certificate"
        };
        Some(match get(&info, team, string_id).and_then(string) {
            Some(team) => format!("{class}, team {team}"),
            None => class.to_string(),
        })
    }

    /// Whether the seal verifies: every file, every architecture, nested code included,
    /// with strict validation and no network. This is the expensive call.
    pub fn seal(&self) -> String {
        match self.check(SEAL_FLAGS, None) {
            0 => VERIFIES.to_string(),
            status => does_not_verify(status),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apples_own_tools_are_signed_by_apple_and_their_seal_verifies() {
        // A reference sample every Mac has: the tool that does the same work by hand.
        let code = Code::at(Path::new("/usr/bin/codesign")).unwrap();
        assert_eq!(code.signer().as_deref(), Some("apple"));
        assert_eq!(code.seal(), VERIFIES);
    }

    #[test]
    fn a_path_the_framework_cannot_make_code_of_is_an_error_not_a_verdict() {
        let missing = std::env::temp_dir().join(format!("immune-no-code-{}", std::process::id()));
        assert!(Code::at(&missing).is_err());
    }

    /// A folder of its own under the temporary folder, removed when dropped.
    struct Dir(std::path::PathBuf);

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A tiny application bundle whose executable is a copy of `/usr/bin/true`, signed ad
    /// hoc with the system's tool when `sign` is set.
    fn bundle(tag: &str, sign: bool) -> (Dir, std::path::PathBuf) {
        let dir =
            Dir(std::env::temp_dir().join(format!("immune-codesign-{tag}-{}", std::process::id())));
        let app = dir.0.join("Tiny.app");
        let contents = app.join("Contents");
        std::fs::create_dir_all(contents.join("MacOS")).unwrap();
        std::fs::create_dir_all(contents.join("Resources/app")).unwrap();
        std::fs::write(
            contents.join("Info.plist"),
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>CFBundleIdentifier</key><string>org.example.tiny</string>\n<key>CFBundleExecutable</key><string>Tiny</string>\n<key>CFBundlePackageType</key><string>APPL</string>\n<key>CFBundleShortVersionString</key><string>1.0</string>\n</dict></plist>\n",
        )
        .unwrap();
        let exe = contents.join("MacOS/Tiny");
        std::fs::copy("/usr/bin/true", &exe).unwrap();
        std::fs::write(contents.join("Resources/app/main.js"), "start();\n").unwrap();
        if sign {
            resign(&app);
        } else {
            // The copy carries Apple's signature of the tool; an unsigned bundle has none.
            let out = std::process::Command::new("/usr/bin/codesign")
                .arg("--remove-signature")
                .arg(&exe)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        (dir, app)
    }

    fn resign(app: &Path) {
        let out = std::process::Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-"])
            .arg(app)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn append(path: &Path, bytes: &[u8]) {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        f.write_all(bytes).unwrap();
    }

    fn verdict(app: &Path) -> (String, String) {
        let code = Code::at(app).unwrap();
        (code.signer().unwrap(), code.seal())
    }

    #[test]
    fn an_ad_hoc_bundle_names_its_code_directory_and_its_seal_verifies() {
        let (_dir, app) = bundle("adhoc", true);
        let (signer, seal) = verdict(&app);
        let cdhash = signer.strip_prefix("ad hoc, cdhash ").unwrap();
        assert!(
            cdhash.len() >= 40 && cdhash.chars().all(|c| c.is_ascii_hexdigit()),
            "{signer}"
        );
        assert_eq!(seal, VERIFIES);
    }

    #[test]
    fn each_way_of_tampering_with_a_sealed_bundle_breaks_its_seal_and_says_how() {
        // The cases of the research's experiments on a copy, each on a fresh bundle.
        type Tamper = fn(&Path);
        let cases: [(&str, Tamper, &str); 5] = [
            (
                "append",
                |app| append(&app.join("Contents/Resources/app/main.js"), b"steal();\n"),
                "a sealed resource is missing or invalid",
            ),
            (
                "add",
                |app| std::fs::write(app.join("Contents/Resources/app/extra.js"), "x\n").unwrap(),
                "a sealed resource is missing or invalid",
            ),
            (
                "root",
                |app| std::fs::write(app.join("planted"), "x\n").unwrap(),
                "unsealed contents present in the bundle root",
            ),
            (
                "grown",
                |app| append(&app.join("Contents/MacOS/Tiny"), b"\0"),
                "main executable failed strict validation",
            ),
            (
                "plist",
                |app| {
                    let plist = app.join("Contents/Info.plist");
                    let text = std::fs::read_to_string(&plist).unwrap();
                    std::fs::write(&plist, text.replace("1.0</string>", "1.0 </string>")).unwrap();
                },
                "invalid Info.plist (plist or signature have been modified)",
            ),
        ];
        for (tag, tamper, why) in cases {
            let (_dir, app) = bundle(tag, true);
            let (before, _) = verdict(&app);
            tamper(&app);
            let (after, seal) = verdict(&app);
            assert_eq!(seal, format!("does not verify: {why}"), "{tag}");
            // The signature itself is not touched: the signer is the same.
            assert_eq!(before, after, "{tag}");
        }
    }

    #[test]
    fn a_bundle_signed_again_after_tampering_verifies_under_another_code_directory() {
        let (_dir, app) = bundle("resign", true);
        let (before, _) = verdict(&app);
        append(&app.join("Contents/Resources/app/main.js"), b"steal();\n");
        resign(&app);
        let (after, seal) = verdict(&app);
        assert_eq!(seal, VERIFIES);
        assert_ne!(before, after);
    }

    #[test]
    fn an_unsigned_bundle_says_so_and_a_signature_without_its_seal_says_what_is_missing() {
        let (_dir, app) = bundle("unsigned", false);
        assert_eq!(
            verdict(&app),
            (
                "unsigned".to_string(),
                "does not verify: code object is not signed at all".to_string()
            )
        );
        let (_dir, app) = bundle("noseal", true);
        std::fs::remove_file(app.join("Contents/_CodeSignature/CodeResources")).unwrap();
        assert_eq!(
            verdict(&app).1,
            "does not verify: invalid resource directory (directory or signature have been modified)"
        );
    }

    #[test]
    fn a_resource_changed_inside_nested_code_breaks_the_seal_of_the_bundle_around_it() {
        // The research's case 4: a shallow check of nested code looks at its signature only,
        // so a resource of a framework or helper inside the bundle passes without the flag.
        let (_dir, app) = bundle("nested", true);
        let (_inner_dir, inner) = bundle("nested-inner", true);
        let helpers = app.join("Contents/Library/LoginItems");
        std::fs::create_dir_all(&helpers).unwrap();
        let helper = helpers.join("Tiny.app");
        std::fs::rename(&inner, &helper).unwrap();
        resign(&app);
        assert_eq!(verdict(&app).1, VERIFIES);
        append(
            &helper.join("Contents/Resources/app/main.js"),
            b"steal();\n",
        );
        assert_ne!(verdict(&app).1, VERIFIES);
    }

    #[test]
    fn a_status_without_words_of_its_own_is_named_by_its_number() {
        assert_eq!(
            does_not_verify(-67013),
            "does not verify: code signing error -67013"
        );
    }
}
