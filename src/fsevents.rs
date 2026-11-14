//! File-system events from FSEvents, the watcher macOS itself ships in CoreServices and
//! maintains: it learns of a change under a path from the kernel. This file only calls it, the
//! way `sha256.rs` calls CommonCrypto; there is no watcher of our own here. A stream starts
//! from now: nothing from before it is replayed, and its caller reads everything at start.
//!
//! Every declaration is copied from the macOS SDK on the build Mac,
//! `MacOSX26.5.sdk/System/Library/Frameworks/CoreServices.framework/Frameworks/
//! FSEvents.framework/Headers/FSEvents.h` (cited as `FSEvents.h:<line>`), from
//! `CoreFoundation.framework/Headers` (`CFBase.h`, `CFArray.h`, `CFString.h`, `CFDate.h`)
//! and from `usr/include/dispatch` (`queue.h`, `object.h`, `base.h`).
//!
//! What an event says is not trusted: its flags are "simply hints" (`FSEvents.h:365`) and
//! the stream "should NOT be treated as a form of historical log". A batch only says that
//! something under the watched paths changed, with the paths FSEvents names, so that the
//! caller reads again the places those paths are in. The paths only choose what is
//! read again, and nothing is ever opened by them. A batch whose events FSEvents says were
//! dropped or coalesced, or that names no path for one, says that anything may have changed.
//!
//! The callback's contract. FSEvents calls `callback` on the serial dispatch queue this file
//! creates, one call at a time, never on the caller's thread. The callback reads the flags and
//! paths FSEvents lends it for the length of the call, touches nothing but the `Sink` its stream
//! owns, which is immutable after the stream is created and whose `deliver` is `Send + Sync`,
//! and hands one `Batch` to it. It never unwinds into FSEvents: a panic aborts the process.
//! `Drop` stops and invalidates the stream, then waits for the queue to drain, so no callback
//! is running or will run when the `Sink` is freed.

use std::ffi::{c_char, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

// CoreFoundation types.
/// `CFIndex`: `typedef signed long CFIndex;` (`CFBase.h:565`).
type CFIndex = isize;
/// `Boolean`: `typedef unsigned char Boolean;` (`CFBase.h:124`).
type Boolean = u8;
/// `CFStringEncoding`: `typedef UInt32 CFStringEncoding;` (`CFString.h:100`).
type CFStringEncoding = u32;
/// `CFTimeInterval`: `typedef double CFTimeInterval;` (`CFDate.h:18`).
type CFTimeInterval = f64;
/// Every CF object reference is a pointer: `CFAllocatorRef` (`CFBase.h:635`), `CFStringRef`,
/// `CFArrayRef`, `CFUUIDRef`, `CFTypeRef`.
type CFRef = *const c_void;
/// `kCFStringEncodingUTF8 = 0x08000100` (`CFString.h:113`).
const UTF8: CFStringEncoding = 0x0800_0100;

// FSEvents types.
/// `FSEventStreamEventId`: `typedef UInt64` (`FSEvents.h:579`).
type EventId = u64;
/// `FSEventStreamCreateFlags` and `FSEventStreamEventFlags`: `typedef UInt32`
/// (`FSEvents.h:197`, `FSEvents.h:357`).
type Flags = u32;
/// `FSEventStreamRef` and `ConstFSEventStreamRef`: pointers to an opaque struct
/// (`FSEvents.h:592`, `FSEvents.h:600`).
type StreamRef = *mut c_void;
/// `dispatch_queue_t`: a pointer to an opaque object (`queue.h`, `DISPATCH_DECL`).
type Queue = *mut c_void;

/// `kFSEventStreamEventIdSinceNow = 0xFFFFFFFFFFFFFFFFULL` (`FSEvents.h:582`).
const SINCE_NOW: EventId = u64::MAX;
/// `kFSEventStreamCreateFlagFileEvents = 0x00000010` (`FSEvents.h:275`).
const CREATE_FILE_EVENTS: Flags = 0x10;
/// The flags after which the path of an event does not say where the change is, so every
/// watched place is read again: `MustScanSubDirs = 0x01` (`FSEvents.h:398`), events were
/// coalesced or lost and everything under the path must be read (`UserDropped` and
/// `KernelDropped` come only with it and, as `FSEvents.h:400-411` says, need no check of their
/// own); `RootChanged = 0x20` (`FSEvents.h:448`), which FSEvents sends only to a stream made
/// with `kFSEventStreamCreateFlagWatchRoot` (`FSEvents.h:255`), which `start` does not ask
/// for: a folder on the way to a watched path that is replaced brings no event here;
/// `Mount = 0x40` and `Unmount = 0x80` (`FSEvents.h:463`, `476`), a volume came or went under
/// a watched path. No event id is kept, so `EventIdsWrapped` means nothing here.
const EVERYWHERE: Flags = 0x01 | 0x20 | 0x40 | 0x80;
/// The most paths a batch, or the changes gathered for one reading, names one by one; past it
/// every watched place is read again, which costs what any reading cost before.
pub const MOST_PATHS: usize = 4096;

/// `struct FSEventStreamContext` (`FSEvents.h:609-644`), declared under
/// `#pragma pack(push, 2)` (`FSEvents.h:44`). Its five fields are each eight bytes, so the
/// packing changes no offset (0, 8, 16, 24, 32) and only lowers the alignment to two; the
/// same packing is declared here so the layout is the header's exactly.
#[repr(C, packed(2))]
struct Context {
    /// `CFIndex version`: "Currently the only valid value is zero."
    version: CFIndex,
    /// `void *info`, passed back to the callback.
    info: *mut c_void,
    /// `CFAllocatorRetainCallBack retain` (`CFBase.h:675`); NULL here: FSEvents keeps the
    /// pointer without retaining it, and this file owns what it points at.
    retain: *const c_void,
    /// `CFAllocatorReleaseCallBack release` (`CFBase.h:676`); NULL for the same reason.
    release: *const c_void,
    /// `CFAllocatorCopyDescriptionCallBack copyDescription` (`CFBase.h:677`); NULL.
    copy_description: *const c_void,
}
const _: () = assert!(std::mem::size_of::<Context>() == 40);

/// `FSEventStreamCallback` (`FSEvents.h:717`): `void (*)(ConstFSEventStreamRef streamRef,
/// void *clientCallBackInfo, size_t numEvents, void *eventPaths,
/// const FSEventStreamEventFlags *eventFlags, const FSEventStreamEventId *eventIds)`.
type Callback =
    extern "C" fn(StreamRef, *mut c_void, usize, *mut c_void, *const Flags, *const EventId);

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    /// `void CFRelease(CFTypeRef cf)` (`CFBase.h:781`).
    fn CFRelease(cf: CFRef);
    /// `CFStringRef CFStringCreateWithBytes(CFAllocatorRef alloc, const UInt8 *bytes,
    /// CFIndex numBytes, CFStringEncoding encoding, Boolean isExternalRepresentation)`
    /// (`CFString.h:186`). Create rule: the caller owns the result, NULL on failure.
    fn CFStringCreateWithBytes(
        alloc: CFRef,
        bytes: *const u8,
        num_bytes: CFIndex,
        encoding: CFStringEncoding,
        is_external_representation: Boolean,
    ) -> CFRef;
    /// `CFArrayRef CFArrayCreate(CFAllocatorRef allocator, const void **values,
    /// CFIndex numValues, const CFArrayCallBacks *callBacks)` (`CFArray.h:174`). With
    /// `kCFTypeArrayCallBacks` the array retains each value. Create rule.
    fn CFArrayCreate(
        allocator: CFRef,
        values: *const CFRef,
        num_values: CFIndex,
        call_backs: *const c_void,
    ) -> CFRef;
    /// `const CFArrayCallBacks kCFTypeArrayCallBacks` (`CFArray.h:92`).
    static kCFTypeArrayCallBacks: c_void;
}

#[link(name = "CoreServices", kind = "framework")]
unsafe extern "C" {
    /// `FSEventStreamRef FSEventStreamCreate(CFAllocatorRef allocator,
    /// FSEventStreamCallback callback, FSEventStreamContext *context,
    /// CFArrayRef pathsToWatch, FSEventStreamEventId sinceWhen, CFTimeInterval latency,
    /// FSEventStreamCreateFlags flags)` (`FSEvents.h:783-790`). NULL "if there was a problem
    /// creating the object". The context's fields are copied out (`FSEvents.h:741-745`).
    fn FSEventStreamCreate(
        allocator: CFRef,
        callback: Callback,
        context: *const Context,
        paths_to_watch: CFRef,
        since_when: EventId,
        latency: CFTimeInterval,
        flags: Flags,
    ) -> StreamRef;
    /// `void FSEventStreamSetDispatchQueue(FSEventStreamRef, dispatch_queue_t q)`
    /// (`FSEvents.h:1230-1232`). The run-loop form is deprecated since macOS 13
    /// (`FSEvents.h:1162`) and not used.
    fn FSEventStreamSetDispatchQueue(stream: StreamRef, q: Queue);
    /// `Boolean FSEventStreamStart(FSEventStreamRef)` (`FSEvents.h:1290`).
    fn FSEventStreamStart(stream: StreamRef) -> Boolean;
    /// `void FSEventStreamStop(FSEventStreamRef)` (`FSEvents.h:1372`): "ensuring the
    /// client's callback will not be called again for this stream" (`FSEvents.h:107-108`).
    fn FSEventStreamStop(stream: StreamRef);
    /// `void FSEventStreamInvalidate(FSEventStreamRef)` (`FSEvents.h:1257`): unschedules it
    /// from its queue. Only on a stream that was given a queue (`FSEvents.h:1209-1213`).
    fn FSEventStreamInvalidate(stream: StreamRef);
    /// `void FSEventStreamRelease(FSEventStreamRef)` (`FSEvents.h:1123`): the refcount
    /// starts at one, so one release after create frees it.
    fn FSEventStreamRelease(stream: StreamRef);
}

unsafe extern "C" {
    /// `dispatch_queue_t dispatch_queue_create(const char *label,
    /// dispatch_queue_attr_t attr)` (`queue.h:1091-1092`), `DISPATCH_RETURNS_RETAINED`.
    /// A NULL attribute is `DISPATCH_QUEUE_SERIAL` (`queue.h:721`).
    fn dispatch_queue_create(label: *const c_char, attr: *const c_void) -> Queue;
    /// `void dispatch_sync_f(dispatch_queue_t queue, void *context,
    /// dispatch_function_t work)` (`queue.h:343-344`); `work` must not be NULL.
    fn dispatch_sync_f(queue: Queue, context: *mut c_void, work: extern "C" fn(*mut c_void));
    /// `void dispatch_release(dispatch_object_t object)` (`object.h:300`); a
    /// `dispatch_object_t` is passed as the object's pointer.
    fn dispatch_release(object: Queue);
}

/// What one callback said: how many events in it say something may have changed, and where
/// the changes are.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Batch {
    pub events: usize,
    pub at: Where,
}

/// Where changes are: at these paths, as FSEvents names them, or anywhere under the watched
/// paths. No path at all names no place, and is read as anywhere (`watch::to_read`).
#[derive(Clone, Debug, PartialEq)]
pub enum Where {
    Paths(std::collections::BTreeSet<std::path::PathBuf>),
    Anywhere,
}

impl Default for Where {
    fn default() -> Where {
        Where::Paths(std::collections::BTreeSet::new())
    }
}

impl Where {
    /// Both: anywhere when either is, or more paths than `MOST_PATHS` together.
    pub fn and(self, other: Where) -> Where {
        match (self, other) {
            (Where::Paths(mut a), Where::Paths(b)) => {
                a.extend(b);
                if a.len() > MOST_PATHS {
                    Where::Anywhere
                } else {
                    Where::Paths(a)
                }
            }
            _ => Where::Anywhere,
        }
    }
}

/// What a stream hands its batches to. Immutable once the stream exists.
struct Sink {
    deliver: Box<dyn Fn(Batch) + Send + Sync>,
}

/// A running stream on a set of paths. Dropping it stops it, and no callback runs after.
pub struct Stream {
    stream: StreamRef,
    queue: Queue,
    sink: *mut Sink,
}

/// Which paths a stream could not be given, by their index, and why.
pub type Refused = Vec<(usize, &'static str)>;

/// Why a path cannot be handed to FSEvents.
const NOT_UTF8: &str = "the path is not UTF-8, which FSEvents takes paths in";

impl Stream {
    /// Starts a stream on `paths`, which need not exist yet, delivering batches to `deliver`
    /// from FSEvents' queue, of the changes made from now (`SinceNow`). When it returns, the
    /// stream is registered with FSEvents to receive events (`FSEventStreamStart`,
    /// `FSEvents.h:1266-1268`), so a change made after it brings an event. `latency` is how long FSEvents gathers events
    /// into one batch, in seconds. A path FSEvents cannot take is refused and the rest are
    /// watched; `Err` when none can be, or the stream cannot be created or started.
    pub fn start(
        paths: &[&Path],
        latency: f64,
        deliver: Box<dyn Fn(Batch) + Send + Sync>,
    ) -> Result<(Stream, Refused), String> {
        let mut refused = Refused::new();
        let mut strings: Vec<CFRef> = Vec::new();
        for (i, path) in paths.iter().enumerate() {
            let bytes = path.as_os_str().as_bytes();
            // SAFETY: `bytes` is valid for its length; the result is owned here (Create
            // rule) and released below, once the array holds its own reference.
            let s = unsafe {
                CFStringCreateWithBytes(
                    std::ptr::null(),
                    bytes.as_ptr(),
                    bytes.len() as CFIndex,
                    UTF8,
                    0,
                )
            };
            if s.is_null() {
                refused.push((i, NOT_UTF8));
            } else {
                strings.push(s);
            }
        }
        if strings.is_empty() {
            return Err("no path could be handed to FSEvents".to_string());
        }
        // SAFETY: `strings` holds valid CFStrings; with the CF type callbacks the array
        // retains each, so this file's own reference to each is released right after.
        let array = unsafe {
            CFArrayCreate(
                std::ptr::null(),
                strings.as_ptr(),
                strings.len() as CFIndex,
                &raw const kCFTypeArrayCallBacks,
            )
        };
        for s in &strings {
            // SAFETY: each string was created above and is released once, here.
            unsafe { CFRelease(*s) };
        }
        if array.is_null() {
            return Err("CoreFoundation could not make the list of paths".to_string());
        }

        let sink = Box::into_raw(Box::new(Sink { deliver }));
        let context = Context {
            version: 0,
            info: sink.cast(),
            retain: std::ptr::null(),
            release: std::ptr::null(),
            copy_description: std::ptr::null(),
        };
        // SAFETY: `context` is read during the call only (its fields are copied out);
        // `array` is valid. The stream is owned here and released exactly once: below on
        // failure, else in `Drop`.
        let stream = unsafe {
            FSEventStreamCreate(
                std::ptr::null(),
                callback,
                &context,
                array,
                SINCE_NOW,
                latency,
                CREATE_FILE_EVENTS,
            )
        };
        // SAFETY: the array was created above; the stream, if any, keeps what it needs.
        unsafe { CFRelease(array) };
        // SAFETY: a valid label; a NULL attribute makes a serial queue. Owned here and
        // released exactly once: below on failure, else in `Drop`.
        let queue = unsafe {
            dispatch_queue_create(c"ai.nuanu.immune.watch.fsevents".as_ptr(), std::ptr::null())
        };
        if stream.is_null() || queue.is_null() {
            // SAFETY: each was created above, is released once, and no callback can run:
            // the stream, if there is one, was never started.
            unsafe {
                if !stream.is_null() {
                    FSEventStreamRelease(stream);
                }
                if !queue.is_null() {
                    dispatch_release(queue);
                }
                drop(Box::from_raw(sink));
            }
            return Err("FSEvents could not create a stream".to_string());
        }
        // SAFETY: both are valid; the stream keeps the queue for as long as it needs it.
        unsafe { FSEventStreamSetDispatchQueue(stream, queue) };
        // SAFETY: the stream is scheduled on a queue, as start requires.
        if unsafe { FSEventStreamStart(stream) } == 0 {
            // SAFETY: never started, so no callback ran; invalidate is allowed because the
            // stream has a queue; each object is released once.
            unsafe {
                FSEventStreamInvalidate(stream);
                FSEventStreamRelease(stream);
                dispatch_release(queue);
                drop(Box::from_raw(sink));
            }
            return Err("FSEvents could not start the stream".to_string());
        }
        Ok((
            Stream {
                stream,
                queue,
                sink,
            },
            refused,
        ))
    }
}

/// Runs nothing; queued after the stream is invalidated, it returns once every callback
/// queued before it has returned.
extern "C" fn drained(_: *mut c_void) {}

impl Drop for Stream {
    fn drop(&mut self) {
        // SAFETY: the stream was started (only a started stream is kept), so stop is allowed,
        // and it has a queue, so invalidate is. After stop no new callback is called; the
        // queue is serial, so once `drained` has run no callback is running either. Only then
        // are the stream, the queue and the sink freed, each once.
        unsafe {
            FSEventStreamStop(self.stream);
            FSEventStreamInvalidate(self.stream);
            dispatch_sync_f(self.queue, std::ptr::null_mut(), drained);
            FSEventStreamRelease(self.stream);
            dispatch_release(self.queue);
            drop(Box::from_raw(self.sink));
        }
    }
}

/// Called by FSEvents on the stream's queue. See the contract at the top of this file.
extern "C" fn callback(
    _stream: StreamRef,
    info: *mut c_void,
    count: usize,
    paths: *mut c_void,
    flags: *const Flags,
    _ids: *const EventId,
) {
    let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if info.is_null() || count == 0 || flags.is_null() {
            return;
        }
        // SAFETY: FSEvents passes `count` flags, valid for this call
        // (`FSEvents.h:665-668`); `info` is the `Sink` this stream owns, freed only after the
        // stream is stopped and the queue drained.
        let (flags, sink) = unsafe {
            (
                std::slice::from_raw_parts(flags, count),
                &*(info as *const Sink),
            )
        };
        // Without `UseCFTypes` the paths are "a raw C array of raw C strings", one per event,
        // freed by FSEvents after the callback returns (`FSEvents.h:674-677`): each is copied
        // out here. A missing one names no path.
        let named: Vec<Option<std::path::PathBuf>> = if paths.is_null() {
            vec![None; count]
        } else {
            // SAFETY: `count` pointers, valid for this call, as above.
            let each = unsafe { std::slice::from_raw_parts(paths as *const *const c_char, count) };
            each.iter()
                .map(|&p| {
                    // SAFETY: a non-null pointer FSEvents gives is a NUL-terminated string
                    // valid for this call.
                    (!p.is_null()).then(|| {
                        let bytes = unsafe { std::ffi::CStr::from_ptr(p) }.to_bytes();
                        std::path::PathBuf::from(std::ffi::OsStr::from_bytes(bytes))
                    })
                })
                .collect()
        };
        (sink.deliver)(summarise(flags, &named));
    }));
    if run.is_err() {
        std::process::abort();
    }
}

/// One batch from the flags and paths of one callback. An event whose flags say the path does
/// not place the change (`EVERYWHERE`), or that names no path, makes the batch say anywhere.
fn summarise(flags: &[Flags], paths: &[Option<std::path::PathBuf>]) -> Batch {
    let mut b = Batch::default();
    for (&f, path) in flags.iter().zip(paths) {
        b.events += 1;
        let here = match path {
            Some(path) if f & EVERYWHERE == 0 => Where::Paths([path.clone()].into()),
            _ => Where::Anywhere,
        };
        b.at = std::mem::take(&mut b.at).and(here);
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    fn temp(tag: &str) -> crate::common::Scratch {
        let dir =
            std::env::temp_dir().join(format!("immune-fsevents-{tag}-{}", std::process::id()));
        crate::common::remove(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // FSEvents names real paths; the temporary folder is behind a symbolic link.
        crate::common::Scratch(std::fs::canonicalize(&dir).unwrap())
    }

    fn start(paths: &[&Path]) -> (Stream, Refused, mpsc::Receiver<Batch>) {
        let (tx, rx) = mpsc::channel();
        let tx = std::sync::Mutex::new(tx);
        let deliver = Box::new(move |b: Batch| {
            let _ = tx.lock().unwrap().send(b);
        });
        let (stream, refused) = Stream::start(paths, 0.1, deliver).unwrap();
        (stream, refused, rx)
    }

    /// How long a test waits on fseventsd. It delivers late when the Mac is busy: measured
    /// on a busy build Mac, every event 14 s late for minutes on end, and under heavy writing
    /// over 40 s. A passing test returns as soon as its batch is in, so the bound costs only
    /// a failing run.
    const DEADLINE: Duration = Duration::from_secs(120);

    /// Waits for a batch with an event. `write` runs
    /// first and again after every second without one: under load a single write can arrive
    /// later than any short wait, and a repeated one says the same thing.
    fn event_after(rx: &mpsc::Receiver<Batch>, write: impl Fn()) -> Option<Batch> {
        let start = std::time::Instant::now();
        while start.elapsed() < DEADLINE {
            write();
            match rx.recv_timeout(Duration::from_secs(1)) {
                Ok(b) if b.events > 0 => return Some(b),
                Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return None,
            }
        }
        None
    }

    #[test]
    fn a_write_under_a_watched_path_that_did_not_exist_at_start_is_delivered_as_a_batch() {
        // The watcher subscribes to places before they exist: the first autostart item ever
        // made must still be seen.
        let dir = temp("later");
        let folder = dir.join("Library/LaunchAgents");
        let (stream, refused, rx) = start(&[&folder]);
        assert!(refused.is_empty());
        let b = event_after(&rx, || {
            std::fs::create_dir_all(&folder).unwrap();
            std::fs::write(folder.join("item.plist"), "x").unwrap();
        });
        assert!(
            b.is_some(),
            "an event for a path created after the stream started"
        );
        drop(stream);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_path_that_is_not_utf8_is_refused_by_index_and_the_others_are_still_watched() {
        use std::os::unix::ffi::OsStrExt;
        let dir = temp("utf8");
        let bad = dir.join(std::ffi::OsStr::from_bytes(b"bad\xff"));
        let good = dir.join("good");
        let (stream, refused, rx) = start(&[&bad, &good]);
        assert_eq!(refused, vec![(0, NOT_UTF8)]);
        assert!(event_after(&rx, || std::fs::write(&good, "x").unwrap()).is_some());
        drop(stream);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn named(paths: &[&str]) -> Vec<Option<std::path::PathBuf>> {
        paths.iter().map(|p| Some(p.into())).collect()
    }

    fn at(paths: &[&str]) -> Where {
        Where::Paths(paths.iter().map(std::path::PathBuf::from).collect())
    }

    #[test]
    fn an_event_whose_flags_say_events_were_dropped_or_coalesced_says_the_change_may_be_anywhere() {
        // FSEvents says where it lost events only roughly ("/" when dropped): what it names
        // cannot choose what is read again, or a change it lost would never be read.
        let flags = [0x01, 0x01 | 0x02, 0x01 | 0x04, 0x20, 0x40, 0x80];
        for flag in flags {
            let b = summarise(&[0x1000, flag], &named(&["/w/a", "/w"]));
            assert_eq!(b.at, Where::Anywhere, "{flag:#x}");
        }
        // Plain file events name where the change is.
        let plain = [0x100, 0x200, 0x800, 0x1000, 0x10000, 0x20000];
        for flag in plain {
            let b = summarise(&[flag], &named(&["/w/a"]));
            assert_eq!(b.at, at(&["/w/a"]), "{flag:#x}");
        }
    }

    #[test]
    fn an_event_that_names_no_path_says_the_change_may_be_anywhere() {
        let b = summarise(&[0x1000, 0x1000], &[Some("/w/a".into()), None]);
        assert_eq!(b.at, Where::Anywhere);
    }

    #[test]
    fn more_paths_than_the_most_named_one_by_one_say_anywhere_and_anywhere_stays() {
        let many: Where = Where::Paths((0..MOST_PATHS).map(|i| format!("/w/{i}").into()).collect());
        assert_eq!(many.clone().and(at(&["/w/0"])), many);
        assert_eq!(many.clone().and(at(&["/w/more"])), Where::Anywhere);
        assert_eq!(Where::Anywhere.and(at(&["/w/a"])), Where::Anywhere);
        assert_eq!(at(&["/w/a"]).and(Where::Anywhere), Where::Anywhere);
        assert_eq!(at(&["/w/a"]).and(at(&["/w/b"])), at(&["/w/a", "/w/b"]));
    }

    #[test]
    fn a_batch_names_the_path_of_the_file_written() {
        // The watcher reads again only the places a change is in, so the path must be the
        // one FSEvents gave, copied whole before FSEvents frees it.
        let dir = temp("named");
        let folder = dir.join("Library/LaunchAgents");
        std::fs::create_dir_all(&folder).unwrap();
        let file = folder.join("com.example.agent.plist");
        let (stream, _, rx) = start(&[&folder]);
        // A batch that says anywhere, as FSEvents may under load, places nothing and is
        // passed over.
        let start = std::time::Instant::now();
        let mut named = false;
        while start.elapsed() < DEADLINE && !named {
            std::fs::write(&file, "x").unwrap();
            if let Ok(b) = rx.recv_timeout(Duration::from_secs(1)) {
                named = matches!(&b.at, Where::Paths(p) if p.contains(&file));
            }
        }
        drop(stream);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(named);
    }
}
