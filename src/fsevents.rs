//! File-system events from FSEvents, the watcher macOS itself ships in CoreServices and
//! maintains: it learns of a change under a path from the kernel and keeps a per-volume
//! history of them. This file only calls it, the way `sha256.rs` calls CommonCrypto; there is
//! no watcher of our own here.
//!
//! Every declaration is copied from the macOS SDK on the build Mac,
//! `MacOSX26.5.sdk/System/Library/Frameworks/CoreServices.framework/Frameworks/
//! FSEvents.framework/Headers/FSEvents.h` (cited as `FSEvents.h:<line>`), from
//! `CoreFoundation.framework/Headers` (`CFBase.h`, `CFArray.h`, `CFString.h`, `CFUUID.h`,
//! `CFDate.h`) and from `usr/include/dispatch` (`queue.h`, `object.h`, `base.h`).
//!
//! What an event says is not trusted: its flags are "simply hints" (`FSEvents.h:365`) and
//! the stream "should NOT be treated as a form of historical log". A batch only says that
//! something under the watched paths changed, with the event ids, so the caller reads the
//! places again. Paths in events are never looked at.
//!
//! The callback's contract. FSEvents calls `callback` on the serial dispatch queue this file
//! creates, one call at a time, never on the caller's thread. The callback reads the flags and
//! ids FSEvents lends it for the length of the call, touches nothing but the `Sink` its stream
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

/// `CFUUIDBytes`, sixteen `UInt8` fields `byte0` to `byte15` (`CFUUID.h:22-38`).
#[repr(C)]
#[derive(Clone, Copy)]
struct CFUUIDBytes([u8; 16]);

// FSEvents types.
/// `FSEventStreamEventId`: `typedef UInt64` (`FSEvents.h:579`).
pub type EventId = u64;
/// `FSEventStreamCreateFlags` and `FSEventStreamEventFlags`: `typedef UInt32`
/// (`FSEvents.h:197`, `FSEvents.h:357`).
type Flags = u32;
/// `dev_t`: `typedef __int32_t __darwin_dev_t;` (`usr/include/sys/_types.h:69`).
pub type Dev = libc::dev_t;
/// `FSEventStreamRef` and `ConstFSEventStreamRef`: pointers to an opaque struct
/// (`FSEvents.h:592`, `FSEvents.h:600`).
type StreamRef = *mut c_void;
/// `dispatch_queue_t`: a pointer to an opaque object (`queue.h`, `DISPATCH_DECL`).
type Queue = *mut c_void;

/// `kFSEventStreamEventIdSinceNow = 0xFFFFFFFFFFFFFFFFULL` (`FSEvents.h:582`).
pub const SINCE_NOW: EventId = u64::MAX;
/// `kFSEventStreamCreateFlagFileEvents = 0x00000010` (`FSEvents.h:275`).
const CREATE_FILE_EVENTS: Flags = 0x10;
/// `kFSEventStreamCreateFlagFullHistory = 0x00000080` (`FSEvents.h:308`).
const CREATE_FULL_HISTORY: Flags = 0x80;
/// `kFSEventStreamEventFlagEventIdsWrapped = 0x00000008` (`FSEvents.h:422`). Every other
/// flag, events dropped (`MustScanSubDirs`, `FSEvents.h:398`) included, needs nothing more
/// than the reading of every watched place that any event brings.
const IDS_WRAPPED: Flags = 0x08;
/// `kFSEventStreamEventFlagHistoryDone = 0x00000010` (`FSEvents.h:435`).
const HISTORY_DONE: Flags = 0x10;

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
    /// `CFUUIDBytes CFUUIDGetUUIDBytes(CFUUIDRef uuid)` (`CFUUID.h:69`).
    fn CFUUIDGetUUIDBytes(uuid: CFRef) -> CFUUIDBytes;
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
    /// `FSEventStreamEventId FSEventsGetCurrentEventId(void)` (`FSEvents.h:973`).
    fn FSEventsGetCurrentEventId() -> EventId;
    /// `CFUUIDRef FSEventsCopyUUIDForDevice(dev_t dev)` (`FSEvents.h:181-182` in the
    /// declaration list, documented at `FSEvents.h:976-990`): `CF_RETURNS_RETAINED`, NULL
    /// when history is not available for the device.
    fn FSEventsCopyUUIDForDevice(dev: Dev) -> CFRef;
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

/// What one callback said: how many events in it say something may have changed, the
/// largest id among them, and whether the history asked for has been delivered in full.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Batch {
    pub events: usize,
    pub latest: EventId,
    pub history_done: bool,
}

/// What a stream hands its batches to. Immutable once the stream exists.
struct Sink {
    /// Events at or before this id are not counted: the full first chunk of history
    /// re-delivers some (measured on macOS 26: the event at exactly the id asked from, and
    /// earlier ones in its chunk).
    since: EventId,
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
    /// from FSEvents' queue. With `since`, FSEvents first replays what happened under the
    /// paths after that event id, then sends a batch with `history_done`; the whole first
    /// chunk of history is asked for (`FullHistory`, `FSEvents.h:297-308`), so an event stored
    /// under an earlier id is not skipped, and the caller decides what is new by the ids.
    /// `latency` is how long FSEvents gathers events into one batch, in seconds. A path
    /// FSEvents cannot take is refused and the rest are watched; `Err` when none can be, or
    /// the stream cannot be created or started.
    pub fn start(
        paths: &[&Path],
        since: Option<EventId>,
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

        let sink = Box::into_raw(Box::new(Sink {
            since: since.unwrap_or(0),
            deliver,
        }));
        let context = Context {
            version: 0,
            info: sink.cast(),
            retain: std::ptr::null(),
            release: std::ptr::null(),
            copy_description: std::ptr::null(),
        };
        let (since_when, flags) = match since {
            Some(id) => (id, CREATE_FILE_EVENTS | CREATE_FULL_HISTORY),
            None => (SINCE_NOW, CREATE_FILE_EVENTS),
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
                since_when,
                latency,
                flags,
            )
        };
        // SAFETY: the array was created above; the stream, if any, keeps what it needs.
        unsafe { CFRelease(array) };
        // SAFETY: a valid label; a NULL attribute makes a serial queue. Owned here and
        // released exactly once: below on failure, else in `Drop`.
        let queue =
            unsafe { dispatch_queue_create(c"soc.watch.fsevents".as_ptr(), std::ptr::null()) };
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
    _paths: *mut c_void,
    flags: *const Flags,
    ids: *const EventId,
) {
    let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if info.is_null() || count == 0 || flags.is_null() || ids.is_null() {
            return;
        }
        // SAFETY: FSEvents passes `count` flags and `count` ids, valid for this call
        // (`FSEvents.h:665-668`); `info` is the `Sink` this stream owns, freed only after the
        // stream is stopped and the queue drained.
        let (flags, ids, sink) = unsafe {
            (
                std::slice::from_raw_parts(flags, count),
                std::slice::from_raw_parts(ids, count),
                &*(info as *const Sink),
            )
        };
        (sink.deliver)(summarise(flags, ids, sink.since));
    }));
    if run.is_err() {
        std::process::abort();
    }
}

/// One batch from the flags and ids of one callback. The sentinel that ends the history says
/// nothing changed and its id is not one to resume from. An event at or before `since` was
/// handled before, except that the ids have wrapped and every id is new.
fn summarise(flags: &[Flags], ids: &[EventId], since: EventId) -> Batch {
    let mut b = Batch::default();
    for (&f, &id) in flags.iter().zip(ids) {
        if f & HISTORY_DONE != 0 {
            b.history_done = true;
            continue;
        }
        if id <= since && f & IDS_WRAPPED == 0 {
            continue;
        }
        b.events += 1;
        b.latest = b.latest.max(id);
    }
    b
}

/// The most recent event id on this Mac, system-wide.
pub fn current_event_id() -> EventId {
    // SAFETY: takes nothing and returns a number.
    unsafe { FSEventsGetCurrentEventId() }
}

/// The identity of the FSEvents history of a volume, as 32 hex digits, or `None` when that
/// volume keeps no history. A different identity means the history was discarded or purged.
pub fn volume_identity(dev: Dev) -> Option<String> {
    // SAFETY: takes a device number; the result is owned here (`CF_RETURNS_RETAINED`) and
    // released once after its bytes are read.
    let uuid = unsafe { FSEventsCopyUUIDForDevice(dev) };
    if uuid.is_null() {
        return None;
    }
    // SAFETY: `uuid` is a valid CFUUID until the release that follows.
    let bytes = unsafe { CFUUIDGetUUIDBytes(uuid) };
    // SAFETY: released once.
    unsafe { CFRelease(uuid) };
    Some(bytes.0.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    fn temp(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("soc-fsevents-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // FSEvents names real paths; the temporary folder is behind a symbolic link.
        std::fs::canonicalize(&dir).unwrap()
    }

    fn start(paths: &[&Path], since: Option<EventId>) -> (Stream, Refused, mpsc::Receiver<Batch>) {
        let (tx, rx) = mpsc::channel();
        let tx = std::sync::Mutex::new(tx);
        let deliver = Box::new(move |b: Batch| {
            let _ = tx.lock().unwrap().send(b);
        });
        let (stream, refused) = Stream::start(paths, since, 0.1, deliver).unwrap();
        (stream, refused, rx)
    }

    /// How long a test waits on fseventsd. It delivers late when the Mac is busy: measured
    /// on a busy build Mac, every event 14 s late for minutes on end, and under heavy writing
    /// over 40 s. A passing test returns as soon as its batch is in, so the bound costs only
    /// a failing run.
    const DEADLINE: Duration = Duration::from_secs(120);

    /// Waits for a batch with an event, skipping the end-of-history sentinel. `write` runs
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

    /// What a stream replays from history, summed up to its end-of-history batch, or `None`
    /// when that batch does not come.
    fn replay(rx: &mpsc::Receiver<Batch>) -> Option<Batch> {
        let start = std::time::Instant::now();
        let mut replayed = Batch::default();
        while start.elapsed() < DEADLINE {
            if let Ok(b) = rx.recv_timeout(Duration::from_secs(1)) {
                replayed.events += b.events;
                replayed.latest = replayed.latest.max(b.latest);
                if b.history_done {
                    replayed.history_done = true;
                    return Some(replayed);
                }
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
        let (stream, refused, rx) = start(&[&folder], None);
        assert!(refused.is_empty());
        let b = event_after(&rx, || {
            std::fs::create_dir_all(&folder).unwrap();
            std::fs::write(folder.join("item.plist"), "x").unwrap();
        })
        .expect("an event for a path created after the stream started");
        assert!(b.latest > 0 && b.latest <= current_event_id());
        drop(stream);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_path_that_is_not_utf8_is_refused_by_index_and_the_others_are_still_watched() {
        use std::os::unix::ffi::OsStrExt;
        let dir = temp("utf8");
        let bad = dir.join(std::ffi::OsStr::from_bytes(b"bad\xff"));
        let good = dir.join("good");
        let (stream, refused, rx) = start(&[&bad, &good], None);
        assert_eq!(refused, vec![(0, NOT_UTF8)]);
        assert!(event_after(&rx, || std::fs::write(&good, "x").unwrap()).is_some());
        drop(stream);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn history_since_an_id_is_replayed_and_then_marked_done() {
        // A change made while no stream ran is in the per-volume history. It need not come
        // before the end-of-history batch: when fseventsd has not yet stored it, it comes
        // after (measured: 4 of 20 times on a busy Mac, 2 to 14 s later). The watcher counts
        // it either way, so the promise is that both come.
        let dir = temp("history");
        let file = dir.join("profile");
        let before = current_event_id();
        std::fs::write(&file, "changed while nobody watched").unwrap();
        let (stream, _, rx) = start(&[&file], Some(before));
        let started = std::time::Instant::now();
        let mut seen = Batch::default();
        while started.elapsed() < DEADLINE && !(seen.history_done && seen.events > 0) {
            if let Ok(b) = rx.recv_timeout(Duration::from_secs(1)) {
                seen.events += b.events;
                seen.latest = seen.latest.max(b.latest);
                seen.history_done |= b.history_done;
            }
        }
        drop(stream);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(seen.history_done, "the end of history is marked");
        assert!(seen.events > 0 && seen.latest > before);
    }

    #[test]
    fn the_end_of_history_is_not_an_event_and_its_id_is_not_kept() {
        let b = summarise(&[0x1000, HISTORY_DONE, 0x01], &[7, 99, 5], 0);
        assert_eq!(
            b,
            Batch {
                events: 2,
                latest: 7,
                history_done: true
            }
        );
    }

    #[test]
    fn events_at_or_before_the_id_asked_from_are_not_counted_unless_the_ids_wrapped() {
        let b = summarise(&[0x1000, 0x1000, IDS_WRAPPED, 0x1000], &[40, 41, 3, 42], 41);
        assert_eq!(
            b,
            Batch {
                events: 2,
                latest: 42,
                history_done: false
            }
        );
    }

    #[test]
    fn a_restart_from_the_last_id_handled_replays_nothing_when_nothing_changed() {
        // FullHistory re-delivers the event at the id asked from; it was handled before.
        let dir = temp("nothing");
        let file = dir.join("profile");
        let (stream, _, rx) = start(&[&file], None);
        // Written once: a second write would be a change after the id handled.
        std::fs::write(&file, "once").unwrap();
        let handled = event_after(&rx, || {}).expect("the live write").latest;
        drop(stream);
        let (stream, _, rx) = start(&[&file], Some(handled));
        let replayed = replay(&rx);
        // Anything still on its way would come right after the end of history.
        let mut events = replayed.as_ref().map_or(0, |b| b.events);
        while let Ok(b) = rx.recv_timeout(Duration::from_millis(500)) {
            events += b.events;
        }
        drop(stream);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(replayed.is_some(), "the end of history is marked");
        assert_eq!(events, 0);
    }

    #[test]
    fn the_volume_of_the_temporary_folder_keeps_a_history_with_a_stable_identity() {
        use std::os::unix::fs::MetadataExt;
        let dev = std::fs::metadata(std::env::temp_dir()).unwrap().dev() as Dev;
        let id = volume_identity(dev).expect("the data volume keeps FSEvents history");
        assert_eq!(id.len(), 32);
        assert_eq!(volume_identity(dev), Some(id));
    }
}
