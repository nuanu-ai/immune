//! The core's hourly full checks, alongside its watcher. launchd only supervises the process.
//! Each check is the same binary's `run` command: the store remains the only seam.

use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const EVERY: i64 = 60 * 60;
const LIMIT: i64 = 30 * 60;
pub const CHECK_ARG: &str = "--background-check";

pub fn command(binary: &std::path::Path) -> Command {
    let mut command = Command::new(binary);
    command
        .arg(CHECK_ARG)
        .arg(std::process::id().to_string())
        .arg("run");
    command
}

/// Arm the check before it can read anything. The write end of stdin belongs only to the
/// watcher. launchd stops the watcher's group, so this separate group watches the pipe too.
pub fn supervise(parent: &str) -> io::Result<()> {
    // SAFETY: these queries take no pointers and return the calling process's identity.
    let (pid, group, actual_parent) = unsafe { (libc::getpid(), libc::getpgrp(), libc::getppid()) };
    if group != pid || actual_parent == 1 || parent.parse() != Ok(actual_parent) {
        return Err(io::Error::other(
            "the full check has no supervising watcher",
        ));
    }
    // SAFETY: fstat writes only into this initialized structure for the given fd.
    let mut input: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(libc::STDIN_FILENO, &mut input) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if input.st_mode & libc::S_IFMT != libc::S_IFIFO {
        return Err(io::Error::other("the full check has no lifetime pipe"));
    }
    let mut stdin = libc::pollfd {
        fd: libc::STDIN_FILENO,
        events: libc::POLLIN,
        revents: 0,
    };
    if poll(&mut stdin, 0)? {
        return Err(io::Error::other(
            "the full check's watcher has already stopped",
        ));
    }
    std::thread::Builder::new().spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(LIMIT as u64);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match poll(&mut stdin, left.as_millis() as i32) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                _ => break,
            }
        }
        // SAFETY: this process leads the group for this check and its tools.
        unsafe { libc::kill(-pid, libc::SIGKILL) };
    })?;
    Ok(())
}

fn poll(fd: &mut libc::pollfd, timeout_ms: i32) -> io::Result<bool> {
    // SAFETY: a single initialized pollfd is alive for the duration of this call.
    let ready = unsafe { libc::poll(fd, 1, timeout_ms) };
    if ready < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ready != 0)
}

pub struct Checks {
    command: Command,
    running: Option<Running>,
    next: i64,
    last: i64,
}

struct Running {
    child: Child,
    at: i64,
    since: Instant,
}

impl Checks {
    pub fn new(mut command: Command) -> Self {
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        Self {
            command,
            running: None,
            next: 0,
            last: 0,
        }
    }

    /// Called by the watcher, also while it waits for the run lock. Wall time notices a
    /// missed hour after sleep; scheduling from now coalesces all missed hours into one.
    pub fn tick(&mut self, now: i64) -> Option<Result<(), String>> {
        if now < self.last {
            self.next = now;
        }
        self.last = now;
        if let Some(running) = &mut self.running {
            match running.finished() {
                Ok(Some(status)) => {
                    let expired = Self::expired(running, now);
                    self.running = None;
                    if status.code() == Some(crate::EXIT_RUN_IN_PROGRESS.into()) {
                        return None;
                    }
                    return Some(if status.success() {
                        Ok(())
                    } else if expired {
                        Err("the full check exceeded 30 minutes and was stopped".into())
                    } else {
                        Err(format!("the full check ended with {status}"))
                    });
                }
                Err(e) => {
                    self.running = None;
                    return Some(Err(format!("the full check could not be waited for: {e}")));
                }
                Ok(None) => {}
            }
            if Self::expired(running, now) {
                self.running = None;
                return Some(Err(
                    "the full check exceeded 30 minutes and was stopped".into()
                ));
            }
        } else if now >= self.next {
            self.next = now.saturating_add(EVERY);
            match self.command.spawn() {
                Ok(child) => {
                    self.running = Some(Running {
                        child,
                        at: now,
                        since: Instant::now(),
                    });
                }
                Err(e) => return Some(Err(format!("the full check could not start: {e}"))),
            }
        }
        None
    }

    fn expired(running: &Running, now: i64) -> bool {
        now.saturating_sub(running.at) >= LIMIT
            || running.since.elapsed() >= Duration::from_secs(LIMIT as u64)
    }
}

impl Running {
    fn finished(&mut self) -> io::Result<Option<ExitStatus>> {
        // SAFETY: initialized signal info is written by waitid. WNOWAIT keeps the child's
        // pid reserved until Drop so it can still stop any tools after an unexpected exit.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                self.child.id(),
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result == -1 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                return Ok(None);
            }
            return Err(error);
        }
        if unsafe { info.si_pid() } == 0 {
            return Ok(None);
        }
        self.stop_group();
        self.child.wait().map(Some)
    }

    fn stop_group(&self) {
        // SAFETY: this unreaped child heads the private group made by process_group(0).
        unsafe { libc::kill(-(self.child.id() as libc::pid_t), libc::SIGKILL) };
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if self.finished().is_ok_and(|status| status.is_none()) {
            self.stop_group();
            let _ = self.child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(script: &str) -> Command {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", script]);
        cmd
    }

    fn finished(checks: &mut Checks, now: i64) -> Result<(), String> {
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(result) = checks.tick(now) {
                return result;
            }
            assert!(Instant::now() < end, "the invented check did not finish");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn full_checks_start_at_once_then_hourly_and_sleep_creates_one_check_without_a_burst() {
        let mut checks = Checks::new(command("exit 0"));
        assert!(checks.tick(10).is_none());
        assert!(checks.running.is_some());
        finished(&mut checks, 10).unwrap();
        assert!(checks.tick(3609).is_none());
        assert!(checks.running.is_none());
        assert!(checks.tick(3610).is_none());
        assert!(checks.running.is_some());
        finished(&mut checks, 3610).unwrap();
        assert!(checks.tick(20000).is_none());
        assert!(checks.running.is_some());
        finished(&mut checks, 20000).unwrap();
        assert!(checks.tick(20000).is_none());
        assert!(checks.running.is_none());
        assert!(checks.tick(23599).is_none());
        assert!(checks.running.is_none());
        assert!(checks.tick(23600).is_none());
        assert!(checks.running.is_some());
        finished(&mut checks, 23600).unwrap();
    }

    #[test]
    fn a_failed_check_is_reported_and_start_failure_waits_until_the_next_hour() {
        let mut checks = Checks::new(command("exit 7"));
        assert!(finished(&mut checks, 10).unwrap_err().contains('7'));
        assert!(checks.tick(11).is_none());
        assert!(checks.running.is_none());
        let mut checks = Checks::new(Command::new("/no/such/immunity-test-tool"));
        assert!(
            checks
                .tick(10)
                .unwrap()
                .unwrap_err()
                .contains("could not start")
        );
        assert!(checks.tick(3609).is_none());
        assert!(checks.tick(3610).unwrap().is_err());
    }

    #[test]
    fn a_check_skipped_because_another_run_holds_the_store_is_not_a_failure() {
        let mut checks = Checks::new(command("exit 4"));
        checks.tick(10);
        let end = Instant::now() + Duration::from_secs(10);
        while checks.running.is_some() {
            assert!(checks.tick(10).is_none());
            assert!(Instant::now() < end, "the skipped check was not reaped");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(checks.tick(11).is_none());
        assert!(checks.running.is_none());
    }

    #[test]
    fn a_hung_check_is_stopped_after_thirty_minutes_and_reaped_before_the_next_check() {
        let mut checks = Checks::new(command("exec /bin/sleep 60"));
        checks.tick(10);
        let pid = checks.running.as_ref().unwrap().child.id() as libc::pid_t;
        assert!(checks.tick(1809).is_none());
        assert_eq!(checks.running.as_ref().unwrap().child.id() as i32, pid);
        assert!(
            checks
                .tick(1810)
                .unwrap()
                .unwrap_err()
                .contains("30 minutes")
        );
        assert!(checks.running.is_none());
        // SAFETY: signal 0 only asks whether the child still exists.
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert!(checks.tick(3609).is_none());
        assert!(checks.running.is_none());
        assert!(checks.tick(3610).is_none());
        assert!(checks.running.is_some());
    }

    #[test]
    fn stopping_the_background_core_stops_its_full_check_and_the_checks_tools() {
        check_tools_stop(false);
    }

    #[test]
    fn an_unexpected_check_exit_leaves_no_tools_running() {
        check_tools_stop(true);
    }

    fn check_tools_stop(kill_child: bool) {
        let dir = std::env::temp_dir().join(format!(
            "immunity-check-stop-{}-{kill_child}",
            std::process::id()
        ));
        let _removed = crate::common::Scratch::at(dir.clone());
        std::fs::create_dir_all(&dir).unwrap();
        let pid_file = dir.join("child");
        let mut cmd = command("/bin/sleep 60 & echo $! > \"$1\"; wait");
        cmd.arg("check").arg(&pid_file);
        let mut checks = Checks::new(cmd);
        checks.tick(10);
        let pid = checks.running.as_ref().unwrap().child.id() as libc::pid_t;
        let end = Instant::now() + Duration::from_secs(10);
        let tool: libc::pid_t = loop {
            if let Ok(contents) = std::fs::read_to_string(&pid_file)
                && let Ok(pid) = contents.trim().parse()
            {
                break pid;
            }
            assert!(Instant::now() < end, "the invented tool did not start");
            std::thread::sleep(Duration::from_millis(10));
        };
        if kill_child {
            checks.running.as_mut().unwrap().child.kill().unwrap();
            assert!(finished(&mut checks, 10).is_err());
        } else {
            drop(checks);
        }
        // SAFETY: signal 0 only asks whether these invented processes still exist.
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        while unsafe { libc::kill(tool, 0) } == 0 {
            assert!(Instant::now() < end, "the check left its tool running");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn moving_the_clock_back_does_not_put_off_full_checks_until_the_old_time() {
        let mut checks = Checks::new(command("exit 0"));
        finished(&mut checks, 10000).unwrap();
        assert!(checks.tick(10).is_none());
        assert!(checks.running.is_some());
        finished(&mut checks, 10).unwrap();
        assert!(checks.tick(11).is_none());
        assert!(checks.running.is_none());
    }
}
