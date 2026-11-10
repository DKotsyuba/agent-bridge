//! Wall-clock discontinuity tracking for freshness checks of data files.
//!
//! A data file (a session descriptor) is fresh when it was written after the
//! process it describes started. Its time is on `CLOCK_REALTIME`; the process
//! start is a `CLOCK_BOOTTIME` tick. Putting the start on the wall clock needs
//! the offset `REALTIME - BOOTTIME`, and that offset is only the offset *at the
//! start* while the wall clock has not been stepped since: a forward step after
//! the start makes a sample taken later place the start too late (or too early
//! after a backward step), so a stale file can pass. The offset cannot be
//! recovered afterwards, so this module only trusts it when no discontinuity can
//! have occurred.
//!
//! One process-wide `Tracker` samples the offset whenever Bridge looks at the
//! clocks (at registry construction, every executable refresh pass and every
//! check). A change between two consecutive samples beyond slew, rounding and
//! scheduling slack is a discontinuity and is remembered by the boot time of the
//! sample that saw it. A check passes only for a process that
//!
//! * started after the first sample (Bridge start), so every moment since its
//!   start was covered by continuous sampling, and
//! * started after the last observed discontinuity,
//!
//! and only when the file time lies between the start placed on the wall clock
//! (rounded up by every uncertainty) and the current wall time. Any other case
//! refuses ("not fresh"; the caller keeps the route unobserved and the next
//! genuine hook or event re-observes it). A step that is undone again between two
//! samples is not visible; Bridge samples about once a second.

#[cfg(not(test))]
use std::sync::Mutex;

use super::ProcessFacts;

/// Resolution of `/proc/uptime`, which truncates to hundredths of a second.
const QUANTUM_NS: i128 = 10_000_000;
/// Kernel clock ticks per second of `/proc/<pid>/stat` times (`USER_HZ`, fixed
/// by the Linux userspace ABI) in nanoseconds.
const TICK_NS: i128 = 10_000_000;
/// Allowance for scheduling between the clock reads of one sample.
const STEP_SLACK_NS: i128 = 50_000_000;
/// Slew budget: the wall clock may be slewed by 500 ppm (1 / 2000).
const SLEW_DIVISOR: i128 = 2_000;
/// Widest accepted spread between the two wall reads bracketing the uptime read.
const MAX_SPREAD_NS: i128 = 5_000_000;

/// One reading of the two clocks (nanoseconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Sample {
    /// Boot time as `/proc/uptime` reports it; the true value is in
    /// `[boot, boot + QUANTUM_NS)`.
    pub boot: i128,
    /// Wall clock read before the uptime.
    pub real_before: i128,
    /// Wall clock read after the uptime.
    pub real_after: i128,
}

impl Sample {
    /// Lowest `REALTIME - BOOTTIME` consistent with the reads.
    fn offset_low(&self) -> i128 {
        self.real_before - self.boot - QUANTUM_NS
    }

    /// Highest `REALTIME - BOOTTIME` consistent with the reads.
    fn offset_high(&self) -> i128 {
        self.real_after - self.boot
    }

    /// Highest boot time consistent with the reads.
    fn boot_high(&self) -> i128 {
        self.boot + QUANTUM_NS
    }
}

/// The clock history of one Bridge process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tracker {
    /// Highest boot time of the first sample: later starts are covered.
    first_boot_high: i128,
    last: Sample,
    /// Highest boot time of the sample that last saw a discontinuity.
    break_boot: Option<i128>,
}

impl Tracker {
    /// A tracker whose Bridge start is `first`.
    pub(crate) fn new(first: Sample) -> Self {
        Self {
            first_boot_high: first.boot_high(),
            last: first,
            break_boot: None,
        }
    }

    /// Records `sample`, remembering a discontinuity when the offset left the
    /// interval its predecessor, widened by rounding, scheduling and slew, allows.
    pub(crate) fn observe(&mut self, sample: Sample) {
        let last = self.last;
        let elapsed = sample.boot - last.boot;
        let budget = STEP_SLACK_NS + elapsed.max(0) / SLEW_DIVISOR;
        if elapsed < 0
            || sample.offset_low() > last.offset_high() + budget
            || sample.offset_high() < last.offset_low() - budget
        {
            self.break_boot = Some(sample.boot_high());
        }
        self.last = sample;
    }

    /// Whether the descriptor written at `written_at` (Unix seconds and
    /// nanoseconds) is positively no older than the process with kernel start
    /// tick `start_ticks`, judged at `now`. Observes `now` first.
    pub(crate) fn fresh(&mut self, now: Sample, start_ticks: u64, written_at: (i64, i64)) -> bool {
        self.observe(now);
        let start = i128::from(start_ticks) * TICK_NS;
        if start <= self.first_boot_high
            || self.break_boot.is_some_and(|broke| start <= broke)
            || start > now.boot_high()
        {
            return false;
        }
        let written = i128::from(written_at.0) * 1_000_000_000 + i128::from(written_at.1);
        let drift = (now.boot - start).max(0) / SLEW_DIVISOR;
        let earliest = start + now.offset_high() + drift;
        let latest = now.real_after + STEP_SLACK_NS;
        written >= earliest && written <= latest
    }
}

#[cfg(not(test))]
static TRACKER: Mutex<Option<Tracker>> = Mutex::new(None);

#[cfg(test)]
thread_local! {
    static TRACKER: std::cell::RefCell<Option<Tracker>> = const { std::cell::RefCell::new(None) };
    static STEP: std::cell::Cell<i128> = const { std::cell::Cell::new(0) };
}

/// Runs `action` on the process-wide tracker; `None` when its lock is poisoned.
#[cfg(not(test))]
fn with_tracker<R>(action: impl FnOnce(&mut Option<Tracker>) -> R) -> Option<R> {
    TRACKER.lock().ok().map(|mut guard| action(&mut guard))
}

/// Test build: one tracker and one injected wall-clock step per test thread.
#[cfg(test)]
fn with_tracker<R>(action: impl FnOnce(&mut Option<Tracker>) -> R) -> Option<R> {
    TRACKER.with(|cell| Some(action(&mut cell.borrow_mut())))
}

/// Test-only: steps this thread's wall clock by `nanos` (positive is forward).
#[cfg(test)]
pub(crate) fn inject_step(nanos: i128) {
    STEP.with(|step| step.set(step.get() + nanos));
}

/// Test-only: forgets this thread's tracker so the next sample starts Bridge.
#[cfg(test)]
pub(crate) fn reset() {
    TRACKER.with(|cell| *cell.borrow_mut() = None);
    STEP.with(|step| step.set(0));
}

fn wall_ns() -> Option<i128> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_nanos();
    #[cfg(test)]
    let now = i128::try_from(now).ok()? + STEP.with(std::cell::Cell::get);
    #[cfg(not(test))]
    let now = i128::try_from(now).ok()?;
    Some(now)
}

/// Boot time in nanoseconds from `/proc/uptime`.
fn uptime_ns() -> Option<i128> {
    let uptime = std::fs::read_to_string("/proc/uptime").ok()?;
    let (seconds, hundredths) = uptime.split_ascii_whitespace().next()?.split_once('.')?;
    if hundredths.len() != 2 {
        return None;
    }
    let boot = i128::from(seconds.parse::<u64>().ok()?) * 1_000_000_000
        + i128::from(hundredths.parse::<u32>().ok()?) * QUANTUM_NS;
    Some(boot)
}

/// Reads both clocks, retrying while the two wall reads are far apart (the
/// thread was descheduled mid-sample); `None` when no tight sample is obtained.
fn read_sample() -> Option<Sample> {
    (0..3).find_map(|_| {
        let real_before = wall_ns()?;
        let boot = uptime_ns()?;
        let real_after = wall_ns()?;
        (real_after - real_before <= MAX_SPREAD_NS).then_some(Sample {
            boot,
            real_before,
            real_after,
        })
    })
}

/// Samples the clocks into the process-wide tracker; the first call is Bridge
/// start. Cheap (one small `/proc` read).
pub(crate) fn observe() {
    let Some(sample) = read_sample() else {
        return;
    };
    with_tracker(|tracker| match tracker {
        Some(tracker) => tracker.observe(sample),
        None => *tracker = Some(Tracker::new(sample)),
    });
}

/// Whether a descriptor written at `written_at` is positively no older than the
/// process `facts`, with no clock discontinuity possible since the process
/// started. Fails closed on any unreadable clock, missing start tick, process
/// that started before Bridge or before the last discontinuity, and a file
/// time outside the plausible window.
pub(crate) fn written_after_start(facts: &ProcessFacts, written_at: (i64, i64)) -> bool {
    let (Some(ticks), Some(now)) = (facts.start_ticks, read_sample()) else {
        return false;
    };
    with_tracker(|tracker| match tracker {
        Some(tracker) => tracker.fresh(now, ticks, written_at),
        None => {
            *tracker = Some(Tracker::new(now));
            false
        }
    })
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECOND: i128 = 1_000_000_000;

    /// A sample at boot time `boot` with offset `offset`, tightly read.
    fn at(boot: i128, offset: i128) -> Sample {
        Sample {
            boot,
            real_before: boot + offset + QUANTUM_NS / 2,
            real_after: boot + offset + QUANTUM_NS / 2 + 100_000,
        }
    }

    fn secs(seconds: i128) -> (i64, i64) {
        (i64::try_from(seconds).unwrap(), 0)
    }

    /// The review scenario: a process started at boot 100 s (wall 1000 s), a
    /// descriptor changed at wall 1001 s, then the wall clock stepped forward by
    /// 60 s. Placing the start with the offset sampled at verification would put
    /// it at 1060 s and wrongly accept; the discontinuity is seen and refused.
    #[test]
    fn forward_step_after_start_refuses_instead_of_accepting() {
        let offset = 900 * SECOND;
        let mut tracker = Tracker::new(at(50 * SECOND, offset));
        tracker.observe(at(99 * SECOND, offset));
        let start_ticks = 100 * 100;
        // Written one second after start, no step: fresh.
        assert!(tracker.fresh(at(110 * SECOND, offset), start_ticks, secs(1001)));
        // Written before the start (stale, wall 999 s): refused.
        assert!(!tracker.fresh(at(110 * SECOND, offset), start_ticks, secs(999)));
        // Forward step of 60 s after the start, then verification at boot 120 s.
        assert!(!tracker.fresh(
            at(120 * SECOND, offset + 60 * SECOND),
            start_ticks,
            secs(1001)
        ));
        // Not even a file written long after the step recovers this process.
        assert!(!tracker.fresh(
            at(130 * SECOND, offset + 60 * SECOND),
            start_ticks,
            secs(1100)
        ));
        // A process started after the step is judged on the new offset.
        assert!(tracker.fresh(
            at(200 * SECOND, offset + 60 * SECOND),
            150 * 100,
            secs(1100 + 50)
        ));
    }

    /// A backward step is also seen and refuses the older process.
    #[test]
    fn backward_step_after_start_refuses() {
        let offset = 900 * SECOND;
        let mut tracker = Tracker::new(at(50 * SECOND, offset));
        assert!(tracker.fresh(at(110 * SECOND, offset), 100 * 100, secs(1005)));
        assert!(!tracker.fresh(
            at(120 * SECOND, offset - 30 * SECOND),
            100 * 100,
            secs(1005)
        ));
        assert!(!tracker.fresh(at(130 * SECOND, offset - 30 * SECOND), 100 * 100, secs(980)));
    }

    /// Processes that started before Bridge cannot be proven free of a step in
    /// the gap and are refused.
    #[test]
    fn process_started_before_bridge_is_not_fresh() {
        let offset = 900 * SECOND;
        let mut tracker = Tracker::new(at(100 * SECOND, offset));
        assert!(!tracker.fresh(at(110 * SECOND, offset), 80 * 100, secs(990)));
        assert!(!tracker.fresh(at(110 * SECOND, offset), 100 * 100, secs(1005)));
        assert!(tracker.fresh(at(110 * SECOND, offset), 105 * 100, secs(1006)));
    }

    /// Slew, rounding and scheduling jitter are not discontinuities.
    #[test]
    fn slew_and_jitter_are_tolerated() {
        let offset = 900 * SECOND;
        let mut tracker = Tracker::new(at(10 * SECOND, offset));
        // 400 ppm slew over an hour, observed every minute: 24 ms per minute.
        let mut boot = 10 * SECOND;
        let mut off = offset;
        for _ in 0..60 {
            boot += 60 * SECOND;
            off += 24_000_000;
            tracker.observe(at(boot, off));
        }
        assert_eq!(tracker.break_boot, None);
        // 30 ms of scheduling noise on one sample.
        tracker.observe(at(boot + SECOND, off + 30_000_000));
        assert_eq!(tracker.break_boot, None);
        let start = (boot - 30 * SECOND) / TICK_NS;
        assert!(tracker.fresh(
            at(boot + 2 * SECOND, off),
            u64::try_from(start).unwrap(),
            (
                i64::try_from((boot - 20 * SECOND + off) / SECOND).unwrap(),
                0
            )
        ));
    }

    /// A file time in the future (a backward step before Bridge started leaves old
    /// times ahead of the clock) or before the start is refused.
    #[test]
    fn implausible_file_times_are_refused() {
        let offset = 900 * SECOND;
        let mut tracker = Tracker::new(at(50 * SECOND, offset));
        let now = at(110 * SECOND, offset);
        assert!(!tracker.fresh(now, 100 * 100, secs(1011 + 1)), "future");
        assert!(!tracker.fresh(now, 100 * 100, secs(999)), "before start");
        assert!(!tracker.fresh(now, 0, secs(1005)), "no start");
        assert!(tracker.fresh(now, 100 * 100, secs(1005)));
    }

    /// The process-wide wrapper with a really injected wall-clock step.
    #[test]
    fn injected_wall_step_refuses_the_live_process() {
        reset();
        observe();
        std::thread::sleep(std::time::Duration::from_millis(60));
        let mut child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let facts = crate::os::process_facts(child.id()).unwrap();
        let wall = |extra: i128| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let total = i128::try_from(now).unwrap() + extra;
            (
                i64::try_from(total / SECOND).unwrap(),
                i64::try_from(total % SECOND).unwrap(),
            )
        };
        assert!(written_after_start(&facts, wall(0)));
        assert!(
            !written_after_start(&facts, wall(-10 * SECOND)),
            "descriptor older than the process"
        );
        inject_step(60 * SECOND);
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(
            !written_after_start(&facts, wall(60 * SECOND)),
            "forward step: the process is no longer provably covered"
        );
        assert!(!written_after_start(&facts, wall(0)));
        child.kill().unwrap();
        child.wait().unwrap();
        reset();
    }
}
