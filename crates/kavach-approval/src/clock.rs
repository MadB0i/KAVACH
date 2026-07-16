use chrono::{DateTime, Utc};

/// Injectable clock abstraction for deterministic time handling.
///
/// Business logic must never depend directly on `SystemTime::now()` or
/// `Utc::now()`. Using this trait enables deterministic expiry testing and
/// isolates all time-dependent behaviour behind a single seam.
pub trait Clock: Send + Sync {
    /// Returns the current UTC time.
    fn now(&self) -> DateTime<Utc>;
}

/// Clock that delegates to `chrono::Utc::now()`.
#[derive(Debug, Clone, Copy)]
pub struct RealClock;

impl Clock for RealClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// Clock with a fixed time, useful for testing.
#[derive(Debug, Clone)]
pub struct FakeClock {
    now: DateTime<Utc>,
}

impl FakeClock {
    /// Creates a new fake clock set to the given time.
    pub fn new(now: DateTime<Utc>) -> Self {
        Self { now }
    }

    /// Advances the clock by the given duration.
    pub fn advance(&mut self, duration: chrono::Duration) {
        self.now += duration;
    }

    /// Sets the clock to the given time.
    pub fn set(&mut self, now: DateTime<Utc>) {
        self.now = now;
    }
}

impl Clock for FakeClock {
    fn now(&self) -> DateTime<Utc> {
        self.now
    }
}
