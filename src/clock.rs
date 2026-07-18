use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};

pub trait Clock: Clone + Send + Sync + 'static {
    fn now_ms(&self) -> u64;
}

#[derive(Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

#[derive(Clone, Default)]
pub struct VirtualClock(Arc<AtomicU64>);

impl VirtualClock {
    pub fn at(now_ms: u64) -> Self {
        Self(Arc::new(AtomicU64::new(now_ms)))
    }

    pub fn advance(&self, delta_ms: u64) {
        self.0.fetch_add(delta_ms, Ordering::SeqCst);
    }
}

impl Clock for VirtualClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
