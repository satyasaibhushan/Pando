pub mod authority;
pub mod classify;
pub mod clock;
pub mod config;
pub mod daemon;
pub mod escape;
pub(crate) mod fsutil;
pub mod git;
pub mod model;
pub mod registry;
pub mod rehydrate;
pub mod service;
pub mod snapshot;
pub mod store;
pub mod sync;
pub mod transport;
pub mod tui;

pub use authority::{
    AcquireResult, Authority, AuthorityStatus, FileAuthority, GarbageCollectionReport,
};
pub use clock::{Clock, SystemClock, VirtualClock};
pub use model::{ChunkHash, FileEntry, FileKind, Lease, Manifest, Overlay, SnapshotId};
pub use snapshot::{capture, materialization_delta, materialize_overlay, overlay_against};
pub use sync::{PullResult, PushResult, Trunk};
