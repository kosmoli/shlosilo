//! Platform resource ceilings, generated at build time from `limits/<profile>.toml`.
//!
//! Nothing here is a protocol constant: these are the caps that follow the carrier's
//! memory budget (PSRAM heap, task stack, DRAM). The profile is chosen with
//! `SHLOSILO_LIMITS=<name>` - normally through `build.sh --profile <name>` - and a
//! bare-metal build refuses to start without one, so a device can never silently wear
//! the host's ceilings.
//!
//! Design rules that outlive this file:
//! - The **source of truth is Rust**; the C header for the forgebox carrier is a
//!   generated projection of this module, never the other way round.
//! - Sizing that must be known at compile time (stack arrays, `heapless` capacities)
//!   lives here. Anything that only sizes a caller-carved workspace takes a runtime
//!   value clamped to these ceilings.
//! - Cross-key sanity is checked in `build.rs` (e.g. the inbound payload ceiling may not
//!   exceed what the part domain can assemble), because a profile that cannot work must
//!   fail the build, not the device.

include!(concat!(env!("OUT_DIR"), "/limits_generated.rs"));
