//! Resource-budget report: what this profile costs, computed by the same formulas that
//! carve the workspaces.
//!
//! Why it exists: the limits profile says how *large* a request may be, and the workspace
//! queries say what that costs, but nothing tied them together. That gap is how a slot
//! count once quadrupled the decode workspace (2.67 MiB -> 5.94 MiB against an 8.38 MB
//! heap) while every test stayed green.
//!
//! Two rules keep this honest:
//!
//! 1. **No second formula.** Every number here comes from the very functions the carve
//!    uses (`SignWsLayout::compute`, `ur_decode_ws_len`, ...), so the report cannot drift
//!    from what the device will really allocate.
//! 2. **It says where it was computed.** `size_of::<usize>()` is 8 on the host and 4 on the
//!    ARM targets, so a host report is not a device report. The `computed_on` block records
//!    the pointer width and the target triple; per-carrier numbers are only authoritative
//!    when produced by that carrier.
//!
//! The peak model is `persistent + max(decode, sign, encode, pairing)`, not the sum:
//! the carrier allocates the decode workspace, releases it, and only then asks for the
//! signing one (see `product_task.c`). Anything that changes that ownership has to change
//! this model too.

use crate::limits;
use core::fmt::Write;

/// What one profile costs at run time, in bytes.
pub struct BudgetReport {
    pub profile: &'static str,
    pub fingerprint: u64,
    pub pointer_bytes: usize,
    pub target: &'static str,
    /// Workspaces the carrier carves, each a separate phase.
    pub sign_ws: usize,
    pub ur_decode_ws: usize,
    pub ur_encode_ws: usize,
    pub pairing_ws: usize,
    pub review_ws: usize,
    /// Budgets the profile grants.
    pub psram_budget: usize,
    pub stack_budget: usize,
}

impl BudgetReport {
    /// Collect every figure by calling the production layout functions.
    #[must_use]
    pub fn collect() -> Self {
        Self {
            profile: limits::PROFILE,
            fingerprint: limits::LIMITS_FINGERPRINT,
            pointer_bytes: core::mem::size_of::<usize>(),
            target: option_env!("SHLOSILO_TARGET").unwrap_or("unknown"),
            sign_ws: crate::business::sign::SignWsLayout::compute().total,
            ur_decode_ws: crate::ur::ur_multipart::ur_decode_ws_len(),
            ur_encode_ws: crate::ur::ur_multipart::ur_encode_ws_len(),
            pairing_ws: crate::business::xmr_pairing::pairing_ws_len(),
            review_ws: crate::ffi::c_abi::review_ws_len(),
            psram_budget: limits::PSRAM_BUDGET_BYTES,
            stack_budget: limits::STACK_BUDGET_BYTES,
        }
    }

    /// Largest single phase: what the carrier must be able to hold at once.
    #[must_use]
    pub fn max_phase(&self) -> usize {
        let phases = [
            ("decode", self.ur_decode_ws),
            ("sign", self.sign_ws),
            ("encode", self.ur_encode_ws),
            ("pairing", self.pairing_ws),
        ];
        phases.iter().map(|(_, bytes)| *bytes).max().unwrap_or(0)
    }

    /// Headroom left in the heap budget after the largest phase. Negative values are
    /// reported as 0 with `over_budget` set, because a negative usize is not a thing.
    #[must_use]
    pub fn headroom(&self) -> usize {
        self.psram_budget.saturating_sub(self.max_phase())
    }

    /// Does the profile fit the heap it was given?
    #[must_use]
    pub fn fits(&self) -> bool {
        self.max_phase() <= self.psram_budget
    }

    /// JSON snapshot (one line per field group, no allocator).
    pub fn write_json(&self, out: &mut [u8]) -> Result<usize, ReportOverflow> {
        let mut w = BufferWriter { buf: out, len: 0 };
        let written = writeln!(
            w,
            "{{\"schema\":1,\"profile\":\"{}\",\"fingerprint\":\"0x{:016x}\",\
             \"computed_on\":{{\"target\":\"{}\",\"pointer_bytes\":{}}},\
             \"workspaces\":{{\"sign\":{},\"ur_decode\":{},\"ur_encode\":{},\"pairing\":{},\"review\":{}}},\
             \"peak_model\":{{\"persistent\":0,\"max_phase\":{},\"peak\":{}}},\
             \"budgets\":{{\"psram\":{},\"stack\":{},\"headroom\":{},\"fits\":{}}},\
             \"limits\":{{\"bt_tx_inputs_max\":{},\"bt_tx_outputs_max\":{},\"psbt_maps_max\":{},\
             \"ur_ws_decoded_slots\":{},\"ur_payload_max\":{},\"pairing_records_max\":{},\
             \"sign_ws_bp_chunk_max\":{},\"sign_bp_chunk_terms\":{}}},\
             \"eip712\":{{\"types_max\":{},\"type_fields_max\":{},\"name_bytes\":{},\"depth_max\":{},\
             \"nodes_max\":{},\"encode_type_bytes\":{},\"arena_bytes\":{},\"display_bytes\":{},\
             \"json_bytes_max\":{}}}}}",
            self.profile,
            self.fingerprint,
            self.target,
            self.pointer_bytes,
            self.sign_ws,
            self.ur_decode_ws,
            self.ur_encode_ws,
            self.pairing_ws,
            self.review_ws,
            self.max_phase(),
            self.max_phase(),
            self.psram_budget,
            self.stack_budget,
            self.headroom(),
            self.fits(),
            limits::BT_TX_INPUTS_MAX,
            limits::BT_TX_OUTPUTS_MAX,
            limits::PSBT_MAPS_MAX,
            limits::UR_WS_DECODED_SLOTS,
            limits::UR_PAYLOAD_MAX,
            limits::PAIRING_RECORDS_MAX,
            limits::SIGN_WS_BP_CHUNK_MAX,
            limits::SIGN_BP_CHUNK_TERMS,
            limits::EIP712_TYPES_MAX,
            limits::EIP712_TYPE_FIELDS_MAX,
            limits::EIP712_NAME_BYTES,
            limits::EIP712_DEPTH_MAX,
            limits::EIP712_NODES_MAX,
            limits::EIP712_ENCODE_TYPE_BYTES,
            limits::EIP712_ARENA_BYTES,
            limits::EIP712_DISPLAY_BYTES,
            limits::EIP712_JSON_BYTES_MAX,
        );
        written.map_err(|_| ReportOverflow)?;
        Ok(w.len)
    }
}

/// The report did not fit the caller's buffer (never truncation: a half-written budget
/// looks like a smaller budget).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportOverflow;

impl core::fmt::Write for BufferWriter<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        if self.len + bytes.len() > self.buf.len() {
            return Err(core::fmt::Error);
        }
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(())
    }
}

struct BufferWriter<'a> {
    buf: &'a mut [u8],
    len: usize,
}
