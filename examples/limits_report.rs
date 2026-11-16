//! Print this build's resource-budget report as JSON.
//!
//! Usage: SHLOSILO_LIMITS=<profile> cargo run --example limits_report
//! The numbers come from the production layout functions, so what you see is what the
//! carrier will carve. `computed_on.pointer_bytes` says whether this was a host or a
//! 32-bit device build.
fn main() {
    let report = shlosilo::limits_report::BudgetReport::collect();
    let mut buf = [0u8; 2048];
    match report.write_json(&mut buf) {
        Ok(n) => {
            use std::io::Write;
            let mut out = std::io::stdout();
            let _ = out.write_all(&buf[..n]);
            let _ = out.flush();
        }
        Err(_) => {
            eprintln!("limits report does not fit the buffer");
            std::process::exit(1);
        }
    }
    if !report.fits() {
        eprintln!(
            "limits: profile {} exceeds its heap budget (peak {} > {})",
            report.profile,
            report.max_phase(),
            report.psram_budget
        );
        std::process::exit(2);
    }
}
