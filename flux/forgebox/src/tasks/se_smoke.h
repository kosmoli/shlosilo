#ifndef _SE_SMOKE_H
#define _SE_SMOKE_H

/*
 * se_smoke.h - SE smoke battery + gated provisioning console (Task 7).
 *
 * HARDWARE SAFETY GATE (the whole point of this file):
 *   - read-only checks (dual-SE identify/comm, RNG, KDF derivation, wrong-
 *     password piece comparison) run automatically and may be re-run any time.
 *   - EVERY SE/OTP write path is behind an explicit serial trigger with a
 *     permanent-side-effect warning on screen first and a second, separate
 *     CONFIRM command. Nothing in the automatic battery can write to the
 *     ATECC608B, the DS28S60 or the MH1903 OTP - not even lazily (the probe
 *     and kdf checks gate on the OTP salt being present before touching any
 *     HashWithSalt path, so the lazy salt burn can never fire implicitly).
 *
 * Why the gate is so strict - these are one-way doors:
 *   OTP_ADDR_AES_KEY      one-time burn; the inner AES piece is PERMANENT
 *   OTP_ADDR_SALT         one-time burn; every HashWithSalt output depends on it
 *   OTP_ADDR_ATECC608B    one-time burn of the ATECC binding keys (first
 *                         Atecc608bInit) + the chip config is written/locked
 *   OTP_ADDR_DS28S60      one-time burn of the DS28S60 binding keys (first
 *                         DS28S60_Init)
 *
 * Commands (UART0, see flux/forgebox/docs/se-keystore-checklist.md):
 *   se probe                       read-only self-check battery
 *   se kdf <password>              read-only wrong-password KDF checks
 *   se provision                   ARM: print permanent warning
 *   se provision CONFIRM           execute: OTP salt + AES piece + SE binding
 *   se slots                       ARM: print SE-write warning
 *   se slots CONFIRM <password>    execute: 3-account key-piece write/readback
 */

/* Run the read-only self-check battery. Returns the number of failed checks.
 * `line` output goes through SeSmokeSetLog's sink (screen + UART mirror). */
int SeSmokeProbe(void);

/* Read-only wrong-password checks. `password` may be NULL (auto battery):
 * then the "correct password" leg is skipped (the battery has no password to
 * try) and only the password-independent checks run. Returns failed checks. */
int SeSmokeKdfChecks(const char *password);

/* Poll the UART0 command console. Call from a task loop, never from the ISR. */
void SeConsolePoll(void);

/* On-screen log sink (the smoke task wires this to its log_line). Default
 * sink is printf (UART only). */
void SeSmokeSetLog(void (*fn)(const char *line));

#endif
