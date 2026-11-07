#ifndef SHLOSILO_UI_H
#define SHLOSILO_UI_H

#include <stdint.h>
#include <stdbool.h>

/* Product UI (direct-write renderer, see shlosilo_ui.c).
 *
 * UiInit(): allocate the canvas + flush band (SRAM heap).
 * UiTick(): poll touch and handle button presses (call every ~40 ms while the
 *           UI is in normal mode; not used while the camera scan is active).
 */
typedef enum {
    UI_PAGE_WELCOME = 0,
    UI_PAGE_SCAN,
    UI_PAGE_PAYLOAD,
    UI_PAGE_SIGN,       /* product sign session (synchronous call behind it) */
    UI_PAGE_QR,         /* UR carousel: animated QR frames for a wallet */
    UI_PAGE_CONFIRM,    /* Task 5b: seed-plate import confirmation */
    UI_PAGE_CRASH,      /* operator diagnostic: unconsumed "LAST CRASH" record */
    UI_PAGE_REVIEW,     /* sign-request review: what the operator signs off on */
    UI_PAGE_EXPORT_LIST, /* S2 account export: pick one of the six wire shapes */
} UiPage;

void UiInit(void);
void UiShow(void);
void UiTick(void);

UiPage UiGetPage(void);
void UiGotoPage(UiPage page);
void UiSetPayload(const char *text, uint32_t len);
void UiScanInfo(const char *line1, const char *line2, const char *line3, const char *line4);
/* Metrics rows only -- never touches the status slot (l1/progress). */
void UiScanMetrics(const char *m1, const char *m2, const char *m3);
void UiScanProgress(uint8_t percent);

/* Sign page summary lines (request type / payload size / key note). Set them
 * before UiGotoPage(UI_PAGE_SIGN); calling while on the sign page repaints. */
void UiSignInfo(const char *line1, const char *line2, const char *line3);

/* Review page (W0-1): four body lines + one footer line.
 *
 * Text comes from the forms review view — fixed vocabulary plus canonically
 * re-encoded addresses/amounts. The platform layer never formats payload
 * content itself. `wire` advances the page and confirms on the last one;
 * `home` cancels (and zeroizes the session). Set the lines before
 * UiGotoPage(UI_PAGE_REVIEW); calling it while on the review page repaints. */
void UiReviewShow(const char *const *lines, unsigned count, const char *foot);
void UiSetLast(const char *text);

/* Seed-plate import confirmation (Task 5b). Set the lines before
 * UiGotoPage(UI_PAGE_CONFIRM); calling while on the confirm page repaints.
 * The warning block is fixed text (ui_layout.h). The page's back/continue
 * buttons do not navigate directly - they record a decision the product
 * task consumes with UiConfirmDecision() and then routes (open/reject ->
 * close + back to scan). */
void UiSeedConfirmInfo(const char *type_line, const char *src_line);
int UiConfirmDecision(void);    /* 0 = pending, 1 = continue, -1 = back */
void UiTouchReset(void);
bool UiIsBackButton(int x, int y);
bool UiIsContinueButton(int x, int y);
bool UiIsModeButton(int x, int y);
/* WP4 UX: one-shot `home` press request (welcome + zeroize). */
int UiTakeHomeRequest(void);
/* S2 export: one-shot `wire` press on the welcome page ("connect software
 * wallet"). The product task consumes it and opens the format list; the UI
 * does not touch the key session, so the session check lives there. */
int UiTakeExportRequest(void);

/* ---------------- S2 account export: format list ----------------
 *
 * The list is the six account-export wire shapes (`ur:crypto-account`,
 * `bitcoin:?xpub=&label=`, ...) - the format strings themselves, not wallet
 * brands. Three LOGICAL actions drive it, so the same library works on a
 * touchscreen (forgebox: home/wire/camera zones) and on a button-only device
 * (three physical keys):
 *
 *   UI_ACTION_PREV   - previous item; on the first item: leave the list
 *   UI_ACTION_NEXT   - next item, wrapping at the end
 *   UI_ACTION_SELECT - take the item under the cursor
 *
 * The list owns the cursor; the platform owns only the key mapping. A caller
 * runs the list like this: UiExportListShow(...) once, then feed actions from
 * its input loop and poll UiExportListTake() for 1 (selected: read
 * UiExportListCursor(), then build the payload) or -1 (leave).
 *
 * Labels are borrowed pointers - they must outlive the page. The labels from
 * shlosilo_export_format_label() are static, which is the intended source. */
#define UI_ACTION_PREV   0
#define UI_ACTION_NEXT   1
#define UI_ACTION_SELECT 2

void UiExportListShow(const char *const *labels, unsigned count);
unsigned UiExportListCursor(void);
/* 0 = nothing yet, 1 = selected, -1 = leave. Consumes the request. */
int UiExportListTake(void);
/* Feed one action in. Returns 0 = consumed (repainted), 1 = selected,
 * -1 = leave requested / not on the list page. */
int UiExportListInput(int action);

/* Binarized aiming preview: render one camera gray frame (640x480) into the
 * scan page. Called by the camera driver while a captured frame is valid. */
void UiScanPreview(const uint8_t *gray, int w, int h);
uint32_t UiScanGetFocus(void);

/* UR carousel frame (F3 output side): render one UR frame string as a QR on
 * the QR page. index is zero-based; total is the cycle's frame count. */
void UiShowQrFrame(const char *text, uint32_t index, uint32_t total);

/* Plate-export QR (Phase 4 acceptance ②): render a steel-plate QR payload
 * (SeedQR standard digits or CompactSeedQR raw entropy bytes) fullscreen on
 * the QR page, with the SECRET-exposure title/caption. Always the BINARY QR
 * encoder: the payload is a length-delimited buffer (never NUL-terminated),
 * and byte-mode carries ASCII digits and raw entropy with the identical
 * decoded payload a text-mode symbol would show. One static frame (no
 * carousel); the payload is a plaintext-equivalent wallet - the caller must
 * wipe its own buffer after this returns. */
void UiShowPlateQr(const uint8_t *payload, uint32_t len);
/* Plate-secret hygiene (Task 8/acceptance): wipe the QR scratch regions
 * (payload buffer, codeword buffer, framebuffer) at session teardown, and
 * report the NONZERO byte count across them for `se dump` forensics. */
void UiWipePlateQr(void);
uint32_t UiPlateQrResidueCount(void);

/* Battery corner readout ("NN%" / "NN%c") driven by the product task:
 * repaints just that corner, and only when the value changes. */
void UiSetBattery(uint8_t percent, bool charging);

/* Panic screen: show an L3 panic message (called from shlosilo_panic_hook;
 * the caller keeps the WDT fed afterwards). No-op before UiInit. */
void UiPanic(const char *msg);

/* Crash-forensics page (boot self-check): fixed-template operator diagnostic
 * for an unconsumed crash record. Lines are pre-formatted by the product task
 * from the fixed vocabulary (type name, "PC .. LR ..", "PSR .. CFSR ..",
 * "PHASE n NAME", "LOC file:line") - addresses/hex are allowed here, this is
 * the operator diagnostic surface, not the error surface. Set the lines
 * before UiGotoPage(UI_PAGE_CRASH). The back tap requests consumption
 * (UiCrashAck -> product task erases the record and routes on). */
void UiCrashInfo(const char *l1, const char *l2, const char *l3,
                 const char *l4, const char *l5);
int UiCrashAck(void);   /* 0 = pending, 1 = back tapped (consumed once) */

/* Input poll hook: the UI runs synchronous waits (band flushes here, capture
 * waits in drv_qrdecode.c) during which a page loop cannot sample input -
 * on device this read as "touch intermittently dead" on the carousel page.
 * The product task installs its touch sampler here; wait loops call
 * UiInputPoll() so a press is seen within ~1 ms even mid-flush. */
typedef void (*UiInputPollFn)(void);
void UiSetInputPoll(UiInputPollFn fn);
void UiInputPoll(void);

#endif
