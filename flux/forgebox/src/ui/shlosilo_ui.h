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
} UiPage;

void UiInit(void);
void UiShow(void);
void UiTick(void);

UiPage UiGetPage(void);
void UiGotoPage(UiPage page);
void UiSetPayload(const char *text, uint32_t len);
void UiScanInfo(const char *line1, const char *line2, const char *line3, const char *line4);
void UiScanProgress(uint8_t percent);

/* Sign page summary lines (request type / payload size / key note). Set them
 * before UiGotoPage(UI_PAGE_SIGN); calling while on the sign page repaints. */
void UiSignInfo(const char *line1, const char *line2, const char *line3);
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

/* Battery corner readout ("NN%" / "NN%c") driven by the product task:
 * repaints just that corner, and only when the value changes. */
void UiSetBattery(uint8_t percent, bool charging);

/* Panic screen: show an L3 panic message (called from shlosilo_panic_hook;
 * the caller keeps the WDT fed afterwards). No-op before UiInit. */
void UiPanic(const char *msg);

/* Input poll hook: the UI runs synchronous waits (band flushes here, capture
 * waits in drv_qrdecode.c) during which a page loop cannot sample input -
 * on device this read as "touch intermittently dead" on the carousel page.
 * The product task installs its touch sampler here; wait loops call
 * UiInputPoll() so a press is seen within ~1 ms even mid-flush. */
typedef void (*UiInputPollFn)(void);
void UiSetInputPoll(UiInputPollFn fn);
void UiInputPoll(void);

#endif
