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
    UI_PAGE_QR,         /* UR carousel: animated QR frames for a wallet */
} UiPage;

void UiInit(void);
void UiShow(void);
void UiTick(void);

UiPage UiGetPage(void);
void UiGotoPage(UiPage page);
void UiSetPayload(const char *text, uint32_t len);
void UiScanInfo(const char *line1, const char *line2, const char *line3, const char *line4);
void UiScanProgress(uint8_t percent);
void UiSetLast(const char *text);
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

/* Status readouts driven by the product task: the battery corner ("NN%" /
 * "NN%c") and the boot-diag footer override (NULL restores the default line).
 * The refresh repaints just that line; no-op while the scan page is up. */
void UiSetBattery(uint8_t percent, bool charging);
void UiSetFooterLine2(const char *text);
void UiRefreshFooterLine2(void);

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
