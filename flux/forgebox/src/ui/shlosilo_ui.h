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

#endif
