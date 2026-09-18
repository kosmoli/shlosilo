#ifndef SHLOSILO_UI_QR_H
#define SHLOSILO_UI_QR_H

#include <stdbool.h>
#include <stdint.h>

/* ui_qr - QR encode + 1bpp canvas rendering (F3 output side).
 *
 * Pure logic, no hardware dependencies: encoder, layout and pixel rendering
 * all operate on caller-provided buffers, so the exact device rendering path
 * compiles and runs on the host (scripts/test_qr_render.py renders sample
 * frames and decodes them with an independent reader). Used by shlosilo_ui.c
 * for the UR carousel page; QR generation is Nayuki qrcodegen.c (MIT,
 * vendored in external/qrcodegen/). */

/* Buffer size for one qrcodegen encode: qrcodegen_BUFFER_LEN_MAX (v40) is
 * 3918; both the temp and the qr buffer must be at least this large. */
#define UI_QR_BUF_BYTES 3919

typedef struct {
    int x0;          /* top-left pixel of the block, quiet zone included */
    int y0;
    int modules;     /* QR size in modules (excluding the quiet zone) */
    int module_px;   /* integer pixels per module */
} UiQrLayout;

/* Encode `text` (ECC LOW, boosted, automatic mask - the pico2 profile).
 * temp and qr are caller buffers of UI_QR_BUF_BYTES. Returns false when the
 * text does not fit a version-40 QR or the buffers are unusable. */
bool ui_qr_encode(const char *text, uint8_t *temp, uint8_t *qr, int *modules_out);

/* Compute the placement of a `modules`-sized QR inside the given area,
 * including a 4-module quiet zone and an integer module scale. Returns false
 * when even scale 1 does not fit. */
bool ui_qr_layout(int modules, int area_x, int area_y, int area_w, int area_h,
                  UiQrLayout *out);

/* Render the QR into a 1bpp framebuffer (stride = fb_w/8, MSB = leftmost):
 * a LIT block over the layout area (so scanners get dark-on-light with a
 * proper quiet zone) with the DARK modules knocked out to 0. */
void ui_qr_draw(const uint8_t *qr, const UiQrLayout *layout,
                uint8_t *fb, int fb_w, int fb_h);

#endif
