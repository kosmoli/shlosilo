/* ui_qr.c - see ui_qr.h. Pure logic; the same source runs on the device and
 * in the host verification harness (scripts/test_qr_render.py). */
#include "ui_qr.h"
#include "qrcodegen.h"

#define UI_QR_QUIET 4

/* Bounded 1bpp pixel fill: on=1 sets bits, on=0 clears (MSB = leftmost). */
static void px_fill(uint8_t *fb, int fb_w, int fb_h,
                    int x, int y, int w, int h, int on)
{
    for (int yy = y; yy < y + h; yy++) {
        if ((unsigned)yy >= (unsigned)fb_h) {
            continue;
        }
        for (int xx = x; xx < x + w; xx++) {
            if ((unsigned)xx >= (unsigned)fb_w) {
                continue;
            }
            uint8_t *cell = &fb[yy * (fb_w / 8) + (xx >> 3)];
            if (on) {
                *cell |= (uint8_t)(0x80u >> (xx & 7));
            } else {
                *cell &= (uint8_t)~(0x80u >> (xx & 7));
            }
        }
    }
}

bool ui_qr_encode(const char *text, uint8_t *temp, uint8_t *qr, int *modules_out)
{
    if (text == NULL || temp == NULL || qr == NULL) {
        return false;
    }
    /* Same profile as the pico2 host (qrcodegen-no-heap mirror): ECC LOW,
     * versions 1..40, automatic mask, ECL boost. */
    bool ok = qrcodegen_encodeText(text, temp, qr, qrcodegen_Ecc_LOW,
                                   qrcodegen_VERSION_MIN, qrcodegen_VERSION_MAX,
                                   qrcodegen_Mask_AUTO, true);
    if (ok && modules_out != NULL) {
        *modules_out = qrcodegen_getSize(qr);
    }
    return ok;
}

bool ui_qr_layout(int modules, int area_x, int area_y, int area_w, int area_h,
                  UiQrLayout *out)
{
    int total = modules + 2 * UI_QR_QUIET;
    int scale;

    if (out == NULL || total <= 0 || area_w <= 0 || area_h <= 0) {
        return false;
    }
    scale = area_w / total;
    if (area_h / total < scale) {
        scale = area_h / total;
    }
    if (scale < 1) {
        return false;
    }
    out->modules = modules;
    out->module_px = scale;
    out->x0 = area_x + (area_w - total * scale) / 2;
    out->y0 = area_y + (area_h - total * scale) / 2;
    return true;
}

void ui_qr_draw(const uint8_t *qr, const UiQrLayout *layout,
                uint8_t *fb, int fb_w, int fb_h)
{
    const int scale = layout->module_px;
    const int span = (layout->modules + 2 * UI_QR_QUIET) * scale;

    if (qr == NULL || fb == NULL || scale < 1) {
        return;
    }

    /* Lit block: quiet zone included - the black screen behind a bare QR
     * would leave the margin dark, and scanners need a light quiet zone. */
    px_fill(fb, fb_w, fb_h, layout->x0, layout->y0, span, span, 1);

    /* Dark modules knocked out to 0. */
    for (int my = 0; my < layout->modules; my++) {
        for (int mx = 0; mx < layout->modules; mx++) {
            if (qrcodegen_getModule(qr, mx, my)) {
                px_fill(fb, fb_w, fb_h,
                        layout->x0 + (UI_QR_QUIET + mx) * scale,
                        layout->y0 + (UI_QR_QUIET + my) * scale,
                        scale, scale, 0);
            }
        }
    }
}
