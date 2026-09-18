/* ui_layout.h - product UI layout constants (D1 base + D2 scan/payload).
 *
 * Single source of truth shared by the firmware (src/ui/shlosilo_ui.c) and the
 * host preview (flux/forgebox/scripts/preview_ui.py parses this header, plus
 * ui_font.c). Edit here, re-run the preview, then flash.
 *
 * All coordinates are inclusive pixel coordinates on the 480x800 portrait
 * panel. Ink layout only: one colour, text + rects + (later) QR.
 */
#ifndef SHLOSILO_UI_LAYOUT_H
#define SHLOSILO_UI_LAYOUT_H

/* Framebuffer geometry (1bpp) */
#define UI_FB_W              480
#define UI_FB_H              800

/* Colours (RGB565) */
#define UI_INK_RGB565        0x07E0
#define UI_BG_RGB565         0x0000

/* Button band (bottom, text labels; back left / continue right) */
#define UI_BTN_Y0            700
#define UI_BTN_Y1            787
#define UI_BTN_L_X0          16
#define UI_BTN_L_X1          231
#define UI_BTN_R_X0          248
#define UI_BTN_R_X1          463
#define UI_BTN_T             2
#define UI_BTN_LABEL_SCALE   2
#define UI_BTN_LABEL_LEFT    "back"
#define UI_BTN_LABEL_RIGHT   "continue"

/* Footer: three diagnostic lines above the button band */
#define UI_FOOTER_X          16
#define UI_FOOTER_L1_Y       588
#define UI_FOOTER_L2_Y       608
#define UI_FOOTER_L3_Y       628

/* Separator line above the button band */
#define UI_LINE_Y            676
#define UI_LINE_X0           16
#define UI_LINE_X1           463

/* Welcome page */
#define UI_W_TITLE_Y         64
#define UI_W_TITLE_SCALE     4
#define UI_W_SUB_Y           152
#define UI_W_SUB_SCALE       2
#define UI_W_BIG_Y           300
#define UI_W_BIG_SCALE       3
#define UI_W_HINT_Y          380
#define UI_W_HINT_SCALE      2
#define UI_TXT_TITLE         "shlosilo"
#define UI_TXT_SUB           "forgebox signer"
#define UI_TXT_BIG           "welcome"
#define UI_TXT_HINT          "tap continue to begin"

/* Scan page */
#define UI_S_TITLE_Y         64
#define UI_S_TITLE_SCALE     4
#define UI_S_SUB_Y           152
#define UI_S_SUB_SCALE       2
#define UI_S_BOX_X0          60
#define UI_S_BOX_Y0          210
#define UI_S_BOX_X1          420
#define UI_S_BOX_Y1          560
#define UI_S_BOX_T           2
#define UI_S_STATUS_Y        230
#define UI_S_STATUS_SCALE    2
#define UI_S_INFO_X          96
#define UI_S_INFO1_Y         300
#define UI_S_INFO2_Y         320
#define UI_S_INFO3_Y         340
#define UI_S_LIVE_X0         64
#define UI_S_LIVE_X1         416
#define UI_S_LIVE_FLUSH_Y0   200
#define UI_S_LIVE_FLUSH_Y1   400
#define UI_TXT_SCAN          "scan"
#define UI_TXT_SCAN_SUB      "qr scanner"

/* Payload page */
#define UI_P_TITLE_Y         32
#define UI_P_TITLE_SCALE     3
#define UI_P_INFO_Y          88
#define UI_P_TEXT_X          16
#define UI_P_TEXT_Y0         110
#define UI_P_LINE_H          18
#define UI_P_MAX_LINES       25
#define UI_P_CHARS_PER_LINE  56
#define UI_TXT_RESULT        "result"

#endif
