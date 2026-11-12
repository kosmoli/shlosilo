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
/* WP4 UX (2026-11-02): three-button bar — home | mode | camera.
 * The middle slot (mode) is only active/drawn with a label on the QR page
 * (wire-view switch: Indexed <-> Keyed); elsewhere its frame stays empty. */
#define UI_BTN_L_X0          16
#define UI_BTN_L_X1          165
#define UI_BTN_M_X0          175
#define UI_BTN_M_X1          305
#define UI_BTN_R_X0          315
#define UI_BTN_R_X1          463
#define UI_BTN_T             2
#define UI_BTN_LABEL_SCALE   2
#define UI_BTN_LABEL_LEFT    "home"
#define UI_BTN_LABEL_MODE    "wire"
#define UI_BTN_LABEL_RIGHT   "camera"

/* Footer: three diagnostic lines above the button band */
#define UI_FOOTER_X          16
#define UI_FOOTER_L1_Y       588
#define UI_FOOTER_L2_Y       608
#define UI_FOOTER_L3_Y       628
/* W0-1: shlosilo build identity (v0.5.0-poc4+<git7>) — the line the operator
 * reads to confirm which shlosilo build is actually flashed. The `fw` line
 * above it is the vendor firmware hash, which does NOT track our commits. */
#define UI_FOOTER_L4_Y       648

/* Battery readout (top-right; text right-aligned at UI_BATT_RIGHT):
 * "NN%" normally, "NN%c" while charging. The repaint box covers the widest
 * string ("100%c") so shrink-repaints leave no residue. */
#define UI_BATT_Y            6
#define UI_BATT_RIGHT        468
#define UI_BATT_SCALE        2
#define UI_BATT_CLEAR_X      376

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

/* Scan page (D2.6: camera preview rotated 90 deg CCW -> portrait 240x320;
 * the status/info strip moved below the box - the footer yields this area
 * on this page, see draw_page) */
#define UI_S_TITLE_Y         64
#define UI_S_TITLE_SCALE     4
#define UI_S_SUB_Y           152
#define UI_S_SUB_SCALE       2
#define UI_S_BOX_X0          60
#define UI_S_BOX_Y0          210
#define UI_S_BOX_X1          420
#define UI_S_BOX_Y1          560
#define UI_S_BOX_T           2
#define UI_S_PV_X0           120
#define UI_S_PV_Y0           224
#define UI_S_PV_W            240
#define UI_S_PV_H            320
#define UI_S_STATUS_Y        568
#define UI_S_STATUS_SCALE    2
#define UI_S_INFO1_Y         608
#define UI_S_INFO2_Y         626
#define UI_S_INFO3_Y         644
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

/* Sign page (product XMR sign session): request summary + a fixed status
 * banner (the sign call is synchronous - the page is painted once before it
 * blocks, so no live region is needed). */
/* Review page (W0-1): sign-request summary, one ink, text only.
 * `wire` advances pages and turns into the confirm key on the last page. */
#define UI_RV_TITLE_Y        40
#define UI_RV_TITLE_SCALE    3
/* Body geometry (2026-11-05, first real-device layout review): a 46 px pitch
 * spread nine short lines over three pages while two thirds of the panel sat
 * empty. 30 px pitch fits twelve lines (the whole typical BTC review) on one
 * page; the page indicator moves under the body instead of floating mid-screen. */
#define UI_RV_BODY_Y0        120
#define UI_RV_LINE_PITCH     30
#define UI_RV_LINES          12
#define UI_RV_FOOT_Y         ((UI_RV_BODY_Y0) + (UI_RV_LINES) * (UI_RV_LINE_PITCH) - 10)
#define UI_RV_LINE_SCALE     1

#define UI_NG_TITLE_Y        64
#define UI_NG_TITLE_SCALE    4
#define UI_NG_SUB_Y          152
#define UI_NG_SUB_SCALE      2
#define UI_NG_INFO1_Y        300
#define UI_NG_INFO2_Y        330
#define UI_NG_INFO3_Y        360
#define UI_NG_STATUS_Y       460
#define UI_NG_STATUS_SCALE   2
#define UI_TXT_SIGN          "sign"
#define UI_TXT_SIGN_SUB      "signing request"
#define UI_TXT_SIGN_STATUS   "signing - do not touch"

/* Confirm page (Task 5b: seed-plate import confirmation). Text only, one ink
 * (the UI constraints hold: no LVGL, monochrome, back/continue text buttons).
 * Type line + source line are pushed by the product task (UiSeedConfirmInfo);
 * the warning is fixed here. */
#define UI_C_TITLE_Y         64
#define UI_C_TITLE_SCALE     4
#define UI_C_SUB_Y           152
#define UI_C_SUB_SCALE       2
#define UI_C_TYPE_Y          300
#define UI_C_TYPE_SCALE      2
#define UI_C_WARN1_Y         380
#define UI_C_WARN2_Y         412
#define UI_C_WARN_SCALE      2
#define UI_C_SRC_Y           480
#define UI_C_SRC_SCALE       2
#define UI_TXT_CONFIRM       "confirm seed"
#define UI_TXT_CONFIRM_SUB   "key import"
#define UI_TXT_CONFIRM_W1    "KEY MATERIAL ENTERS RAM"
#define UI_TXT_CONFIRM_W2    "SHUTDOWN CLEARS THE KEY"
#define UI_TXT_CONFIRM_SRC   "source: plate scan"

/* QR carousel page (F3 output side: UR frames for a wallet to scan) */
/* S2 account export: the six wire shapes as a selectable list.
 * Rows are the format strings themselves (scale 2 = 16 px glyphs, the longest
 * label `json: monero (cupcake)` is 22 chars = 352 px, so text starts at 56
 * and clears 480). */
#define UI_XP_TITLE_Y        40
#define UI_XP_TITLE_SCALE    3
#define UI_XP_ROW_Y0         140
#define UI_XP_ROW_PITCH      64
#define UI_XP_ROWS           8
#define UI_XP_ROW_SCALE      2
#define UI_XP_MARK_X         16
#define UI_XP_TEXT_X         56
#define UI_XP_FOOT_Y         600

#define UI_Q_TITLE_Y         36
#define UI_Q_TITLE_SCALE     2
#define UI_Q_TXT_TITLE       "scan with wallet"
/* Plate export (Phase 4 acceptance ②): the screen QR IS the wallet's steel
 * plate - anyone who photographs it owns the wallet. The title says so, on
 * the screen, next to the code (same warning style as the console face). */
#define UI_Q_TXT_PLATE_TITLE "seedqr plate - SECRET"
#define UI_Q_TXT_PLATE_CAP   "screen shows the wallet!"
#define UI_Q_AREA_X0         16
#define UI_Q_AREA_Y0         80
#define UI_Q_AREA_W          448
#define UI_Q_AREA_H          476
#define UI_Q_CAP_Y           566

/* Crash-forensics page (boot self-check "LAST CRASH", operator diagnostic).
 * Fixed template: title + 5 content lines + ack hint; addresses/hex allowed. */
#define UI_X_TITLE_Y         88
#define UI_X_TITLE_SCALE     3
#define UI_X_L1_Y            190
#define UI_X_L2_Y            226
#define UI_X_L3_Y            262
#define UI_X_L4_Y            298
#define UI_X_L5_Y            334
#define UI_X_HINT_Y          430
#define UI_X_HINT_SCALE      2
#define UI_TXT_CRASH         "LAST CRASH"
#define UI_TXT_CRASH_HINT    "back: clear record"

#endif
