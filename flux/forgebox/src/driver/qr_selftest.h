#ifndef SHLOSILO_QR_SELFTEST_H
#define SHLOSILO_QR_SELFTEST_H

#include <stdint.h>

/* Synthetic QR self-test (see qr_selftest.c).
 *
 * QrSelfTestStamp() draws a clean version-1 QR ("SELFTEST-OK") into a
 * 640x480, 8-bit luma capture buffer - the same layout the decode library
 * reads. drv_qrdecode.c calls it every few frames while scanning; a decode
 * of this pattern proves the capture->decode path works end to end, so a
 * decode failure on a real scene can be attributed to the scene itself
 * (distance / focus / framing) instead of the pipeline. */

#define QR_SELFTEST_MODULES    21      /* version-1 QR: 21x21 modules */
#define QR_SELFTEST_MODULE_PX  6       /* pixels per module in the stamp */
#define QR_SELFTEST_QUIET      4       /* quiet-zone modules around the code */
#define QR_SELFTEST_LIGHT      190     /* luma: light modules + quiet zone */
#define QR_SELFTEST_DARK       40      /* luma: dark modules */

extern const uint32_t g_qr_selftest_modules[QR_SELFTEST_MODULES];

void QrSelfTestStamp(uint8_t *buf, int width, int height);

#endif
