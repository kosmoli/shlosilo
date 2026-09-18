/* ui_wrap.h - pure word-wrap for the payload page (host-testable).
 *
 * Splits a byte buffer into display lines without losing characters:
 *   - prefers breaking at the last space within the range (the space stays at
 *     the end of the emitted line);
 *   - hard-breaks when no space fits;
 *   - \n / \r force a break (and are consumed, not rendered);
 *   - never drops or duplicates characters.
 *
 * The firmware renderer (shlosilo_ui.c) and the host preview
 * (scripts/preview_ui.py) implement this same algorithm; keep them in sync
 * and cross-check with scripts/test_wrap.py (C vs Python diff).
 */
#ifndef SHLOSILO_UI_WRAP_H
#define SHLOSILO_UI_WRAP_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint32_t start;     /* offset into the source buffer */
    uint32_t len;       /* characters in this line (may be 0 for a blank line) */
} UiWrapLine;

/* Wrap s[0..n) into at most max_lines lines of at most chars_per_line
 * characters each. Returns the number of lines produced; *truncated (may be
 * NULL) is set when input remained unemitted. */
int ui_wrap_text(const char *s, uint32_t n, uint32_t chars_per_line,
                 int max_lines, UiWrapLine *out, bool *truncated);

#endif
