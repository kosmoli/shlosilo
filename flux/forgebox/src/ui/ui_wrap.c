/* ui_wrap.c - see ui_wrap.h. Pure logic, no hardware access. */
#include <stddef.h>
#include "ui_wrap.h"

int ui_wrap_text(const char *s, uint32_t n, uint32_t chars_per_line,
                 int max_lines, UiWrapLine *out, bool *truncated)
{
    uint32_t pos = 0;
    int line = 0;

    if (truncated != NULL) {
        *truncated = false;
    }
    if (chars_per_line == 0 || max_lines <= 0) {
        return 0;
    }

    while (pos < n && line < max_lines) {
        uint32_t end = pos, last_space = 0;
        uint32_t limit = pos + chars_per_line;
        bool nl = false;

        while (end < n && end < limit) {
            char c = s[end];
            if (c == '\n' || c == '\r') {
                nl = true;
                break;
            }
            end++;
            if (c == ' ') {
                last_space = end;
            }
        }

        if (nl) {
            /* Forced break: emit what we have (possibly empty), skip the
             * newline run. */
            out[line].start = pos;
            out[line].len = end - pos;
            line++;
            pos = end + 1;
            while (pos < n && (s[pos] == '\n' || s[pos] == '\r')) {
                pos++;
            }
        } else {
            uint32_t emit_end = end;
            if (end < n && last_space > pos) {
                emit_end = last_space;
            }
            out[line].start = pos;
            out[line].len = emit_end - pos;
            line++;
            pos = emit_end;
        }
    }

    if (truncated != NULL) {
        *truncated = (pos < n);
    }
    return line;
}
