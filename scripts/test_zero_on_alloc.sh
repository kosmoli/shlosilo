#!/bin/bash
# P6.4: host-test-side zero-on-alloc (v2-security §3 clause 4)
#
# X3 remediation (2026-08-31): the original `export MALLOC_CONF` is completely
# ineffective against glibc malloc — MALLOC_CONF is a jemalloc-only setting and
# glibc never reads it; jemalloc's zero option also takes a boolean value
# (zero:true), so the old value zero:1 is rejected with "Invalid conf value" on
# jemalloc 5 and ignored. Measured (/tmp/zerotest: poison the heap, then
# reallocate):
#   glibc + MALLOC_CONF=zero:1          → nonzero=4096 (no effect, the old bug)
#   LD_PRELOAD jemalloc + zero:true     → nonzero=0 (effective)
#
# Mechanism: jemalloc MALLOC_CONF=zero:true makes malloc return zeroed memory —
# this gives "uninitialized read" a deterministic behavior on host tests (reads 0
# instead of stale key material).
#
# Usage: bash scripts/test_zero_on_alloc.sh   (instead of a bare cargo test)
# Depends: libjemalloc2 (/lib/x86_64-linux-gnu/libjemalloc.so.2)

JEMALLOC=/lib/x86_64-linux-gnu/libjemalloc.so.2
if [ ! -f "$JEMALLOC" ]; then
    echo "ERROR: libjemalloc2 not installed (apt install libjemalloc2)" >&2
    exit 2
fi

# Self-check: confirm zero-on-alloc is actually in effect on this machine (guards
# against "config present but ineffective" recurring)
if command -v cc >/dev/null 2>&1 && [ ! -x /tmp/.zero_on_alloc_selfcheck ]; then
    cat > /tmp/.zero_on_alloc_selfcheck.c <<'EOF'
#include <stdlib.h>
int main(void) {
    char *p1 = malloc(4096);
    for (int i = 0; i < 4096; i++) p1[i] = 0xAA;
    free(p1);
    char *p2 = malloc(4096);
    for (int i = 0; i < 4096; i++) if (p2[i] != 0) return 1;
    return 0;
}
EOF
    cc /tmp/.zero_on_alloc_selfcheck.c -o /tmp/.zero_on_alloc_selfcheck
fi
if [ -x /tmp/.zero_on_alloc_selfcheck ]; then
    if ! LD_PRELOAD="$JEMALLOC" MALLOC_CONF="zero:true" /tmp/.zero_on_alloc_selfcheck; then
        echo "ERROR: zero-on-alloc selfcheck failed — jemalloc zero:true not effective" >&2
        exit 3
    fi
fi

export LD_PRELOAD="$JEMALLOC"
export MALLOC_CONF="zero:true"
exec cargo test "$@"
