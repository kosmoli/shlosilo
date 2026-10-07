#ifndef PRODUCT_TASK_H
#define PRODUCT_TASK_H

/* Create the product-UI boot task (product flavor; SMOKE_SCREEN=0). */
void CreateProductTask(void);

/*
 * Task 8: SE password unlock -> live key session on the product sign route
 * (the same g_key_session the plate flow signs with).
 *
 * v1 entry is the dev console ('se unlock <password>', se_smoke.c): the
 * password transits the serial console - DEVELOPMENT CONVENIENCE ONLY, the
 * product entry is the P4 UI. v1 account scope: account 0.
 *
 * Returns 0 = session live; -24 = auth failed (empty/over-long/wrong
 * password, one shot); -23 = a session is already live (close first);
 * -20 = workspace query larger than the static workspace; otherwise the
 * shlosilo_keysource_se_open_ffi error code.
 */
int ProductKeySeUnlock(const char *password);

/* Close (zeroize) the live key session, whichever source opened it (the
 * shared QR/SE teardown). Idempotent. */
void ProductKeyLock(void);

#endif
