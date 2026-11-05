/* exti_stubs.c — ForgeBox helloworld EXTI dependency stubs
 *
 * The interrupt handlers in drv_exti.c reference four business handlers from
 * the production firmware (tamper / SD card / button / USB insertion).
 * helloworld is a diagnostic firmware and has none of those subsystems — these
 * no-op stubs let the EXTI interrupt framework (including the PF1 touch INT)
 * initialise the same way the keystone production build does.
 * In helloworld a tamper event is only printed (the production firmware erases
 * and reboots — never replicate that). */

#include <stdint.h>
#include <stdio.h>

__attribute__((weak)) void TamperIntHandler(void)
{
    printf("tamper int (stub: ignored)\r\n");
}

__attribute__((weak)) void SdCardIntHandler(void)
{
}

__attribute__((weak)) void ButtonIntHandler(void)
{
}

__attribute__((weak)) void ChangerInsertHandler(void)
{
}
