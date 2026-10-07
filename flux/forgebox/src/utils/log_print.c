#include "log_print.h"
#include "stdio.h"

/*
 * log_print.c - printf-backed debug printers for the SE drivers
 * (see log_print.h). SECURITY: PrintArray dumps raw bytes to the debug
 * console - never point it at key material on a provisioned device.
 */

void PrintString(char *str)
{
    printf("%s\r\n", str);
}

void PrintArray(const char *name, const uint8_t *data, uint16_t length)
{
    printf("%s[%u]:", name, (unsigned)length);
    for (uint16_t i = 0; i < length; i++) {
        printf(" %02X", data[i]);
    }
    printf("\r\n");
}
