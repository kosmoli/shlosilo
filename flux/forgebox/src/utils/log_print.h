#ifndef _LOG_PRINT_H
#define _LOG_PRINT_H

/*
 * log_print.h - minimal shlosilo port of keystone3's debug-print surface.
 * The in-tree SE drivers (drv_atecc608b.c / drv_ds28s60.c) include this
 * header; only the array/string printers they actually call are provided.
 * (keystone3 src/log_print.h carried a larger surface tied to their Rust
 * memory logger - not ported, not referenced here.)
 */

#include "stdint.h"
#include "stdbool.h"

void PrintString(char *str);
void PrintArray(const char *name, const uint8_t *data, uint16_t length);
void PrintU16Array(const char *name, const uint16_t *data, uint16_t length);

#endif
