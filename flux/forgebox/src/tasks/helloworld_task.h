#ifndef _HELLOWORLD_TASK_H
#define _HELLOWORLD_TASK_H

#include "stdint.h"
#include "stdbool.h"

void CreateHelloWorldTask(void);

#endif

/* LVGL global lock: the smoke task must hold it before calling lv_* (see helloworld_task.c) */
void lvgl_lock(void);
void lvgl_unlock(void);
