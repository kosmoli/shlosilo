#ifndef _HELLOWORLD_TASK_H
#define _HELLOWORLD_TASK_H

#include "stdint.h"
#include "stdbool.h"

void CreateHelloWorldTask(void);

#endif

/* LVGL 全局锁：smoke 任务调 lv_* 前必须持有（见 helloworld_task.c） */
void lvgl_lock(void);
void lvgl_unlock(void);
