#ifndef _SHLOSILO_SMOKE_TASK_H
#define _SHLOSILO_SMOKE_TASK_H

void ShlosiloSmokeTask(void *argument);

#endif

/* Task factory: creates the smoke diagnostics thread (called from
 * helloworld_task after the LVGL container is ready). */
void CreateShlosiloSmokeTask(void);
