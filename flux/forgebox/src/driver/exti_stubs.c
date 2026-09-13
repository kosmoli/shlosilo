/* exti_stubs.c — ForgeBox helloworld EXTI 依赖桩
 *
 * drv_exti.c 的中断处理函数引用生产固件的四个业务 handler（tamper/SD 卡/
 * 按键/USB 插入）。helloworld 是诊断固件，没有这些子系统——提供 no-op 桩，
 * 让 EXTI 中断框架（含 PF1 触摸 INT）按 keystone 生产方式初始化。
 * tamper 事件在 helloworld 中仅打印（生产固件做擦除+重启，绝不复刻）。 */

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
