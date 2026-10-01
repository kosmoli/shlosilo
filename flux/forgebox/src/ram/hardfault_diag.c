/* hardfault_diag.c — K2-D 诊断：真 HardFault 处理器
 *
 * 此前 HardFault 落到 startup 的 weak Default_Handler（死循环）→ WDT 2s
 * 复位，故障信息全丢（export 对齐事故、cn5 后崩溃两次盲刷的教训）。
 * 这里捕获 fault：读 SCB 故障状态寄存器 + 从栈帧取 stacked PC/LR，写入
 * .diag_noinit 保留区，然后主动 WDT 复位重启。
 * 重启后 smoke task 开头读该区并把寄存器打到屏幕。
 *
 * 2026-09-30 修复：记录区原在 0x2000F004（注释称"0x2000F000 未被 .bss
 * 占用"），实际 g_lvglCache 早已覆盖该地址，启动清 .bss 时把记录清掉——
 * 诊断从未生效过。现移入 mh1903b.ld 的 .diag_noinit（0x20098000，NOLOAD，
 * 启动不清零、WDT 暖复位保留）。
 */
#include <stdint.h>
#include <string.h>
#include "mhscpu.h"

/* 复位后由 smoke 读取。布局: [magic][cfsr][hfsr][bfar][pc][lr][xpsr] */
#define FAULT_MAGIC 0x464C5444U /* 'FLTD' */
volatile uint32_t g_fault_log[7] __attribute__((section(".diag_noinit")));

/* naked: 只取 MSP 栈帧（smoke task 异常时自动压栈的 8 字） */
__attribute__((naked)) void HardFault_Handler(void)
{
    __asm__ volatile(
        "tst   lr, #4          \n"
        "ite   eq              \n"
        "mrseq r0, msp         \n"
        "mrsne r0, psp         \n"
        "b     hardfault_capture\n");
}

void hardfault_capture(uint32_t *stack) __attribute__((noreturn));
void hardfault_capture(uint32_t *stack)
{
    g_fault_log[0] = FAULT_MAGIC;
    g_fault_log[1] = SCB->CFSR;
    g_fault_log[2] = SCB->HFSR;
    g_fault_log[3] = SCB->BFAR;
    g_fault_log[4] = stack[6]; /* stacked PC */
    g_fault_log[5] = stack[5]; /* stacked LR */
    g_fault_log[6] = stack[7]; /* stacked xPSR */

    /* 主动复位：WDT 最短窗口即可 */
    WDT_ModeConfig(WDT_Mode_CPUReset);
    WDT_SetReload(0x10U);
    WDT_ReloadCounter();
    WDT_Enable();
    for (;;) {
        __asm__ volatile("wfi");
    }
}
