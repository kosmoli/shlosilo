/* shlosilo_embedded_alloc_glue.c — P6.2c: L3 内存接口
 *
 * embedded_alloc.rs 的 EmbeddedAllocator 调这两个符号。
 * helloworld 宿主：走 PSRAM heap_4（8MB，与 PoC 3 相同策略——
 * SRAM 1MB 已被 FreeRTOS/LVGL 占满，Rust alloc 全放 PSRAM）。
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "user_memory.h"

void *shlosilo_embedded_malloc(size_t size)
{
    /* P6.4 zero-on-alloc (v2-安全 §3 威胁1: 未初始化读旧密钥)：
     * heap_4/psram heap 不清零返回内存，这里统一清零。
     * 密钥类 alloc 后立刻被填充，成本可忽略；非密钥 alloc 多一次 memset 也无害。 */
    void *p = ExtMalloc(size);
    if (p != NULL) {
        memset(p, 0, size);
    }
    return p;
}

void shlosilo_embedded_free(void *ptr)
{
    ExtFree(ptr);
}
