# pico2 硬件引脚表 — SpotPear RP2350A-Linux-Pro（shlosilo 核实版）

> 核实日期 2026-09-16。方法 = **双通道 + 例程互证**：
> ① 原理图 PDF 文本层带坐标取证（`pdftotext -bbox`，926 词；MCU 侧 GPIO 编号与外设侧网名按**同 y 行**配对）；
> ② 400 DPI 局部渲染目视（关键行逐条仲裁）；
> ③ 厂商 C 例程交叉验证（`C/01-LCD`、`C/02-CAM`、`C/04`）。
> 自洽性检查：LCD/TP/CAM/SD 四组 GPIO 均与 RP2350 硬件功能表吻合（SPI1=14/15、I2C1=26/27、I2C0=28/29、SPI0=20-23）。
> 工具：`scripts/sch_pins.py`。原始资料：`~/codebases/spotpear-rp2350/`（原理图 `rp2350a-linux-pro.pdf` + Gitee 官方例程）。

## 外设引脚（定稿）

| 外设 | 信号 | GPIO | 备注 |
|---|---|---|---|
| LCD ST7789V2（SPI1） | SCK | GP14 | |
| | MOSI | GP15 | |
| | D/C | GP12 | |
| | CS | GP13 | |
| | RST | GP16 | 经 R5（0R）串联；R103 10K 上拉 + C104 100nF（复位 RC） |
| | BL | GP18 | |
| | MISO | — | 未接 MCU（写-only 不需要；P2 上悬空） |
| 触摸 CST816D（I2C1, addr 0x15） | SDA | GP26 | |
| | SCL | GP27 | |
| | INT | GP17 | |
| | RST | **GP16** | 图上经 R0（0R）与 LCD_RST 共享 GP16。⚠️ 例程写 19——但 **GP19 实为 PSRAM CS**（R30 0R→PSRAM SS，既有事实），判例程对本板无效；上板仍复核（见「待验证点」） |
| 摄像头 OV5640（DVP+PIO） | D0–D7 | GP0–GP7 | PIO 捕获 11 个连续脚（基准脚 0） |
| | VSYNC | GP8 | |
| | HREF/HSYNC | GP9 | |
| | PCLK | GP10 | |
| | XCLK | GP11 | PWM 时钟输出（例程设 24–37 MHz，实测定） |
| | PWDN | GP24 | |
| | RST | — | 仅 RC（10K 上拉），无 GPIO 直连 |
| | SCCB SDA | GP28 | I2C0（例程头名写 `I2C1_*`，按硬件映射即 I2C0） |
| | SCCB SCL | GP29 | I2C0；R44/R45 1K 上拉至 CSI_3V3 |
| TF/SD（SPI0） | MISO | GP20 | R38–R41 10K 上拉 |
| | CS | GP21 | |
| | CLK | GP22 | |
| | MOSI | GP23 | |
| 按键 | K1 | — | BOOT（BOOTSEL） |
| | K2 | — | RUN（复位） |
| LED | LED2 | GP25 | 470R 限流 |
| | LED3 | 待核实 | 疑电源/充电指示 |

## 连接器（供接线核对）

- **P1 摄像头 24-pin FPC**：22=D2、21=D1、20=D3、19=D0、18=D4、17=PCLK、16=D5、14=D6、13=XCLK、12=D7、9=HSYNC、8=PWDN、7=VSYNC、6=CAM_RST、5=SCL(TWI_SCK)、3=SDA(TWI_SDA)、1=STROBE/NC；其余 = 电源/GND（CSI_3V3/2V8/1V2 分配详见原理图）。
- **P2 显示+触摸 18-pin FPC**：2=BL、4=SCK、5=MOSI、6=MISO、7=D/C、8=RST、9=CS、10=SD_CS-1（经 R4 0R 接 SD_CS 网络）、12=TP_RST、13=TP_SCL、14=TP_SDA、15=TP_INT；1/3/11/16/17/18 = 电源/GND（未逐一追）。

## 板级其他

- **Flash**：W25Q16JVUXIQ（2 MB QSPI，U2）。
- **PSRAM**：板载（QSPI 共总线，独立 CS：GPIO19 → R30 0R → PSRAM SS；schematic 值文本仅标 "PSRAM"）。
- 2× LDO（U8/U9）供摄像头 CSI_2V8 / CSI_1V2。
- 电池 ADC：**无**（例程 `BAT_ADC_PIN 28` 对本板无效——GP28 是摄像头 SCCB SDA）。
- **无 IMU**（早前 QMI8658 之说为误报）。

## 待验证点（P0 上板清单）

1. **TP_RST**：按 GP16 初始化（与 LCD_RST 共享）——若触摸不应答再排查（勿动 GP19=PSRAM CS）。
2. **LED3** 的实际 GPIO（疑非 GPIO，为电源指示）。
3. **SD_CS 走线**：TF 侧 CS=GP21，且该网络经 R4（0R）续至 "SD_CS-1"→P2.10（schematic 原样记录；功能影响待上板确认）。

## 取证过程要点（防复踩）

- ⚠️ **整页视觉分析会编造**：本次实测两起（谎称原理图由 LCEDA 绘制并编造整套引脚映射；谎报板载 IMU）——引脚取证只认「文本层坐标 + 局部高清目视」双通道，且以官方例程/硬件功能表自洽为准。
- ⚠️ **例程 ≠ 板子**：`Arduino/RP2350-Touch-LCD-2` 是另一款独立 2" 触摸模块产品（RST=20、I2C=12/13 等）——**勿参考**；参考只用 `C/01`、`C/02`、`C/04`。
- 原理图每根信号线两侧各有一个文本：MCU 侧 = GPIO 编号（棕色）、外设侧 = 功能网名（蓝色）——**同 y 行配对**（±0.5 pt）；行内可能串 0R/RC（R5/R0/R4）。
