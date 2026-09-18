#ifndef SHLOSILO_UI_H
#define SHLOSILO_UI_H

/* Product UI (D1) - direct-write renderer, see shlosilo_ui.c.
 *
 * UiInit(): allocate the canvas + flush band (SRAM heap).
 * UiShow(): draw the current page and flush it to the panel.
 * UiTick(): poll touch and handle button presses (call every ~40 ms).
 */
void UiInit(void);
void UiShow(void);
void UiTick(void);

#endif
