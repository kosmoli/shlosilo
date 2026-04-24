#include "helloworld_task.h"
#include "stdio.h"
#include "cmsis_os.h"
#include "mhscpu.h"
#include "mhscpu_wdt.h"
#include "hal_lcd.h"
#include "lvgl.h"
#include "stdlib.h"
#include "mhscpu_gpio.h"

#define LVGL_TICK_MS    5
#define LVGL_GRAM_PIXEL (LCD_DISPLAY_WIDTH * LCD_DISPLAY_HEIGHT / 10)

// Power button configuration
#define BUTTON_INT_PORT                 GPIOE
#define BUTTON_INT_PIN                  GPIO_Pin_14
#define BUTTON_LONG_PRESS_MS            3000
#define BUTTON_CHECK_INTERVAL_MS        50
#define WDT_FEED_INTERVAL_MS            100

// Snake game constants
#define GRID_SIZE       20
#define GRID_WIDTH      (LCD_DISPLAY_WIDTH / GRID_SIZE)   // 24
#define GRID_HEIGHT     (LCD_DISPLAY_HEIGHT / GRID_SIZE)  // 40
#define MAX_SNAKE_LEN   (GRID_WIDTH * GRID_HEIGHT)
#define GAME_SPEED_MS   150

#define HEAD_COLOR   lv_color_hex(0x0000FF)
#define BODY_COLOR   lv_color_hex(0x0000AA)
#define FOOD_COLOR   lv_color_hex(0xF5870A)

// Grid calculation: 160/20=8, 78/20=3.9
#define LOGO_GRID_X      8
#define LOGO_GRID_Y      3
#define LOGO_GRID_WIDTH  8
#define LOGO_GRID_HEIGHT 8

typedef struct {
    int16_t x;
    int16_t y;
} Point;

typedef enum {
    DIR_UP = 0,
    DIR_RIGHT,
    DIR_DOWN,
    DIR_LEFT
} Direction;

static void HelloWorldTask(void *argument);
static void LvglTickTimerFunc(void *argument);
static void LcdFlush(struct _lv_disp_drv_t *disp_drv, const lv_area_t *area, lv_color_t *color_p);
static void SnakeGameInit(void);
static void SnakeGameUpdate(void);
static void SnakeGameDraw(void);
static void GenerateFood(void);
static Direction GetAIDirection(void);
static bool IsSafePosition(int16_t x, int16_t y);
static bool IsDirectionSafe(Direction dir);
static bool IsInLogoArea(int16_t x, int16_t y);
static bool IsInLabelArea(int16_t x, int16_t y);
static void PowerButtonInit(void);
static void PowerButtonCheck(void);
static void RestartDevice(void);

osThreadId_t g_helloWorldTaskHandle;
osTimerId_t g_lvglTickTimer;

static lv_disp_draw_buf_t g_dispBuf;
static lv_color_t g_lvglCache[LCD_DISPLAY_WIDTH * LCD_DISPLAY_HEIGHT / 10];
static lv_obj_t *g_container;
static lv_obj_t *g_hintLabel;
static lv_obj_t *g_snakeObjs[MAX_SNAKE_LEN];
static lv_obj_t *g_foodObj;
static lv_obj_t *g_logoObj;
static lv_obj_t *g_helloLabel;
LV_IMG_DECLARE(imgDevLogo);

// Snake game state
static Point g_snake[MAX_SNAKE_LEN];
static uint16_t g_snakeLen;
static Direction g_direction;
static Point g_food;
static uint32_t g_score;
static bool g_gameOver;

static uint32_t g_buttonPressStartTime = 0;
static bool g_buttonPressed = false;

LV_FONT_DECLARE(openSansEnText);

void CreateHelloWorldTask(void)
{
    const osThreadAttr_t taskAttr = {
        .name = "snake_game",
        .stack_size = 1024 * 32,
        .priority = osPriorityHigh,
    };
    g_helloWorldTaskHandle = osThreadNew(HelloWorldTask, NULL, &taskAttr);
    g_lvglTickTimer = osTimerNew(LvglTickTimerFunc, osTimerPeriodic, NULL, NULL);
}

static void HelloWorldTask(void *argument)
{
    printf("Snake Game Task started\n");
    
    static lv_disp_drv_t dispDrv;
    
    // Initialize LVGL
    lv_init();
    printf("LVGL initialized\n");
    
    // Initialize display buffer
    lv_disp_draw_buf_init(&g_dispBuf, g_lvglCache, NULL, LVGL_GRAM_PIXEL);
    printf("Display buffer initialized\n");
    
    // Initialize and register display driver
    lv_disp_drv_init(&dispDrv);
    dispDrv.flush_cb = LcdFlush;
    dispDrv.draw_buf = &g_dispBuf;
    dispDrv.hor_res = LCD_DISPLAY_WIDTH;
    dispDrv.ver_res = LCD_DISPLAY_HEIGHT;
    lv_disp_drv_register(&dispDrv);
    printf("Display driver registered\n");
    
    // Start LVGL tick timer
    osTimerStart(g_lvglTickTimer, LVGL_TICK_MS);
    printf("Timer started\n");
    
    // Create black background container
    g_container = lv_obj_create(lv_scr_act());
    lv_obj_set_size(g_container, LCD_DISPLAY_WIDTH, LCD_DISPLAY_HEIGHT);
    lv_obj_set_style_bg_color(g_container, lv_color_hex(0x000000), 0);
    lv_obj_set_style_border_width(g_container, 0, 0);
    lv_obj_set_style_radius(g_container, 0, 0);
    lv_obj_set_style_pad_all(g_container, 0, 0);
    lv_obj_clear_flag(g_container, LV_OBJ_FLAG_SCROLLABLE);
    printf("Container created\n");
    
    // Create score label
    // g_scoreLabel = lv_label_create(lv_scr_act());
    // lv_obj_align(g_scoreLabel, LV_ALIGN_TOP_MID, 0, 5);
    // lv_obj_set_style_text_color(g_scoreLabel, lv_color_hex(0xFFFFFF), 0);
    // lv_label_set_text(g_scoreLabel, "Score: 0");
    // printf("Score label created\n");

    g_hintLabel = lv_label_create(lv_scr_act());
    lv_obj_align(g_hintLabel, LV_ALIGN_BOTTOM_MID, 0, -5);
    lv_obj_set_style_text_color(g_hintLabel, lv_color_hex(0xFFFFFF), 0);
    lv_obj_set_width(g_hintLabel, LCD_DISPLAY_WIDTH - 20);
    lv_obj_set_style_text_font(g_hintLabel, &openSansEnText, 0);
    const char *hintText = "To flash your next firmware:\n"
                           "1. Hold power key to restart\n"
                           "2. Keep holding until Recovery Mode appears";
    lv_label_set_long_mode(g_hintLabel, LV_LABEL_LONG_WRAP);
    lv_label_set_text(g_hintLabel, hintText);

    // Create snake segments
    for (uint16_t i = 0; i < MAX_SNAKE_LEN; i++) {
        g_snakeObjs[i] = lv_obj_create(g_container);
        lv_obj_set_size(g_snakeObjs[i], GRID_SIZE - 2, GRID_SIZE - 2);
        lv_obj_set_style_bg_color(g_snakeObjs[i], BODY_COLOR, 0);
        lv_obj_set_style_bg_opa(g_snakeObjs[i], LV_OPA_COVER, 0);
        lv_obj_set_style_border_width(g_snakeObjs[i], 0, 0);
        lv_obj_set_style_border_opa(g_snakeObjs[i], LV_OPA_TRANSP, 0);
        lv_obj_set_style_radius(g_snakeObjs[i], 3, 0);
        lv_obj_set_style_pad_all(g_snakeObjs[i], 0, 0);
        lv_obj_add_flag(g_snakeObjs[i], LV_OBJ_FLAG_HIDDEN);
    }
    printf("Snake objects created\n");
    
    // Create food object
    g_foodObj = lv_obj_create(g_container);
    lv_obj_set_size(g_foodObj, GRID_SIZE - 4, GRID_SIZE - 4);
    lv_obj_set_style_bg_color(g_foodObj, FOOD_COLOR, 0);
    lv_obj_set_style_border_width(g_foodObj, 0, 0);
    lv_obj_set_style_radius(g_foodObj, GRID_SIZE / 2, 0);
    printf("Food object created\n");
    
    g_logoObj = lv_img_create(g_container);
    lv_img_set_src(g_logoObj, &imgDevLogo);
    lv_obj_align(g_logoObj, LV_ALIGN_TOP_MID, 0, 78);

    PowerButtonInit();
    
    SnakeGameInit();
    printf("Game initialized\n");
    
    uint32_t lastUpdate = osKernelGetTickCount();
    uint32_t lastButtonCheck = osKernelGetTickCount();
    uint32_t lastWdtFeed = osKernelGetTickCount();
    
    // Main game loop
    while (1) {
        uint32_t now = osKernelGetTickCount();

        if (now - lastWdtFeed >= WDT_FEED_INTERVAL_MS) {
            lastWdtFeed = now;
            WDT_ReloadCounter();
        }

        if (now - lastButtonCheck >= BUTTON_CHECK_INTERVAL_MS) {
            lastButtonCheck = now;
            PowerButtonCheck();
        }

        if (now - lastUpdate >= GAME_SPEED_MS) {
            lastUpdate = now;
            
            if (!g_gameOver) {
                SnakeGameUpdate();
                SnakeGameDraw();
            } else {
                printf("Game Over! Score: %d. Restarting...\n", g_score);
                for (uint32_t t = 0; t < 2000; t += 50) {
                    WDT_ReloadCounter();
                    osDelay(50);
                }
                SnakeGameInit();
            }
        }
        
        lv_timer_handler();
        osDelay(5);
    }
}

static void SnakeGameInit(void)
{
    printf("Initializing Snake Game\n");
    
    g_snakeLen = 3;
    g_direction = DIR_RIGHT;
    g_score = 0;
    g_gameOver = false;
    
    // Initialize snake in the middle
    g_snake[0].x = GRID_WIDTH / 2;
    g_snake[0].y = GRID_HEIGHT / 2;
    g_snake[1].x = g_snake[0].x - 1;
    g_snake[1].y = g_snake[0].y;
    g_snake[2].x = g_snake[0].x - 2;
    g_snake[2].y = g_snake[0].y;
    
    GenerateFood();
    
    printf("Snake initialized at (%d, %d), Food at (%d, %d)\n", 
           g_snake[0].x, g_snake[0].y, g_food.x, g_food.y);
}

static void GenerateFood(void)
{
    bool validPos = false;
    
    while (!validPos) {
        g_food.x = lv_rand(0, GRID_WIDTH - 1);
        g_food.y = lv_rand(0, GRID_HEIGHT - 1);
        
        if (IsInLogoArea(g_food.x, g_food.y)) {
            continue;
        }
        
        if (IsInLabelArea(g_food.x, g_food.y)) {
            continue;
        }
        
        // Check if food is not on snake
        validPos = true;
        for (uint16_t i = 0; i < g_snakeLen; i++) {
            if (g_snake[i].x == g_food.x && g_snake[i].y == g_food.y) {
                validPos = false;
                break;
            }
        }
    }
    
    printf("New food generated at (%d, %d)\n", g_food.x, g_food.y);
}

static bool IsInLogoArea(int16_t x, int16_t y)
{
    return (x >= LOGO_GRID_X && x < LOGO_GRID_X + LOGO_GRID_WIDTH &&
            y >= LOGO_GRID_Y && y < LOGO_GRID_Y + LOGO_GRID_HEIGHT);
}

static bool IsInLabelArea(int16_t x, int16_t y)
{
    // Check hintLabel area (bottom label)
    if (g_hintLabel != NULL) {
        lv_coord_t label_x = lv_obj_get_x(g_hintLabel);
        lv_coord_t label_y = lv_obj_get_y(g_hintLabel);
        lv_coord_t label_w = lv_obj_get_width(g_hintLabel);
        lv_coord_t label_h = lv_obj_get_height(g_hintLabel);
        int16_t grid_x1 = label_x / GRID_SIZE;
        int16_t grid_y1 = label_y / GRID_SIZE;
        int16_t grid_x2 = (label_x + label_w) / GRID_SIZE + 1;
        int16_t grid_y2 = (label_y + label_h) / GRID_SIZE + 1;
        
        if (x >= grid_x1 && x < grid_x2 && y >= grid_y1 && y < grid_y2) {
            return true;
        }
    }
    
    // Check g_helloLabel area (if exists)
    if (g_helloLabel != NULL) {
        lv_coord_t label_x = lv_obj_get_x(g_helloLabel);
        lv_coord_t label_y = lv_obj_get_y(g_helloLabel);
        lv_coord_t label_w = lv_obj_get_width(g_helloLabel);
        lv_coord_t label_h = lv_obj_get_height(g_helloLabel);
        int16_t grid_x1 = label_x / GRID_SIZE;
        int16_t grid_y1 = label_y / GRID_SIZE;
        int16_t grid_x2 = (label_x + label_w) / GRID_SIZE + 1;
        int16_t grid_y2 = (label_y + label_h) / GRID_SIZE + 1;

        if (x >= grid_x1 && x < grid_x2 && y >= grid_y1 && y < grid_y2) {
            return true;
        }
    }
    
    return false;
}

static bool IsSafePosition(int16_t x, int16_t y)
{
    // Wrap coordinates
    if (x < 0) x = GRID_WIDTH - 1;
    else if (x >= GRID_WIDTH) x = 0;
    if (y < 0) y = GRID_HEIGHT - 1;
    else if (y >= GRID_HEIGHT) y = 0;
    
    // Check if position is in logo area
    if (IsInLogoArea(x, y)) {
        return false;
    }
    
    // Check if position is in label area
    if (IsInLabelArea(x, y)) {
        return false;
    }
    
    // Check if position collides with snake body
    for (uint16_t i = 0; i < g_snakeLen; i++) {
        if (g_snake[i].x == x && g_snake[i].y == y) {
            return false;
        }
    }
    return true;
}

static bool IsDirectionSafe(Direction dir)
{
    Point head = g_snake[0];
    Point nextPos = head;
    
    switch (dir) {
        case DIR_UP:    nextPos.y--; break;
        case DIR_DOWN:  nextPos.y++; break;
        case DIR_LEFT:  nextPos.x--; break;
        case DIR_RIGHT: nextPos.x++; break;
    }
    
    return IsSafePosition(nextPos.x, nextPos.y);
}

static Direction GetAIDirection(void)
{
    Point head = g_snake[0];
    int16_t dx = g_food.x - head.x;
    int16_t dy = g_food.y - head.y;
    
    // Consider wrapping for shortest path (穿墙最短路径)
    if (abs(dx) > GRID_WIDTH / 2) {
        dx = dx > 0 ? dx - GRID_WIDTH : dx + GRID_WIDTH;
    }
    if (abs(dy) > GRID_HEIGHT / 2) {
        dy = dy > 0 ? dy - GRID_HEIGHT : dy + GRID_HEIGHT;
    }
    
    // Try directions in order of priority
    Direction priorities[4];
    int priorityCount = 0;
    
    // Add primary directions based on distance
    if (abs(dx) > abs(dy)) {
        // Horizontal first
        if (dx > 0) {
            priorities[priorityCount++] = DIR_RIGHT;
        } else if (dx < 0) {
            priorities[priorityCount++] = DIR_LEFT;
        }
        if (dy > 0) {
            priorities[priorityCount++] = DIR_DOWN;
        } else if (dy < 0) {
            priorities[priorityCount++] = DIR_UP;
        }
    } else {
        // Vertical first
        if (dy > 0) {
            priorities[priorityCount++] = DIR_DOWN;
        } else if (dy < 0) {
            priorities[priorityCount++] = DIR_UP;
        }
        if (dx > 0) {
            priorities[priorityCount++] = DIR_RIGHT;
        } else if (dx < 0) {
            priorities[priorityCount++] = DIR_LEFT;
        }
    }
    
    // Add remaining directions
    Direction allDirs[4] = {DIR_UP, DIR_RIGHT, DIR_DOWN, DIR_LEFT};
    for (int i = 0; i < 4; i++) {
        bool found = false;
        for (int j = 0; j < priorityCount; j++) {
            if (allDirs[i] == priorities[j]) {
                found = true;
                break;
            }
        }
        if (!found) {
            priorities[priorityCount++] = allDirs[i];
        }
    }
    
    // Try each direction in priority order
    for (int i = 0; i < priorityCount; i++) {
        Direction dir = priorities[i];
        
        // Don't reverse direction
        if ((g_direction == DIR_UP && dir == DIR_DOWN) ||
            (g_direction == DIR_DOWN && dir == DIR_UP) ||
            (g_direction == DIR_LEFT && dir == DIR_RIGHT) ||
            (g_direction == DIR_RIGHT && dir == DIR_LEFT)) {
            continue;
        }
        
        // Check if direction is safe
        if (IsDirectionSafe(dir)) {
            return dir;
        }
    }
    
    // If no safe direction found, keep current direction
    return g_direction;
}

static void SnakeGameUpdate(void)
{
    // Get AI direction
    g_direction = GetAIDirection();
    
    // Calculate new head position
    Point newHead = g_snake[0];
    
    switch (g_direction) {
        case DIR_UP:
            newHead.y--;
            break;
        case DIR_DOWN:
            newHead.y++;
            break;
        case DIR_LEFT:
            newHead.x--;
            break;
        case DIR_RIGHT:
            newHead.x++;
            break;
    }
    
    // Wrap around edges (穿墙模式)
    if (newHead.x < 0) {
        newHead.x = GRID_WIDTH - 1;
    } else if (newHead.x >= GRID_WIDTH) {
        newHead.x = 0;
    }
    
    if (newHead.y < 0) {
        newHead.y = GRID_HEIGHT - 1;
    } else if (newHead.y >= GRID_HEIGHT) {
        newHead.y = 0;
    }
    
    if (IsInLogoArea(newHead.x, newHead.y)) {
        g_gameOver = true;
        printf("Hit logo at (%d, %d)!\n", newHead.x, newHead.y);
        return;
    }
    
    if (IsInLabelArea(newHead.x, newHead.y)) {
        g_gameOver = true;
        printf("Hit label at (%d, %d)!\n", newHead.x, newHead.y);
        return;
    }
    
    // Check self collision
    for (uint16_t i = 0; i < g_snakeLen; i++) {
        if (g_snake[i].x == newHead.x && g_snake[i].y == newHead.y) {
            g_gameOver = true;
            return;
        }
    }
    
    // Check if food eaten
    bool ateFood = (newHead.x == g_food.x && newHead.y == g_food.y);
    
    if (ateFood) {
        g_score++;
        g_snakeLen++;
        printf("Food eaten! Score: %d, Length: %d\n", g_score, g_snakeLen);
        GenerateFood();
    }
    
    // Move snake body
    for (int16_t i = g_snakeLen - 1; i > 0; i--) {
        g_snake[i] = g_snake[i - 1];
    }
    
    // Update head
    g_snake[0] = newHead;
}

static void SnakeGameDraw(void)
{
    // Update snake segments
    for (uint16_t i = 0; i < MAX_SNAKE_LEN; i++) {
        if (i < g_snakeLen) {
            // Show and position this segment
            lv_obj_clear_flag(g_snakeObjs[i], LV_OBJ_FLAG_HIDDEN);
            lv_obj_set_pos(g_snakeObjs[i], 
                          g_snake[i].x * GRID_SIZE + 1, 
                          g_snake[i].y * GRID_SIZE + 1);
            
            if (i == 0) {
                lv_obj_set_style_bg_color(g_snakeObjs[i], HEAD_COLOR, 0);
            } else {
                lv_obj_set_style_bg_color(g_snakeObjs[i], BODY_COLOR, 0);
            }
        } else {
            // Hide unused segments
            lv_obj_add_flag(g_snakeObjs[i], LV_OBJ_FLAG_HIDDEN);
        }
    }
    
    // Update food position
    lv_obj_set_pos(g_foodObj, 
                   g_food.x * GRID_SIZE + 2, 
                   g_food.y * GRID_SIZE + 2);
}

static void LvglTickTimerFunc(void *argument)
{
    lv_tick_inc(LVGL_TICK_MS);
}

static void LcdFlush(struct _lv_disp_drv_t *disp_drv, const lv_area_t *area, lv_color_t *color_p)
{
    LcdDraw(area->x1, area->y1, area->x2, area->y2, (uint16_t *)color_p);
    while (LcdBusy()) {
        osDelay(1);
    }
    lv_disp_flush_ready(disp_drv);
}

static void PowerButtonInit(void)
{
    GPIO_InitTypeDef gpioInit = {0};

    SYSCTRL_APBPeriphClockCmd(SYSCTRL_APBPeriph_GPIO, ENABLE);
    gpioInit.GPIO_Pin = BUTTON_INT_PIN;
    gpioInit.GPIO_Mode = GPIO_Mode_IPU;
    gpioInit.GPIO_Remap = GPIO_Remap_1;
    GPIO_Init(BUTTON_INT_PORT, &gpioInit);
}

static void PowerButtonCheck(void)
{
    uint32_t now = osKernelGetTickCount();
    bool pressed = (GPIO_ReadInputDataBit(BUTTON_INT_PORT, BUTTON_INT_PIN) == Bit_RESET);

    if (!pressed) {
        g_buttonPressed = false;
        return;
    }

    if (!g_buttonPressed) {
        g_buttonPressed = true;
        g_buttonPressStartTime = now;
        return;
    }

    if (now - g_buttonPressStartTime >= BUTTON_LONG_PRESS_MS) {
        RestartDevice();
    }
}

static void RestartDevice(void)
{
    printf("Power button long press detected, restarting...\n");
    NVIC_SystemReset();
}
