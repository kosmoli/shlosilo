#ifndef _DECODELIB_H_
#define _DECODELIB_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "stdio.h"
#include "stdlib.h"
#include "mhscpu.h"

/************************************************************************************************/
/* Image flip type selection */
typedef enum {
    FLIP_NORMAL,    // Original image
    FLIP_VER,       // Vertical flip
    FLIP_HOZ,       // Horizontal flip
    FLIP_VERHOZ     // Vertical and horizontal flip, i.e. the original image rotated 180 degrees
} SensorImageFlipType;

/************************************************************************************************/
/* Decode code ID */
typedef enum {
    ID_NONE = 0,        /* No code decoded */
    ID_CODE128,         /*code128*/
    ID_CODE39,          /*code39*/
    ID_CODE93,          /*code93*/
    ID_EAN13,           /*EAN 13*/
    ID_EAN8,            /*EAN 8*/
    ID_UPC_A,           /*UPC_A*/
    ID_UPC_E0,          /*UPC_E0*/
    ID_UPC_E1,          /*UPC_E1*/
    ID_ISBN13,          /*ISBN13*/
    ID_ITF25,           /* Interleaved 2 of 5 */
    ID_QRCODE,          /*QRCode*/
    ID_PDF417,          /*PDF417*/
    ID_DATAMATRIX       /*DataMatrix*/
} DecodeIDType;
/* Decode result struct */
typedef struct {
    DecodeIDType id;    /* Decode result id */
    uint8_t AIM[4];     /*AIM ID*/
    uint8_t *result;    /* Base address of the buffer that holds the decode results */
    uint32_t resn;      /* Number of decode results returned */
    uint32_t maxn;      /* Maximum number of decode results the buffer can hold */
} DecodeResultTypeDef;
/************************************************************************************************/
/* Decode init config struct */
typedef struct {
    void            *pool;                  /* Memory pool base address */
    unsigned int    size;                   /* Memory pool size, >= 410 * 1024 kbyte; stack >= 4k */
    GPIO_TypeDef*   CAM_PWDN_GPIOx;         /*camera PWDN gpio */
    uint16_t        CAM_PWDN_GPIO_Pin;      /*camera PWDN gpio pin */
    GPIO_TypeDef*   CAM_RST_GPIOx;          /*camera RESET gpio */
    uint16_t        CAM_RST_GPIO_Pin;       /*camera RESET gpio pin */
    I2C_TypeDef*    CAM_I2Cx;               /* I2C instance the camera is wired to */
    uint32_t        CAM_I2CClockSpeed;      /* I2C clock rate, range [100000, 400000] */
    uint8_t (*SensorConfig)[2];             /* Base address of the custom sensor config array; NULL uses the default parameters */
    uint32_t        SensorCfgSize;          /* Size of the custom sensor config array */
} DecodeInitTypeDef;

/* Decode library init return status */
typedef enum {
    DecodeInitSuccess,              /* Decode library init succeeded */
    DecodeInitCheckError,           /* Decode library integrity check failed; contact the chip vendor */
    DecodeInitMemoryError,          /* Buffer given to the decode library is too small */
    DecodeInitSensorError,          /* Camera init failed */
} DecodeFlagTypeDef;

/* DecodeStart error return values */
enum {
    DecodeResOverflowError = -1,    /* Decode results exceed the buffer, or the buffer is smaller than 256 byte */
    DecodeImageNoDoneError = -2,    /* Image capture not finished */
    DecodeLibNoInitError   = -3,    /* Decode library not initialised */
};
/* Decode config struct */
typedef struct {
    /* 1D barcode config */
    uint32_t cfgCODE128;            /* code 128 decode setting */
    uint32_t cfgCODE39;             /* code 39 decode setting  */
    uint32_t cfgCODE93;             /* code 93 decode setting  */
    uint32_t cfgEAN13;              /* EAN13 decode setting    */
    uint32_t cfgEAN8;               /* EAN8 decode setting     */
    uint32_t cfgUPC_A;              /* UPC_A decode setting    */
    uint32_t cfgUPC_E0;             /* UPC_E0 decode setting (UPC_E with leading digit 0) */
    uint32_t cfgUPC_E1;             /* UPC_E1 decode setting (UPC_E with leading digit 1) */
    uint32_t cfgISBN13;             /* ISBN13 decode setting   */
    uint32_t cfgInterleaved2of5;    /* Interleaved 2 of 5 decode setting */
    /* 2D barcode config */
    uint32_t cfgQRCode;             /* qr code decode setting  */
    uint32_t cfgPDF417;             /* pdf 417 decode setting  */
    uint32_t cfgDataMatrix;         /* data matrix decode setting */
    /* Global decode settings */
    uint32_t cfgGlobal;             /* Global decode setting */
} DecodeConfigTypeDef;

/* Config state */
typedef enum {
    DECODE_DISABLE = 0,                 /* Config disabled */
    DECODE_ENABLE = !DECODE_DISABLE     /* Config enabled */
} DecodeStatus_t;

/* Barcode decode status config */
typedef enum {
    DE_STATUS  = 0,             /* 0bit barcode status bit: enables/disables all barcodes, 1D and 2D */
    DE_EMIT_CHECK = 1,          /* 1bit enable check-digit output (all barcodes except code128) */
    DE_ADD_CHECK = 2,           /* 2bit enable check-digit computation (code39, Interleaved2of5) */
    //code128
    DE_CODE128_ENHANCE = 7,     /* 7bit enable code128 reading enhancement, mainly for code128 whose bar/space ratio is out of spec */
    //code39
    DE_ASCII     = 3,           /* 3bit enable full ASCII output mode (code39) */
    DE_EMIT_START = 6,          /* 6bit enable code39 start character output ('*') */
    DE_EMIT_END   = 7,          /* 7bit enable code39 stop character output ('*') */
    //EAN UPC
    DE_UPC2EAN   = 4,           /* 4bit enable UPC_A to EAN13 output conversion (UPC_A) */
    DE_MUSTADDN  = 5,           /* 5bit require output of barcodes carrying add-on data (EAN13,UPC_A,EAN8,UPC_E0,UPC_E1) */
    DE_EANADDON2 = 6,           /* 6bit output the 2-digit add-on (EAN13,UPC_A,EAN8,UPC_E0,UPC_E1) */
    DE_EANADDON5 = 7,           /* 7bit output the 5-digit add-on (EAN13,UPC_A,EAN8,UPC_E0,UPC_E1) */

    DE_MIN_LEN   = 16,          /* 16bit-23bit, 8bit total: minimum decode length */
    DE_MAX_LEN   = 24           /* 24bit-31bit, 8bit total: maximum decode length */
} DeBarCodeStatus_t;

/* QRCode decode status config */
typedef enum {
    DEQR_STATUS        = 0,     /* 0bit QRCode decode enable bit */
    DEQR_MISSINGCORNER = 1,     /* 1bit QRCode missing-corner algorithm enable */
    DEQR_CURVE         = 3,     /* 3bit QRCode curved-surface decode algorithm enable */
    DEQR_ECICONFIG     = 7,     /* 16bit QRCode ECI output switch */
} DeQRCodeStatus_t;

/* Global barcode decode settings */
typedef enum {
    DEBAR_PRECISION   = 0,      /* 0bit barcode precision decode config bit */
    DECODE_ANTICOLOR  = 1,      /* 1bit enable inverse (light-on-dark) code decoding */
    DEBAR_DAMAGE      = 2,      /* 2bit decode of barcodes with damage or drawn-over lines */
    DECODE_MIRROR     = 3,      /* 3-4bit barcode (DM) mirror setting: 0/1 = normal codes, 2 = mirrored codes, 3 = both */
} DecodeGlobalStatus_t;
/****************************************************************************************************/
/**
 * Initialise the barcode config struct
 *
 */
void DecodeConfigInit(DecodeConfigTypeDef *cfg);
/**
 * Initialise the config struct recommended by BCTC conformance testing
 *
 */
void BCTCTestConfigInit(DecodeConfigTypeDef *cfg);
/****************************************************************************************************/
/**
 * Peripheral and memory pool init
 * Initialises the struct
 * Return value 1 means init succeeded, 0 means init failed
 */
DecodeFlagTypeDef DecodeInit(DecodeInitTypeDef* DecodeInitStruct);

/**
 *  Start decoding
 *  Returns the number of decode results
 *  Returns 0 when decoding fails
 *       DecodeResOverflowError: results exceed the given buffer range, or the given decode buffer is smaller than 256 byte
 *       DecodeImageNoDoneError: image capture not finished
 *       DecodeLibNoInitError: not initialised, or init failed
 */
int DecodeStart(DecodeConfigTypeDef *cfg, DecodeResultTypeDef *res);

/**
 * Enable DCMI image capture
 *
 *
 */
void DecodeDcmiStart(void);

/**
 * Check whether image capture has finished
 * Must be called from the completion interrupt (DCMI_CallBackFrame())
 * Return 0 = capture not finished, 1 = capture finished; optional call
 */
int DecodeDcmiFinish(void);

/**
 * Clear all decode buffer flags so the currently stored image buffer data is invalidated
 *
 */
void CleanDecodeBuffFlag(void);

/**
 * Check whether all decode buffers are currently idle
 * Returns FALSE when every image buffer is invalid and a new capture is required
 * Returns TRUE when at least one image buffer is not invalid
 */
Boolean GetDecodeBuffFlag(void);

/**
 * DCMI_IT_FRAME interrupt callback
 */
void DCMI_CallBackFrame(void);

/**
 * Set the image flip
 *
 */
void SetSensorImageFlip(SensorImageFlipType fliptype);

/**
 * Release the software and hardware resources used for decoding
 *
 */
void CloseDecode(void);

/**
  * Get the current algorithm version number
  * bits 16-31 major version, bits 8-15 minor version, bits 0-7 patch version
  */
uint32_t GetDecodeLibVerison(void);

/**
  * Get Gray array of image,640*480
  *
  * const char * const GetImageBuffAddr(void) returns the image address: 640 * 480 luma-only data starting there;
  * valid only once the current frame capture has finished and before that frame has entered decoding — it returns the image base address in that window, NULL in every other state;
  * callers must first declare: const char * const GetImageBuffAddr(void);
  *
  */
char *GetImageBuffAddr(void);

#ifdef __cplusplus
}
#endif

#endif
