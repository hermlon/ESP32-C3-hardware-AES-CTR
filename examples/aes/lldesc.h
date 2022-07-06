#ifndef LLDESC_H
#define LLDESC_H

/*
 * https://github.com/espressif/esp-idf/blob/master/components/esp_rom/include/esp32c3/rom/lldesc.h 
 */

#include <mdk.h>

/*
 *  SLC2 DMA Desc struct, aka lldesc_t
 *
 * --------------------------------------------------------------
 * | own | EoF | sub_sof | 5'b0   | length [11:0] | size [11:0] |
 * --------------------------------------------------------------
 * |            buf_ptr [31:0]                                  |
 * --------------------------------------------------------------
 * |            next_desc_ptr [31:0]                            |
 * --------------------------------------------------------------
 */

/* this bitfield is start from the LSB!!! */
typedef struct lldesc_s {
    volatile uint32_t size  : 12,
             length: 12,
             offset: 5, /* h/w reserved 5bit, s/w use it as offset in buffer */
             sosf  : 1, /* start of sub-frame */
             eof   : 1, /* end of frame */
             owner : 1; /* hw or sw */
    volatile const uint8_t *buf;       /* point to buffer data */
    union {
        volatile uint32_t empty;
        struct lldesc_s *qe;  /* pointing to the next desc */
    };
} lldesc_t;

#endif