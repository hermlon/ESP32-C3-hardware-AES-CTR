#ifndef LLDESC_H
#define LLDESC_H

#include <mdk.h>

/*
 * adapted from https://github.com/espressif/esp-idf/blob/master/components/esp_rom/include/esp32c3/rom/lldesc.h 
 */
typedef struct lldesc_s {
    volatile uint32_t size  : 12,
             length: 12,
             reserved_1: 4,
             err_eof: 1,
             reserved_2: 1,
             suc_eof: 1,
             owner : 1;
    /* point to buffer data */
    volatile const uint8_t *buf; 
    union {
        volatile uint32_t empty;
        /* pointing to the next desc */
        struct lldesc_s *qe;
    };
} lldesc_t;

#endif