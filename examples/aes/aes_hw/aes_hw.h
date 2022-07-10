#ifndef AES_HW_H
#define AES_HW_H

#include <mdk.h>
#include "lldesc.h"

/* Number of bytes in an AES block */
#define AES_BLOCK_BYTES     (16)

void aes_hw_encrypt_ctr(const uint8_t* key, const uint8_t* iv, const uint8_t* in, uint8_t* out, uint32_t length);
void esp_aes_dma_start(const lldesc_t *input, const lldesc_t *output);

#endif