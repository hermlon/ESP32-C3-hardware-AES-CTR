#ifndef AES_HW_H
#define AES_HW_H

#include <mdk.h>
#include "common.h"

void aes_hw_encrypt_ctr(const param* p, const uint8_t* in, uint8_t* out, uint32_t len);

#endif