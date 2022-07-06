#ifndef COMMON_H
#define COMMON_H

typedef struct param {
	uint8_t nonce[12];
	uint8_t ctr[4];
	uint8_t rk[2*11*16];
} param;

#define NUM_BLOCKS    200
#define INPUT_LENGTH  (NUM_BLOCKS*16)
#define OUTPUT_LENGTH (((INPUT_LENGTH+32)/32)*32)

#endif