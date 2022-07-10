#include "aes_hw.h"

#include "common.h"

#define GDMA_CHN 0

/* receive from AES */
static lldesc_t block_in_desc = {
    .size = 4096-4,
    .suc_eof = 0,
    .owner = 1,
    .qe = NULL
};

/* transmit to AES */
static lldesc_t block_out_desc = {
    .size = 4096-4,
    .suc_eof = 1,
    .owner = 1,
    .qe = NULL
};

/* for debugging: enable all interrupts first:
 * REG_WRITE((C3_GDMA + 0x0008), 0xffff); */
void print_status_regs(int num) {
    uint8_t n = GDMA_CHN;
    printf("(%d)\n", num);
    
    uint32_t interrupt = REG_READ(C3_GDMA + 0x04 + (16*n));
    printf("INT: %p\n", (void*)interrupt);
    printf("len: %d\n", block_in_desc.length);
    printf("eof: %d\n", block_in_desc.suc_eof);
    printf("own: %d\n", block_in_desc.owner);

    uint32_t r78 = REG_READ(C3_GDMA + 0x78 + (192*n));
    printf("RX fifo      78: %p ", (void*)r78);
    printf("INFIFO FULL: %ld, ", r78 & 1);
    printf("INFIFO EMPTY: %ld ", (r78 & 2) >> 1);
    printf("INFIFO CNT: %ld\n", (r78 & 0b11111100) >> 2);

    printf("RX status    84: %p\n", (void*)REG_READ(C3_GDMA + 0x84 + (192*n)));
    printf("RX last addr 94: %p\n", (void*)REG_READ(C3_GDMA + 0x94 + (192*n)));

    uint32_t rd8 = REG_READ(C3_GDMA + 0xd8 + (192*n));
    printf("TX fifo      78: %p ", (void*)rd8);
    printf("OUTFIFO FULL: %ld, ", rd8 & 1);
    printf("OUTFIFO EMPTY: %ld ", (rd8 & 2) >> 1);
    printf("OUTFIFO CNT: %ld\n", (rd8 & 0b11111100) >> 2);

    printf("TX status    e4: %p\n", (void*)REG_READ(C3_GDMA + 0xe4 + (192*n)));
    printf("TX eof addr  e8: %p\n", (void*)REG_READ(C3_GDMA + 0xe8 + (192*n)));
    printf("--------------------------------%s\n", "");
}

void aes_hw_encrypt_ctr(const uint8_t* key, const uint8_t* iv, const uint8_t* in, uint8_t* out, uint32_t blocks) {
    uint32_t length = blocks * 16;

    block_in_desc.buf = out;
    block_out_desc.buf = in;
    block_out_desc.length = length & 0xfff;

    /* periph_ll_enable_clk_clear_rst https://github.com/espressif/esp-idf/blob/495d35949d50033ebcb89def98f107aa267388c0/components/hal/esp32c3/include/hal/clk_gate_ll.h#L202 */
    // enable AES and GDMA clock
    SET_REG_MASK(SYSTEM_PERIP_CLK_EN1_REG, (SYSTEM_CRYPTO_AES_CLK_EN | SYSTEM_GDMA_CLK_EN));
    // Clear reset on digital signature, otherwise AES unit is held in reset also.
    CLEAR_REG_MASK(SYSTEM_PERIP_RST_EN1_REG, (SYSTEM_CRYPTO_AES_RST | SYSTEM_CRYPTO_DS_RST | SYSTEM_GDMA_RST));
    
    // select AES mode:
    REG_WRITE(AES_MODE_REG, AES_MODE_128_ENCRYPT);

    // copy key to hardware registers
    uint32_t key_word;
    for(int i = 0; i < 4; i++) {
        memcpy(&key_word, key + i*4, 4);
        REG_WRITE(((uint32_t*)AES_KEY_BASE) + i, key_word);
    }

    // set block mode to CTR
    REG_WRITE(AES_BLOCK_MODE_REG, AES_BLOCK_MODE_CTR);

    // set incrementing function
    REG_WRITE(AES_INC_SEL_REG, AES_INC_32);

    // copy IV / Initial Counter Block
    uint32_t iv_word;
    for(int i = 0; i < 4; i++) {
        memcpy(&iv_word, iv + i*4, 4);
        REG_WRITE(((uint32_t*)AES_IV_BASE) + i, iv_word);
    }
    
    // disable interrupts
    REG_WRITE(AES_INT_ENA_REG, 0);

    /* 1. connect DMA with AES */
    esp_aes_dma_start(&block_in_desc, &block_out_desc);
    
    /* 2. Initialize the AES accelerator-related registers */
    REG_WRITE(AES_DMA_ENABLE_REG, 1);
    
    // set number of blocks
    REG_WRITE(AES_BLOCK_NUM_REG, blocks);
    
    /* 3. start operation */
    REG_WRITE(AES_TRIGGER_REG, 1);
    
    /* 4. wait until AES done */
    while(REG_READ(AES_STATE_REG) != AES_STATE_DONE) {}
    /* make sure GDMA transfer is complete */
    while(block_in_desc.owner != 0 && block_in_desc.suc_eof != 1) {}
}

void esp_aes_dma_start(const lldesc_t *input, const lldesc_t *output) {
    // 1. Set GDMA_OUT_RST_CH0 first to 1 and then to 0, to reset the state machine of GDMA’s transmit channel and FIFO pointer
    // in and out
    SET_REG_MASK(GDMA_IN_CONF0_CHn_REG(GDMA_CHN), GDMA_IN_RST_CHn);
    SET_REG_MASK(GDMA_OUT_CONF0_CHn_REG(GDMA_CHN), GDMA_OUT_RST_CHn);
    CLEAR_REG_MASK(GDMA_IN_CONF0_CHn_REG(GDMA_CHN), GDMA_IN_RST_CHn);
    CLEAR_REG_MASK(GDMA_OUT_CONF0_CHn_REG(GDMA_CHN), GDMA_OUT_RST_CHn);

    // 2. Load an outlink, and configure GDMA_OUTLINK_ADDR_CHn with address of the first transmit descriptor
    // in
    REG_SET_BITS(GDMA_IN_LINK_CHn_REG(GDMA_CHN), input, GDMA_INLINK_ADDR_CHn);
    // out
    REG_SET_BITS(GDMA_OUT_LINK_CHn_REG(GDMA_CHN), output, GDMA_OUTLINK_ADDR_CHn);

    // 3. Configure GDMA_PERI_OUT_SEL_CHn with the value corresponding to the peripheral to be connected, as shown in Table 2-1
    // in
    REG_WRITE(GDMA_IN_PERI_SEL_CHn_REG(GDMA_CHN), PERI_SEL_AES);
    // out
    REG_WRITE(GDMA_OUT_PERI_SEL_CHn_REG(GDMA_CHN), PERI_SEL_AES);

    // 4. Set GDMA_OUTLINK_START_CHn to enable GDMA’s transmit channel for data transfer
    // in
    SET_REG_MASK(GDMA_IN_LINK_CHn_REG(GDMA_CHN), GDMA_INLINK_START_CHn);
    // out
    SET_REG_MASK(GDMA_OUT_LINK_CHn_REG(GDMA_CHN), GDMA_OUTLINK_START_CHn);
}