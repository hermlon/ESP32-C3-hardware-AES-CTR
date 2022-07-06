#include "aes_hw.h"

#include "common.h"

/* receive from AES */
static lldesc_t block_in_desc = {
    .size = 3200,
    .eof = 0,
    .owner = 1
};

/* transmit to AES */
static lldesc_t block_out_desc = {
    .size = 3200,
    .length = 3200,
    .eof = 1,
    .owner = 1
};



/* expects 256 blocks, so 4096 bytes */
void aes_hw_encrypt_ctr(const uint8_t* key, const uint8_t* iv, const uint8_t* in, uint8_t* out) {
    block_in_desc.buf = out;
    block_out_desc.buf = in;
    printf("in: %p\n", in);
    printf("out: %p\n", out);
    printf("inlink: %p\n", (void*)&block_in_desc);
    printf("outlink: %p\n", (void*)&block_out_desc);

    /* periph_ll_enable_clk_clear_rst https://github.com/espressif/esp-idf/blob/16a4ee7c36a848ca155791677ce011f3ca75c519/components/hal/esp32c3/include/hal/clk_gate_ll.h#L202 */
    // enable AES clock
    SET_REG_MASK(SYSTEM_PERIP_CLK_EN1_REG, (SYSTEM_CRYPTO_AES_CLK_EN | SYSTEM_DMA_CLK_EN));
    // Clear reset on digital signature, otherwise AES unit is held in reset also.
    CLEAR_REG_MASK(SYSTEM_PERIP_RST_EN1_REG, (SYSTEM_CRYPTO_AES_RST | SYSTEM_CRYPTO_DS_RST | SYSTEM_DMA_RST));

    /* 1. connect DMA with AES */

    esp_aes_dma_start(&block_in_desc, &block_out_desc);
    

    /* 2. Initialize the AES accelerator-related registers */

    REG_WRITE(AES_DMA_ENABLE_REG, 1);
    // disable interrupts
    REG_WRITE(AES_INT_ENA_REG, 0);
    // select AES mode:
    REG_WRITE(AES_MODE_REG, AES_MODE_128_ENCRYPT);
    
    // copy key to hardware registers
    uint32_t key_word;
    for(int i = 0; i < 4; i++) {
        memcpy(&key_word, key + i*4, 4);
        REG_WRITE(AES_KEY_BASE + i*4, key_word);
    }
    
    // set block mode to CTR
    REG_WRITE(AES_BLOCK_MODE_REG, AES_BLOCK_MODE_CTR);
    
    // set number of blocks
    REG_WRITE(AES_BLOCK_NUM_REG, NUM_BLOCKS);
    
    // set incrementing function
    REG_WRITE(AES_INC_SEL_REG, AES_INC_32);
    
    // copy IV / Initial Counter Block
    memcpy((uint8_t*)AES_IV_BASE, iv, 16);
    
    /* 3. start operation */
    REG_WRITE(AES_TRIGGER_REG, 1);
    
    printf("INT: %p\n", (void*)REG_READ(DMA_INT_ST_CH0_REG));
    /* 4. wait until AES done */
    //while(REG_READ(AES_STATE_REG) != AES_STATE_DONE) {
        //printf("%ld\n", REG_READ(AES_STATE_REG));
    //printf("INT: %ld\n", REG_READ(DMA_INT_ST_CH0_REG));
    //printf("INT: %p\n", (void*)REG_READ(DMA_INT_ST_CH0_REG));
    //}
    
    printf("done\n%s", "");

}

void esp_aes_dma_start(const lldesc_t *input, const lldesc_t *output) {
    printf("INT 1: %p\n", (void*)REG_READ(DMA_INT_ST_CH0_REG));

    //SET_REG_MASK((C3_GDMA + 0x0044), BIT(0));
    //CLEAR_REG_MASK((C3_GDMA + 0x0044), BIT(0));

    printf("INT 2: %p\n", (void*)REG_READ(DMA_INT_ST_CH0_REG));
    //REG_WRITE((C3_GDMA + 0x0008), 0xffff);
    printf("INT 3: %p\n", (void*)REG_READ(DMA_INT_ST_CH0_REG));

    // 1. Set GDMA_OUT_RST_CH0 first to 1 and then to 0, to reset the state machine of GDMA’s transmit channel and FIFO pointer
    // in
    SET_REG_MASK(DMA_IN_CONF0_CH0_REG, GDMA_IN_RST_CH0);
    CLEAR_REG_MASK(DMA_IN_CONF0_CH0_REG, GDMA_IN_RST_CH0);
    // out
    SET_REG_MASK(DMA_OUT_CONF0_CH0_REG, GDMA_OUT_RST_CH0);
    CLEAR_REG_MASK(DMA_OUT_CONF0_CH0_REG, GDMA_OUT_RST_CH0);

    printf("INT 4: %p\n", (void*)REG_READ(DMA_INT_ST_CH0_REG));
    
    // 2. Load an outlink, and configure GDMA_OUTLINK_ADDR_CHn with address of the first transmit descriptor
    // in
    REG_SET_BITS(DMA_IN_LINK_CH0_REG, input, DMA_INLINK_ADDR_CH0);
    // out
    REG_SET_BITS(DMA_OUT_LINK_CH0_REG, output, DMA_OUTLINK_ADDR_CH0);

    printf("INT 5: %p\n", (void*)REG_READ(DMA_INT_ST_CH0_REG));
    
    // 3. Configure GDMA_PERI_OUT_SEL_CHn with the value corresponding to the peripheral to be connected, as shown in Table 2-1
    // in
    REG_WRITE(DMA_IN_PERI_SEL_CH0_REG, PERI_SEL_AES);
    // out
    REG_WRITE(DMA_OUT_PERI_SEL_CH0_REG, PERI_SEL_AES);

    printf("INT 6: %p\n", (void*)REG_READ(DMA_INT_ST_CH0_REG));

    // 4. Set GDMA_OUTLINK_START_CHn to enable GDMA’s transmit channel for data transfer
    // in
    SET_REG_MASK(DMA_INLINK_ADDR_CH0, DMA_INLINK_START_CH0);
    // out
    SET_REG_MASK(DMA_OUTLINK_ADDR_CH0, DMA_OUTLINK_START_CH0);

    printf("INT 8: %p\n", (void*)REG_READ(DMA_INT_ST_CH0_REG));
}