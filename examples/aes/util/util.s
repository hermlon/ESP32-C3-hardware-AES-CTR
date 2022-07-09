.text

.globl init_cycles
.align 2
init_cycles:
    /* write 0 to value register */
    csrwi 0x7E2, 0
    /* count clock cycles */
    csrwi 0x7E0, 1 
    /* start counting, halt on max value */
    csrwi 0x7E0, 3 
    ret
.size init_cycles,.-init_cycles

.globl get_cycles
.align 2
get_cycles:
    /* return value register */
    csrr a0, 0x7E2
    ret
.size get_cycles,.-get_cycles
