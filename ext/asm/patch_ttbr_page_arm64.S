.text

.pool
.set PAGE_OFFSET,        0xBAD00001

; If you modify me, don't forget to change _inv_tlbi offset in patch_sigchecks

.globl _main
_main:
    MOV     X11, X30
    LDR     X10, =PAGE_OFFSET
    MRS     X6, TTBR0_EL1
    LDR     X5, [X6, X10]
    MOV     X9, #0x6000000000000000
    BIC     X8, X5, X9
    CBZ     X8, #_else1
_bit62_61:
    ORR     X5, X5, X9, LSL #0
_else1:
    AND     X8, X5, #0x80
    CBZ     X8, #_patch
_bit7:
    EOR     X5, X5, #0x80
_patch:
    STR     X5, [X6, X10]
_inv_tlbi:
    MOV     X11, X30
    ISB
    DMB     SY
    TLBI    VMALLE1
    DSB     SY
    ISB
_ret:
    MOV     X30, X11
    RET