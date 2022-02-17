@ ibss-flash-nor-shellcode.S
@ Author: axi0mX
@ Flashes parts of payload to NOR using iPhone2,1 4.3.5 iBSS
@ Parts flashed: 0x0-0x200, 0x8000-0xF3000

.text

.pool
.set reboot_cmd,            0x84000cdd
.set set_bgcolor,           0x8400c6ed
.set apply_bgcolor,         0x8400c789
.set get_block_device,      0x84012c61

.set gNor0String,           0x84014754

.set NOR_PAYLOAD_BASE,      0x41000080
.set NOR_WRITE_1_OFFSET,             0
.set NOR_WRITE_1_SIZE,           0x200
.set NOR_WRITE_2_OFFSET,        0x8000
.set NOR_WRITE_2_SIZE,         0x78000
.set NOR_WRITE_3_OFFSET,       0x80000
.set NOR_WRITE_3_SIZE,         0x73000

.global _start

_start:
.code 16
    MOV R0, #0
    MOV R1, #160
    MOV R2, #0
    LDR R3, =set_bgcolor
    BLX R3                                      @ set_bgcolor(0, 160, 0)

    LDR R3, =apply_bgcolor
    BLX R3                                      @ apply_bgcolor()

    LDR R0, =NOR_WRITE_1_OFFSET
    LDR R1, =NOR_WRITE_1_SIZE
    BL flash_nor                                @ flash_nor(NOR_WRITE_1_OFFSET, NOR_WRITE_1_SIZE)

    LDR R0, =NOR_WRITE_2_OFFSET
    LDR R1, =NOR_WRITE_2_SIZE
    BL flash_nor                                @ flash_nor(NOR_WRITE_2_OFFSET, NOR_WRITE_2_SIZE)

    LDR R0, =NOR_WRITE_3_OFFSET
    LDR R1, =NOR_WRITE_3_SIZE
    BL flash_nor                                @ flash_nor(NOR_WRITE_3_OFFSET, NOR_WRITE_3_SIZE)

    LDR R3, =reboot_cmd
    BLX R3                                      @ reboot_cmd()

    /* reboot_cmd should never return */

    B spin                                      @ goto spin

flash_nor:                                      @ void flash_nor(R0=offset, R1=size)
    PUSH {R4-R5, LR}

    MOV R4, R0                                  @ R4 = R0
    MOV R5, R1                                  @ R5 = R1

    LDR R0, =gNor0String
    LDR R3, =get_block_device
    BLX R3                                      @ R0 = get_block_device(gNor0String)

    CBZ R0, fail                                @ if (R0 == 0) goto fail

    LDR R1, =NOR_PAYLOAD_BASE
    ADD R1, R1, R4
    MOV R2, R4
    MOV R3, #0
    STR R5, [SP]
    LDR R4, [R0, #0x24]
    BLX R4                                      @ R0 = R0[9](R0, NOR_PAYLOAD_BASE + R4, R4, 0, R5)

    CMP R0, R5
    BNE fail                                    @ if (R0 != R5) goto fail

    POP {R4-R5, PC}                             @ return

fail:
    MOV R0, #255
    MOV R1, #0
    MOV R2, #0
    LDR R3, =set_bgcolor
    BLX R3                                      @ set_bgcolor(255, 0, 0)

    LDR R3, =apply_bgcolor
    BLX R3                                      @ apply_bgcolor()

spin:
    B spin                                      @ while (1)
