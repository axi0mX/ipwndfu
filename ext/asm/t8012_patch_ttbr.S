.text

.align 2

.globl _main
_main:

  MOV  X1, #0x180000000
  ADD  X2, X1, #0xC000

  MOV  X1, #0x100000000
  ADD  X1, X1, #0x625
  STR  X1, [X2,#0x5e8]

  MOV  X1, #0x180000000
  ADD  X1, X1, #0x625
  STR  X1, [X2,#0x5f0]
  MOV  X1, #0x180000000
  ADD  X1, X1, #0x6A5
  STR  X1, [X2,#0x5f8]
  DMB  SY

  RET