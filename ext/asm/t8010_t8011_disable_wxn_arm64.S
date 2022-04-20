.text

.align 2

.globl _main
_main:
  MOV  X1, #0x180000000
  ADD  X2, X1, #0xA0000
  ADD  X1, X1, #0x625
  STR  X1, [X2,#0x600]
  DMB  SY

  MOV  X0, #0x100D
  MSR  SCTLR_EL1, X0
  DSB  SY
  ISB

  RET
