.text
.pool
.set patch, 0x100D
.set page, 0x18000c400
.set new_perm, 0x60000100000625
.set old_perm, 0x1000006a5
.globl _main
_main:
  MSR DAIFSET, #0xF
  LDR X5, =page
  LDR X6, =new_perm
  STR X6, [X5]
  ISB
  DMB SY
  DSB SY
  SYS #0, c8, c7, #0
  DSB SY
  ISB
  LDR X4, =0x100006868
  LDR W6, =0x52800021
  STR W6, [X4]
  ADD X4, X4, 4
  LDR W6, =0xd503201f
  STR W6, [X4]
  ADD X4, X4, 4
  LDR W6, =0x390487e1
  STR W6, [X4]
  ADD X4, X4, 4
  LDR W6, =0x39048be1
  STR W6, [X4]
  ADD X4, X4, 4
  LDR W6, =0x52800039
  STR W6, [X4]
  ADD X4, X4, 4
  LDR W6, =0xd503201f
  STR W6, [X4]
  ADD X4, X4, 4
  LDR W6, =0xd503201f 
  STR W6, [X4]
  LDR W6, =0xd503201f
  LDR X4, =0x100006838
  STR W6, [X4]
  LDR X4, =0x10000685c
  STR W6, [X4]
  LDR X4, =0x100006810
  STR W6, [X4]
  LDR X4, =0x1000067fc
  STR W6, [X4]
  LDR X4, =0x1000067c4
  STR W6, [X4]
  LDR X4, =0x10000678c
  STR W6, [X4]
  LDR X4, =0x100006784
  STR W6, [X4]
  LDR W6, =0xd503201f
  LDR X4, =0x100006618
  STR W6, [X4]
  LDR X4, =0x10000663c
  STR W6, [X4]
  LDR X4, =0x10000665c
  STR W6, [X4]
  LDR X4, =0x100006668
  STR W6, [X4]
  LDR X4, =0x1000066a0
  STR W6, [X4]
  LDR X4, =0x1000066ac
  STR W6, [X4]
  LDR X4, =0x1000066c8
  STR W6, [X4]
  LDR X4, =0x1000067C4
  LDR W6, =0x1400001c
  STR W6, [X4]
  LDR X4, =0x100006750
  LDR W6, =0x14000009
  STR W6, [X4]
  LDR X4, =0x100006268
  LDR W6, =0xD2800000 
  STR W6, [X4]
  LDR W6, =0xD65F03C0
  STR W6, [X4,4]
  ISB
  LDR X5, =page
  LDR X6, =old_perm
  STR X6, [X5]
  ISB
  ISB
  DMB SY
  ISB
  DSB SY
  SYS #0, c8, c7, #0
  DSB SY
  ISB
  MSR DAIFSET, #0x0
  RET
 
 



