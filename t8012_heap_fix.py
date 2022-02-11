import usbexec

def fix_heap():
  d = usbexec.PwnedUSBDevice()

  calculate_block_checksum = 0x10000D4E8

  block_1 = 0x1801edb40
  block_2 = 0x1801fffc0
  block_2_size = 0x40
  block_2_move_to = 0x1801fff80

  if block_1 + d.read_memory_uint32(block_1 + 0x20) * 64 != block_2:
    raise Exception("bad block_1")

  for i in range(0, block_2_size, 4):
    m = d.read_memory_uint32(block_2 + i)
    d.write_memory_uint32(block_2_move_to + i, m)

  d.write_memory_uint32(block_1 + 0x20,  d.read_memory_uint32(block_1 + 0x20) - 1)
  d.execute(0, calculate_block_checksum, block_1)