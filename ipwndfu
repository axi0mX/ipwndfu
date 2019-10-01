#!/usr/bin/python
# ipwndfu: open-source jailbreaking tool for older iOS devices
# Author: axi0mX

import binascii, datetime, getopt, hashlib, struct, sys, time
import dfu, nor, utilities
import alloc8, checkm8, image3_24Kpwn, limera1n, SHAtter, steaks4uce, usbexec
from dfuexec import *

def print_help():
    print 'USAGE: ipwndfu [options]'
    print 'Interact with an iOS device in DFU Mode.\n'
    print 'Basic options:'
    print '  -p\t\t\t\tUSB exploit for pwned DFU Mode'
    print '  -x\t\t\t\tinstall alloc8 exploit to NOR'
    print '  -f file\t\t\tsend file to device in DFU Mode'
    print 'Advanced options:'
    print '  --demote\t\t\tdemote device to enable JTAG'
    print '  --boot\t\t\tboot device'
    print '  --dump=address,length\t\tdump memory to stdout'
    print '  --hexdump=address,length\thexdump memory to stdout'
    print '  --dump-rom\t\t\tdump SecureROM'
    print '  --dump-nor=file\t\tdump NOR to file'
    print '  --flash-nor=file\t\tflash NOR (header and firmware only) from file'
    print '  --24kpwn\t\t\tinstall 24Kpwn exploit to NOR'
    print '  --remove-24kpwn\t\tremove 24Kpwn exploit from NOR'
    print '  --remove-alloc8\t\tremove alloc8 exploit from NOR'
    print '  --decrypt-gid=hexdata\t\tAES decrypt with GID key'
    print '  --encrypt-gid=hexdata\t\tAES encrypt with GID key'
    print '  --decrypt-uid=hexdata\t\tAES decrypt with UID key'
    print '  --encrypt-uid=hexdata\t\tAES encrypt with UID key'

if __name__ == '__main__':
    try:
        advanced = ['demote', 'boot', 'dump=', 'hexdump=', 'dump-rom', 'dump-nor=', 'flash-nor=', '24kpwn', 'remove-24kpwn', 'remove-alloc8', 'decrypt-gid=', 'encrypt-gid=', 'decrypt-uid=', 'encrypt-uid=']
        opts, args = getopt.getopt(sys.argv[1:], 'pxf:', advanced)
    except getopt.GetoptError:
        print 'ERROR: Invalid arguments provided.'
        print_help()
        sys.exit(2)

    if len(opts) == 0:
        print_help()
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-p':
            device = dfu.acquire_device()
            serial_number = device.serial_number
            dfu.release_device(device)

            if 'CPID:8720' in serial_number:
                steaks4uce.exploit()
            elif 'CPID:8920' in serial_number:
                limera1n.exploit()
            elif 'CPID:8922' in serial_number:
                limera1n.exploit()
            elif 'CPID:8930' in serial_number:
                SHAtter.exploit()
            elif 'CPID:8947' in serial_number:
                checkm8.exploit()
            elif 'CPID:8950' in serial_number:
                checkm8.exploit()
            elif 'CPID:8955' in serial_number:
                checkm8.exploit()
            elif 'CPID:8960' in serial_number:
                checkm8.exploit()
            elif 'CPID:8002' in serial_number:
                checkm8.exploit()
            elif 'CPID:8004' in serial_number:
                checkm8.exploit()
            elif 'CPID:8010' in serial_number:
                checkm8.exploit()
            elif 'CPID:8011' in serial_number:
                checkm8.exploit()
            elif 'CPID:8015' in serial_number:
                checkm8.exploit()
            else:
                print 'Found:', serial_number
                print 'ERROR: This device is not supported.'
                sys.exit(1)

        if opt == '-x':
            device = PwnedDFUDevice()
            if device.config.cpid != '8920':
                print 'This is not a compatible device. alloc8 exploit is for iPhone 3GS only.'
                sys.exit(1)

            if device.config.version == '359.3':
                print 'WARNING: iPhone 3GS (old bootrom) was detected. Use 24Kpwn exploit for faster boots, alloc8 exploit is for testing purposes only.'
                raw_input("Press ENTER to continue.")

            print 'Installing alloc8 exploit to NOR.'

            dump = device.nor_dump(saveBackup=True)

            nor = nor.NorData(dump)

            for byte in nor.parts[1]:
                if byte != '\x00':
                    print 'ERROR: Bytes following IMG2 header in NOR are not zero. alloc8 exploit was likely previously installed. Exiting.'
                    sys.exit(1)
            if len(nor.images) == 0 or len(nor.images[0]) < 0x24000:
                print 'ERROR: 24Kpwn LLB was not found. You must restore a custom 24Kpwn IPSW before using this exploit.'
                sys.exit(1)

            print 'Preparing modified NOR with alloc8 exploit.'
            # Remove 24Kpwn first.
            nor.images[0] = image3_24Kpwn.remove_exploit(nor.images[0])
            new_nor = alloc8.exploit(nor, device.config.version)
            device.flash_nor(new_nor.dump())

        if opt == '-f':
            try:
                with open(arg, 'rb') as f:
                    data = f.read()
            except IOError:
                print 'ERROR: Could not read file:', arg
                sys.exit(1)

            device = dfu.acquire_device()
            dfu.reset_counters(device)
            dfu.send_data(device, data)
            dfu.request_image_validation(device)
            dfu.release_device(device)

        if opt == '--demote':
            device = dfu.acquire_device()
            serial_number = device.serial_number
            dfu.release_device(device)

            if 'PWND:[checkm8]' in serial_number:
                pwned = usbexec.PwnedUSBDevice()
                old_value = pwned.read_memory_uint32(pwned.platform.demotion_reg)
                print 'Demotion register: 0x%x' % old_value
                if old_value & 1:
                    print 'Attempting to demote device.'
                    pwned.write_memory_uint32(pwned.platform.demotion_reg, old_value & 0xFFFFFFFE)
                    new_value = pwned.read_memory_uint32(pwned.platform.demotion_reg)
                    print 'Demotion register: 0x%x' % new_value
                    if old_value != new_value:
                        print 'Success!'
                    else:
                        print 'Failed.'
                else:
                    print 'WARNING: Device is already demoted.'
            else:
                print 'ERROR: Demotion is only supported on devices pwned with checkm8 exploit.'
                sys.exit(1)

        if opt == '--dump':
            if arg.count(',') != 1:
                print 'ERROR: You must provide exactly 2 comma separated values: address,length'
                sys.exit(1)
            raw_address, raw_length = arg.split(',')
            address = int(raw_address, 16) if raw_address.startswith('0x') else int(raw_address, 10)
            length = int(raw_length, 16) if raw_length.startswith('0x') else int(raw_length, 10)

            device = dfu.acquire_device()
            serial_number = device.serial_number
            dfu.release_device(device)

            if 'PWND:[checkm8]' in serial_number:
                device = usbexec.PwnedUSBDevice()
                sys.stdout.write(device.read_memory(address, length))
            else:
                device = PwnedDFUDevice()
                print device.read_memory(address, length)

        if opt == '--hexdump':
            if arg.count(',') != 1:
                print 'ERROR: You must provide exactly 2 comma separated values: address,length'
                sys.exit(1)
            raw_address, raw_length = arg.split(',')
            address = int(raw_address, 16) if raw_address.startswith('0x') else int(raw_address, 10)
            length = int(raw_length, 16) if raw_length.startswith('0x') else int(raw_length, 10)

            device = dfu.acquire_device()
            serial_number = device.serial_number
            dfu.release_device(device)

            if 'PWND:[checkm8]' in serial_number:
                device = usbexec.PwnedUSBDevice()
                dump = device.read_memory(address, length)
                for line in utilities.hex_dump(dump, address).splitlines():
                    print '%x: %s' % (address, line[10:])
                    address += 16
            else:
                device = PwnedDFUDevice()
                dump = device.read_memory(address, length)
                print utilities.hex_dump(dump, address),

        if opt == '--dump-rom':
            device = dfu.acquire_device()
            serial_number = device.serial_number
            dfu.release_device(device)

            if 'PWND:[checkm8]' in serial_number:
                pwned = usbexec.PwnedUSBDevice()
                securerom = pwned.read_memory(pwned.platform.rom_base, pwned.platform.rom_size)
                if hashlib.sha1(securerom).hexdigest() != pwned.platform.rom_sha1:
                    print hashlib.sha1(securerom).hexdigest()
                    print 'ERROR: SecureROM was dumped, but the SHA1 hash does not match. Exiting.'
                    sys.exit(1)
                chip    = securerom[0x200:0x240].split(' ')[2][:-1]
                kind    = securerom[0x240:0x280].split('\0')[0]
                version = securerom[0x280:0x2C0].split('\0')[0][6:]
                filename = 'SecureROM-%s-%s-%s.dump' % (chip, version, kind)
                with open(filename, 'wb') as f:
                    f.write(securerom)
                print 'Saved:', filename
            else:
                device = PwnedDFUDevice()
                securerom = device.securerom_dump()
                filename = 'SecureROM-%s-RELEASE.dump' % device.config.version
                f = open(filename, 'wb')
                f.write(securerom)
                f.close()
                print 'SecureROM dumped to file:', filename

        if opt == '--dump-nor':
            device = PwnedDFUDevice()
            if device.config.cpid != '8920':
                print 'This is not a compatible device. Dumping NOR is only supported on iPhone 3GS.'
                sys.exit(1)
            nor = device.nor_dump(saveBackup=False)
            f = open(arg, 'wb')
            f.write(nor)
            f.close()
            print 'NOR dumped to file: %s' % arg

        if opt == '--flash-nor':
            print 'Flashing NOR from file:', arg
            f = open(arg, 'rb')
            new_nor = f.read()
            f.close()
            if new_nor[:4] != 'IMG2'[::-1]:
                print 'ERROR: Bad IMG2 header magic. This is not a valid NOR. Exiting.'
                sys.exit(1)

            device = PwnedDFUDevice()
            if device.config.cpid != '8920':
                print 'This is not a compatible device. Flashing NOR is only supported on iPhone 3GS.'
                sys.exit(1)
            device.nor_dump(saveBackup=True)
            device.flash_nor(new_nor)

        if opt == '--24kpwn':
            print '*** based on 24Kpwn exploit (segment overflow) by chronic, CPICH, ius, MuscleNerd, Planetbeing, pod2g, posixninja, et al. ***'

            device = PwnedDFUDevice()
            if device.config.version != '359.3':
                print 'Only iPhone 3GS (old bootrom) is supported.'
                sys.exit(1)

            dump = device.nor_dump(saveBackup=True)

            print 'Preparing modified NOR with 24Kpwn exploit.'
            nor = nor.NorData(dump)
            for byte in nor.parts[1]:
                if byte != '\x00':
                    print 'ERROR: Bytes following IMG2 header in NOR are not zero. alloc8 exploit was likely previously installed. Exiting.'
                    sys.exit(1)
            if len(nor.images) == 0:
                print 'ERROR: 24Kpwn exploit cannot be installed, because NOR has no valid LLB. Exiting.'
                sys.exit(1)

            # Remove existing 24Kpwn exploit.
            if len(nor.images[0]) > 0x24000:
                nor.images[0] = image3_24Kpwn.remove_exploit(nor.images[0])
            nor.images[0] = image3_24Kpwn.exploit(nor.images[0], device.securerom_dump())
            device.flash_nor(nor.dump())

        if opt == '--remove-24kpwn':
            device = PwnedDFUDevice()
            if device.config.cpid != '8920':
                print 'This is not a compatible device. 24Kpwn exploit is only supported on iPhone 3GS.'
                sys.exit(1)

            print 'WARNING: This feature is for researchers only. Device will probably not boot into iOS until it is restored in iTunes.'
            raw_input("Press ENTER to continue.")

            dump = device.nor_dump(saveBackup=True)

            nor = nor.NorData(dump)

            if len(nor.images) == 0:
                print 'ERROR: NOR has no valid LLB. It seems that 24Kpwn exploit is not installed. Exiting.'
                sys.exit(1)
            if len(nor.images[0]) <= 0x24000:
                print 'ERROR: LLB is not oversized. It seems that 24Kpwn exploit is not installed. Exiting.'
                sys.exit(1)

            print 'Preparing modified NOR without 24Kpwn exploit.'
            nor.images[0] = image3_24Kpwn.remove_exploit(nor.images[0])
            device.flash_nor(nor.dump())

        if opt == '--remove-alloc8':
            device = PwnedDFUDevice()
            if device.config.cpid != '8920':
                print 'This is not a compatible device. alloc8 exploit is for iPhone 3GS only.'
                sys.exit(1)

            print 'WARNING: This feature is for researchers only. Device will probably not boot into iOS until it is restored in iTunes.'
            raw_input("Press ENTER to continue.")

            dump = device.nor_dump(saveBackup=True)

            nor = nor.NorData(dump)

            if len(nor.images) < 700:
                print 'ERROR: It seems that alloc8 exploit is not installed. There are less than 700 images in NOR. Exiting.'
                sys.exit(1)

            print 'Preparing modified NOR without alloc8 exploit.'
            new_nor = alloc8.remove_exploit(nor)
            device.flash_nor(new_nor.dump())

        if opt == '--decrypt-gid':
            device = dfu.acquire_device()
            serial_number = device.serial_number
            dfu.release_device(device)

            if 'PWND:[checkm8]' in serial_number:
                pwned = usbexec.PwnedUSBDevice()
                print 'Decrypting with %s GID key.' % pwned.platform.name()
                print pwned.aes(arg.decode('hex'), usbexec.AES_DECRYPT, usbexec.AES_GID_KEY).encode('hex')
            else:
                device = PwnedDFUDevice()
                print 'Decrypting with S5L%s GID key.' % device.config.cpid
                print device.aes_hex(arg, AES_DECRYPT, AES_GID_KEY)

        if opt == '--encrypt-gid':
            device = dfu.acquire_device()
            serial_number = device.serial_number
            dfu.release_device(device)

            if 'PWND:[checkm8]' in serial_number:
                pwned = usbexec.PwnedUSBDevice()
                print 'Encrypting with %s GID key.' % pwned.platform.name()
                print pwned.aes(arg.decode('hex'), usbexec.AES_ENCRYPT, usbexec.AES_GID_KEY).encode('hex')
            else:
                device = PwnedDFUDevice()
                print 'Encrypting with S5L%s GID key.' % device.config.cpid
                print device.aes_hex(arg, AES_ENCRYPT, AES_GID_KEY)

        if opt == '--decrypt-uid':
            device = dfu.acquire_device()
            serial_number = device.serial_number
            dfu.release_device(device)

            if 'PWND:[checkm8]' in serial_number:
                pwned = usbexec.PwnedUSBDevice()
                print 'Decrypting with %s device-specific UID key.' % pwned.platform.name()
                print pwned.aes(arg.decode('hex'), usbexec.AES_DECRYPT, usbexec.AES_UID_KEY).encode('hex')
            else:
                device = PwnedDFUDevice()
                print 'Decrypting with device-specific UID key.'
                print device.aes_hex(arg, AES_DECRYPT, AES_UID_KEY)

        if opt == '--encrypt-uid':
            device = dfu.acquire_device()
            serial_number = device.serial_number
            dfu.release_device(device)

            if 'PWND:[checkm8]' in serial_number:
                pwned = usbexec.PwnedUSBDevice()
                print 'Encrypting with %s device-specific UID key.' % pwned.platform.name()
                print pwned.aes(arg.decode('hex'), usbexec.AES_ENCRYPT, usbexec.AES_UID_KEY).encode('hex')
            else:
                device = PwnedDFUDevice()
                print 'Encrypting with device-specific UID key.'
                print device.aes_hex(arg, AES_ENCRYPT, AES_UID_KEY)

        if opt == '--boot':
            device = dfu.acquire_device()
            serial_number = device.serial_number
            dfu.release_device(device)

            if 'CPID:8015' not in serial_number or 'PWND:[checkm8]' not in serial_number:
                print serial_number
                print 'ERROR: Option --boot is currently only supported on iPhone X pwned with checkm8.'
            else:
                HEAP_BASE         = 0x1801E8000
                HEAP_WRITE_OFFSET = 0x5000
                HEAP_WRITE_HASH   = 0x10000D4EC
                HEAP_CHECK_ALL    = 0x10000DB98
                HEAP_STATE        = 0x1800086A0
                NAND_BOOT_JUMP    = 0x10000188C
                BOOTSTRAP_TASK_LR = 0x180015F88
                DFU_BOOL          = 0x1800085B0
                DFU_NOTIFY        = 0x1000098B4
                DFU_STATE         = 0x1800085E0
                TRAMPOLINE        = 0x180018000
                block1 = struct.pack('<8Q', 0, 0, 0, HEAP_STATE, 2, 132, 128, 0)
                block2 = struct.pack('<8Q', 0, 0, 0, HEAP_STATE, 2,   8, 128, 0)
                device = usbexec.PwnedUSBDevice()
                device.write_memory(HEAP_BASE + HEAP_WRITE_OFFSET        , block1)
                device.write_memory(HEAP_BASE + HEAP_WRITE_OFFSET +  0x80, block2)
                device.write_memory(HEAP_BASE + HEAP_WRITE_OFFSET + 0x100, block2)
                device.write_memory(HEAP_BASE + HEAP_WRITE_OFFSET + 0x180, block2)
                device.execute(0, HEAP_WRITE_HASH, HEAP_BASE + HEAP_WRITE_OFFSET        )
                device.execute(0, HEAP_WRITE_HASH, HEAP_BASE + HEAP_WRITE_OFFSET +  0x80)
                device.execute(0, HEAP_WRITE_HASH, HEAP_BASE + HEAP_WRITE_OFFSET + 0x100)
                device.execute(0, HEAP_WRITE_HASH, HEAP_BASE + HEAP_WRITE_OFFSET + 0x180)
                device.execute(0, HEAP_CHECK_ALL)
                print 'Heap repaired.'

                device.write_memory(TRAMPOLINE, checkm8.asm_arm64_branch(TRAMPOLINE, TRAMPOLINE + 0x400))
                device.write_memory(TRAMPOLINE + 0x400, open('bin/t8015_shellcode_arm64.bin').read())

                device.write_memory_ptr(BOOTSTRAP_TASK_LR, NAND_BOOT_JUMP)
                device.write_memory(DFU_BOOL, '\x01')
                device.execute(0, DFU_NOTIFY, DFU_STATE)
                print 'Booted.'
