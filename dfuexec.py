import binascii, datetime, hashlib, struct, sys, time
import usb # pyusb: use 'pip install pyusb' to install this module
import dfu, recovery, image3, image3_24Kpwn, utilities

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
        decryptediBSS = iBSS.newImage3(decrypted=True)
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