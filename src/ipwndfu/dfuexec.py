import binascii
import dataclasses
import datetime
import hashlib
import struct
import sys
import time
from contextlib import suppress

import usb  # type: ignore
from ipwndfu import dfu, image3, recovery, utilities

EXEC_MAGIC = "exec"[::-1]
AES_BLOCK_SIZE = 16
AES_GID_KEY = 0x20000200
AES_UID_KEY = 0x20000201
AES_ENCRYPT = 16
AES_DECRYPT = 17


@dataclasses.dataclass
class PwnedDeviceConfig:
    version: str
    cpid: str
    aes_crypto_cmd: int
    memmove: int
    get_block_device: int
    load_address: int
    rom_address: int
    rom_size: int
    rom_sha256: str


configs = [
    PwnedDeviceConfig(
        # S5L8920 (old bootrom)
        version="359.3",
        cpid="8920",
        aes_crypto_cmd=0x925,
        memmove=0x83D4,
        get_block_device=0x1351,
        load_address=0x84000000,
        rom_address=0xBF000000,
        rom_size=0x10000,
        rom_sha256="99fd16f919a506c7f0701620e132e18c0e6f4025a57a85807960ca092e5e3587",
    ),
    PwnedDeviceConfig(
        # S5L8920 (new bootrom)
        version="359.3.2",
        cpid="8920",
        aes_crypto_cmd=0x925,
        memmove=0x83DC,
        get_block_device=0x1351,
        load_address=0x84000000,
        rom_address=0xBF000000,
        rom_size=0x10000,
        rom_sha256="0e6feb1144c95b1ee088ecd6c45bfdc2ed17191167555b6ca513d6572e463c86",
    ),
    PwnedDeviceConfig(
        # S5L8922
        version="359.5",
        cpid="8922",
        aes_crypto_cmd=0x919,
        memmove=0x8564,
        get_block_device=0x1851,
        load_address=0x84000000,
        rom_address=0xBF000000,
        rom_size=0x10000,
        rom_sha256="07b8a615f00961c5802451b5717c344db287b68c5f6d2331ac6ba7a6acdbac9d",
    ),
    PwnedDeviceConfig(
        # S5L8930
        version="574.4",
        cpid="8930",
        aes_crypto_cmd=0x686D,
        memmove=0x84DC,
        get_block_device=0x81D5,
        load_address=0x84000000,
        rom_address=0xBF000000,
        rom_size=0x10000,
        rom_sha256="4f34652a238a57ae0018b6e66c20a240cdbee8b4cca59a99407d09f83ea8082d",
    ),
]


class PwnedDFUDevice:
    def __init__(self):
        device = dfu.acquire_device()
        self.identifier = device.serial_number
        dfu.release_device(device)

        if "PWND:[" not in self.identifier:
            print(
                "ERROR: Device is not in pwned DFU Mode. Use -p flag to exploit device and then try again."
            )
            sys.exit(1)

        if "CPID:8720" in self.identifier:
            print(
                "ERROR: This feature is not supported on iPod Touch (2nd generation)."
            )
            sys.exit(1)

        self.config = None
        for config in configs:
            if f"SRTG:[iBoot-{config.version}]" in self.identifier:
                self.config = config
                break
        if self.config is None:
            print(
                "ERROR: Device seems to be in pwned DFU Mode, but a matching configuration was not found."
            )
            sys.exit(1)

    def ecid_string(self):
        tokens = self.identifier.split()
        for token in tokens:
            if token.startswith("ECID:"):
                return token[5:]
        print("ERROR: ECID is missing from USB serial number string.")
        sys.exit(1)

    def execute(self, cmd, receive_length):
        device = dfu.acquire_device()
        assert self.identifier == device.serial_number

        dfu.reset_counters(device)
        dfu.send_data(device, EXEC_MAGIC + cmd)
        dfu.request_image_validation(device)
        dfu.release_device(device)

        time.sleep(0.5)

        device = dfu.acquire_device()
        assert self.identifier == device.serial_number

        required_length = 0x8 + receive_length
        required_length = (
            required_length
            if required_length % 0x800 == 0
            else required_length / 0x800 * 0x800 + 0x800
        )
        received = dfu.get_data(device, required_length)
        dfu.release_device(device)

        (exec_cleared, retval) = struct.unpack("<2I", received[:8])
        assert exec_cleared == 0
        return retval, received[8 : 8 + receive_length]

    def securerom_dump(self):
        securerom = self.read_memory(self.config.rom_address, self.config.rom_size)
        if hashlib.sha256(securerom).hexdigest() != self.config.rom_sha256:
            print(
                "ERROR: SecureROM was dumped, but the SHA256 hash does not match. Exiting."
            )
            sys.exit(1)
        return securerom

    def aes(self, data, action, key):
        if len(data) % AES_BLOCK_SIZE != 0:
            print(
                "ERROR: Length of data for AES encryption/decryption must be a multiple of %s."
                % AES_BLOCK_SIZE
            )
            sys.exit(1)

        cmd = struct.pack(
            "<8I",
            self.config.aes_crypto_cmd,
            action,
            self.config.load_address + 36,
            self.config.load_address + 0x8,
            len(data),
            key,
            0,
            0,
        )
        (retval, received) = self.execute(cmd + data, len(data))
        return received[: len(data)]

    def aes_hex(self, hexdata, action, key):
        if len(hexdata) % 32 != 0:
            print(
                "ERROR: Length of hex data for AES encryption/decryption must be a multiple of %s."
                % (2 * AES_BLOCK_SIZE)
            )
            sys.exit(1)

        return binascii.hexlify(self.aes(binascii.unhexlify(hexdata), action, key))

    def read_memory(self, address, length):
        (retval, data) = self.execute(
            struct.pack(
                "<4I",
                self.config.memmove,
                self.config.load_address + 8,
                address,
                length,
            ),
            length,
        )
        return data

    def write_memory(self, address, data):
        (retval, data) = self.execute(
            struct.pack(
                f"<4I{len(data)}s",
                self.config.memmove,
                address,
                self.config.load_address + 20,
                len(data),
                data,
            ),
            0,
        )
        return data

    def nor_dump(self, save_backup):
        (bdev, empty) = self.execute(
            struct.pack(
                "<2I5s",
                self.config.get_block_device,
                self.config.load_address + 12,
                "nor0\x00",
            ),
            0,
        )
        if bdev == 0:
            print("ERROR: Unable to dump NOR. Pointer to nor0 block device was NULL.")
            sys.exit(1)

        data = self.read_memory(bdev + 28, 4)
        (read,) = struct.unpack("<I", data)
        if read == 0:
            print("ERROR: Unable to dump NOR. Function pointer for reading was NULL.")
            sys.exit(1)

        nor_part_size = 0x20000
        nor_parts = 8
        nor = bytes()
        for i in range(nor_parts):
            print(f"Dumping NOR, part {i + 1}/{nor_parts}.")
            (retval, received) = self.execute(
                struct.pack(
                    "<6I",
                    read,
                    bdev,
                    self.config.load_address + 8,
                    i * nor_part_size,
                    0,
                    nor_part_size,
                ),
                nor_part_size,
            )
            nor += received

        if save_backup:
            date = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            filename = f"nor-backups/nor-{self.ecid_string()}-{date}.dump"
            with open(filename, "wb") as f:
                f.write(nor)

            print(f"NOR backed up to file: {filename}")

        return nor

    def boot_ibss(self):
        print("Sending i_bss.")
        if self.config.cpid != "8920":
            print("ERROR: Boot i_bss is currently only supported on iPhone 3GS.")
            sys.exit(1)

        help1 = "Download iPhone2,1_4.3.5_8L1_Restore.ipsw and use the following command to extract i_bss:"
        help2 = (
            "unzip -p iPhone2,1_4.3.5_8L1_Restore.ipsw "
            "Firmware/dfu/i_bss.n88ap.RELEASE.dfu > n88ap-i_bss-4.3.5.img3"
        )
        data = None
        try:
            with open("n88ap-i_bss-4.3.5.img3", "rb") as f:
                data = f.read()
        except IOError:
            print("ERROR: n88ap-i_bss-4.3.5.img3 is missing.")
            print(help1)
            print(help2)
            sys.exit(1)
        if len(data) == 0:
            print("ERROR: n88ap-i_bss-4.3.5.img3 exists, but is empty (size: 0 bytes).")
            print(help1)
            print(help2)
            sys.exit(1)
        if (
            hashlib.sha256(data).hexdigest()
            != "b47816105ce97ef02637ec113acdefcdee32336a11e04eda0a6f4fc5e6617e61"
        ):
            print(
                "ERROR: n88ap-i_bss-4.3.5.img3 exists, but is from the wrong IPSW or corrupted."
            )
            print(help1)
            print(help2)
            sys.exit(1)

        i_bss = image3.Image3(data)
        decrypted_ibss = i_bss.new_image3(decrypted=True)
        n88ap_i_bss_435_patches = [
            (0x14954, "run\x00"),  # patch 'reset' command string to 'run'
            # patch 'reset' command handler to LOAD_ADDRESS + 1
            (0x17654, struct.pack("<I", 0x41000001)),
        ]
        patched_ibss = decrypted_ibss[:64] + utilities.apply_patches(
            decrypted_ibss[64:], n88ap_i_bss_435_patches
        )

        device = dfu.acquire_device()
        assert self.identifier == device.serial_number
        dfu.reset_counters(device)
        dfu.request_image_validation(device)
        dfu.release_device(device)

        time.sleep(0.5)

        device = dfu.acquire_device()
        assert self.identifier == device.serial_number
        dfu.send_data(device, patched_ibss)
        dfu.request_image_validation(device)
        dfu.release_device(device)

        time.sleep(0.5)

        print("Waiting for i_bss to enter Recovery Mode.")
        device = recovery.acquire_device()
        recovery.release_device(device)

    def flash_nor(self, nor):
        self.boot_ibss()
        print("Sending iBSS payload to flash NOR.")
        max_shellcode_length = 132
        payload = None
        with open("bin/ibss-flash-nor-shellcode.bin", "rb") as f:
            payload = f.read()
        assert len(payload) <= max_shellcode_length
        payload += "\x00" * (max_shellcode_length - len(payload)) + nor

        device = recovery.acquire_device()
        assert "CPID:8920" in device.serial_number
        recovery.send_data(device, payload)
        with suppress(usb.core.USBError):
            print("Sending run command.")
            recovery.send_command(device, "run")

        recovery.release_device(device)
        print(
            "If screen is not red, NOR was flashed successfully and device will reboot."
        )

    def decrypt_keybag(self, keybag):
        keybag_length = 48
        assert len(keybag) == keybag_length

        keybag_filename = f"aes-keys/S5L{self.config.cpid}-firmware"
        data = None
        try:
            with open(keybag_filename, "rb") as f:
                data = f.read()
        except IOError:
            data = str()
        assert len(data) % 2 * keybag_length == 0

        for i in range(0, len(data), 2 * keybag_length):
            if keybag == data[i : i + keybag_length]:
                return data[i + keybag_length : i + 2 * keybag_length]

        device = PwnedDFUDevice()
        decrypted_keybag = device.aes(keybag, AES_DECRYPT, AES_GID_KEY)

        with open(keybag_filename, "a") as f:
            f.write(keybag + decrypted_keybag)

        return decrypted_keybag
