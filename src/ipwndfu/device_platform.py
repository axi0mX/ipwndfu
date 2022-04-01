from typing import Optional


class DevicePlatform:
    def __init__(
        self,
        cpid: int,
        cprv: int,
        scep: int,
        arch: str,
        srtg: str,
        rom_base: int,
        rom_size: int,
        rom_sha1: str,
        sram_base: int,
        sram_size: int,
        dram_base: int,
        nonce_length: int,
        sep_nonce_length: Optional[int],
        demotion_reg: int,
        sigcheck_addr: int,
        sigcheck_patch: int,
        heap_state: int,
        heap_write_hash: int,
        heap_check_all: int,
    ) -> None:
        self.cpid = cpid
        self.cprv = cprv
        self.scep = scep
        self.arch = arch
        self.srtg = srtg
        self.rom_base = rom_base
        self.rom_size = rom_size
        self.rom_sha1 = rom_sha1
        self.sram_base = sram_base
        self.sram_size = sram_size
        self.dram_base = dram_base
        self.nonce_length = nonce_length
        self.sep_nonce_length = sep_nonce_length
        self.demotion_reg = demotion_reg
        self.sigcheck_addr = sigcheck_addr
        self.sigcheck_patch = sigcheck_patch
        self.heap_state = heap_state
        self.heap_write_hash = heap_write_hash
        self.heap_check_all = heap_check_all
        if self.cpid in [0x8940, 0x8947]:
            self.dfu_image_base = 0x34000000
            self.dfu_load_base = 0x9FF00000
            self.recovery_image_base = 0x9FF00000
            self.recovery_load_base = 0x80000000
            self.heap_base = 0
            self.heap_offset = 0
            self.trampoline_base = 0
            self.trampoline_offset = 0
            self.page_offset = 0
        if self.cpid in [0x8950, 0x8955]:
            self.dfu_image_base = 0x10000000
            self.dfu_load_base = 0xBFF00000
            self.recovery_image_base = 0xBFF00000
            self.recovery_load_base = 0x80000000
            self.heap_base = 0
            self.heap_offset = 0
            self.trampoline_base = 0
            self.trampoline_offset = 0
            self.page_offset = 0
        if self.cpid == 0x8960:
            self.dfu_image_base = 0x180380000
            self.dfu_load_base = 0x180000000  # varies (HACK: test purposes)
            self.recovery_image_base = 0x83D7F7000  # varies
            self.recovery_load_base = 0x800000000
            self.heap_base = 0
            self.heap_offset = 0
            self.trampoline_base = 0
            self.trampoline_offset = 0
            self.page_offset = 0
        if self.cpid in [0x8002, 0x8004]:
            self.dfu_image_base = 0x48818000
            self.dfu_load_base = 0x80000000
            self.recovery_image_base = 0x48818000
            self.recovery_load_base = 0x80000000
            self.heap_base = 0
            self.heap_offset = 0
            self.trampoline_base = 0
            self.trampoline_offset = 0
            self.page_offset = 0
        if self.cpid in [0x8010, 0x8011]:
            self.dfu_image_base = 0x1800B0000
            self.dfu_load_base = 0x800000000
            self.recovery_image_base = 0x1800B0000
            self.recovery_load_base = 0x800000000
            self.heap_base = 0
            self.heap_offset = 0
            self.trampoline_base = 0
            self.trampoline_offset = 0
            self.page_offset = 0
        if self.cpid in [0x8012, 0x8015]:
            self.dfu_image_base = 0x18001C000
            self.dfu_load_base = 0x800000000
            self.recovery_image_base = 0x18001C000
            self.recovery_load_base = 0x800000000
            self.heap_base = 0x1801E8000
            self.heap_offset = 0x5000
            self.trampoline_base = 0x180018000
            self.trampoline_offset = 0x620
            self.page_offset = 0x400
        if self.cpid in [0x8000, 0x8003, 0x7000]:
            self.dfu_image_base = 0x180380000
            self.dfu_load_base = 0x180000000  # varies (HACK: test purposes)
            self.recovery_image_base = 0x83D7F7000  # varies
            self.recovery_load_base = 0x800000000
            self.heap_base = 0
            self.heap_offset = 0
            self.trampoline_base = 0x00000001800c0000
            self.trampoline_offset = 0
            self.page_offset = 0

    def name(self):
        if 0x8720 <= self.cpid <= 0x8960:
            return f"s5l{self.cpid:02x}xsi"
        elif self.cpid in [0x7002, 0x8000, 0x8001, 0x8003]:
            return f"s{self.cpid:02x}si"
        else:
            return f"t{self.cpid:02x}si"


all_platforms = [
    DevicePlatform(
        cpid=0x8947,
        cprv=0x00,
        scep=0x10,
        arch="armv7",
        srtg="iBoot-1458.2",
        rom_base=0x3F000000,
        rom_size=0x10000,
        rom_sha1="d9320ddd4bdb1de79ae0601f20e7db23441ab1a7",
        sram_base=0x34000000,
        sram_size=0x40000,
        dram_base=0x80000000,
        nonce_length=20,
        sep_nonce_length=None,
        demotion_reg=0x3F500000,
        sigcheck_addr=0x451E,
        sigcheck_patch=0x0020,
        heap_state=0,
        heap_write_hash=0,
        heap_check_all=0,
    ),
    DevicePlatform(
        cpid=0x8950,
        cprv=0x20,
        scep=0x10,
        arch="armv7s",
        srtg="iBoot-1145.3",
        rom_base=0x3F000000,
        rom_size=0x10000,
        rom_sha1="50a8dd9863868c971aaf95a96e5152378784e4db",
        sram_base=0x10000000,
        sram_size=0x80000,
        dram_base=0x80000000,
        nonce_length=20,
        sep_nonce_length=None,
        demotion_reg=0x3F500000,
        sigcheck_addr=0x4D28,
        sigcheck_patch=0x0020,
        heap_state=0,
        heap_write_hash=0,
        heap_check_all=0,
    ),
    DevicePlatform(
        cpid=0x8955,
        cprv=0x20,
        scep=0x10,
        arch="armv7s",
        srtg="iBoot-1145.3.3",
        rom_base=0x3F000000,
        rom_size=0x10000,
        rom_sha1="3af575cc84e54f951db2a83227737664abdc8f40",
        sram_base=0x10000000,
        sram_size=0x80000,
        dram_base=0x80000000,
        nonce_length=20,
        sep_nonce_length=None,
        demotion_reg=0x3F500000,
        sigcheck_addr=0x4D28,
        sigcheck_patch=0x0020,
        heap_state=0,
        heap_write_hash=0,
        heap_check_all=0,
    ),
    DevicePlatform(
        cpid=0x8002,
        cprv=0x10,
        scep=0x01,
        arch="armv7k",
        srtg="iBoot-2651.0.0.1.31",
        rom_base=0x40000000,
        rom_size=0x100000,
        rom_sha1="46c14a17f54ec6079260e9253e813084ab1e634b",
        sram_base=0x48800000,
        sram_size=0x120000,
        dram_base=0x80000000,
        nonce_length=32,
        sep_nonce_length=20,
        demotion_reg=0x481BC000,
        sigcheck_addr=0x4452,
        sigcheck_patch=0x0020,
        heap_state=0,
        heap_write_hash=0,
        heap_check_all=0,
    ),
    DevicePlatform(
        cpid=0x8004,
        cprv=0x10,
        scep=0x01,
        arch="armv7k",
        srtg="iBoot-2651.0.0.3.3",
        rom_base=0x40000000,
        rom_size=0x20000,
        rom_sha1="8afdcd6c147ac63fddadd1b92536d1f80c0b8a21",
        sram_base=0x48800000,
        sram_size=0x140000,
        dram_base=0x80000000,
        nonce_length=32,
        sep_nonce_length=20,
        demotion_reg=0x481BC000,
        sigcheck_addr=0x4452,
        sigcheck_patch=0x0020,
        heap_state=0,
        heap_write_hash=0,
        heap_check_all=0,
    ),
    DevicePlatform(
        cpid=0x8960,
        cprv=0x11,
        scep=0x01,
        arch="arm64",
        srtg="iBoot-1704.10",
        rom_base=0x100000000,
        rom_size=0x80000,
        rom_sha1="2ae035c46e02ca40ae777f89a6637be694558f0a",
        sram_base=0x180000000,
        sram_size=0x400000,
        dram_base=0x800000000,
        nonce_length=20,
        sep_nonce_length=20,
        demotion_reg=0x20E02A000,
        sigcheck_addr=0x100005BE8,
        sigcheck_patch=0xD2800000,
        heap_state=0,
        heap_write_hash=0,
        heap_check_all=0,
    ),
    DevicePlatform(
        cpid=0x8010,
        cprv=0x11,
        scep=0x01,
        arch="arm64",
        srtg="iBoot-2696.0.0.1.33",
        rom_base=0x100000000,
        rom_size=0x20000,
        rom_sha1="41a488b3c46ff06c1a2376f3405b079fb0f15316",
        sram_base=0x180000000,
        sram_size=0x200000,
        dram_base=0x800000000,
        nonce_length=32,
        sep_nonce_length=20,
        demotion_reg=0x2102BC000,
        sigcheck_addr=0x1000074AC,
        sigcheck_patch=0xD2800000,
        heap_state=0,
        heap_write_hash=0,
        heap_check_all=0,
    ),
    DevicePlatform(
        cpid=0x8011,
        cprv=0x10,
        scep=0x01,
        arch="arm64",
        srtg="iBoot-3135.0.0.2.3",
        rom_base=0x100000000,
        rom_size=0x100000,
        rom_sha1="2fae20a11860b0e3ce1d8a6df7d3961f610ab70d",
        sram_base=0x180000000,
        sram_size=0x200000,
        dram_base=0x800000000,
        nonce_length=32,
        sep_nonce_length=20,
        demotion_reg=0x2102BC000,
        sigcheck_addr=0x100007630,
        sigcheck_patch=0xD2800000,
        heap_state=0,
        heap_write_hash=0,
        heap_check_all=0,
    ),
    DevicePlatform(
        cpid=0x8012,
        cprv=0x10,
        scep=0x01,
        arch="arm64",
        srtg="iBoot-3401.0.0.1.16",
        rom_base=0x100000000,
        rom_size=0x100000,
        rom_sha1="68be532dea4cc05b393ef5f49962aef3f99d629d",
        sram_base=0x180000000,
        sram_size=0x200000,
        dram_base=0x800000000,
        nonce_length=32,
        sep_nonce_length=20,
        demotion_reg=0x2112BC000,
        sigcheck_addr=0x100004854,
        sigcheck_patch=0xD2800000,
        heap_state=0x180008B60,
        heap_write_hash=0x10000D4E8,
        heap_check_all=0x10000DB88,
    ),
    DevicePlatform(
        cpid=0x8015,
        cprv=0x11,
        scep=0x01,
        arch="arm64",
        srtg="iBoot-3332.0.0.1.23",
        rom_base=0x100000000,
        rom_size=0x100000,
        rom_sha1="96fccb1a63de1a2d50ff14555d3898a5af46e9b1",
        sram_base=0x180000000,
        sram_size=0x200000,
        dram_base=0x800000000,
        nonce_length=32,
        sep_nonce_length=20,
        demotion_reg=0x2352BC000,
        sigcheck_addr=0x10000624C,
        sigcheck_patch=0xD2800000,
        heap_state=0x1800086A0,
        heap_write_hash=0x10000D4EC,
        heap_check_all=0x10000DB98,
    ),
    DevicePlatform(
        cpid=0x7000,
        cprv=0x11,
        scep=0x01,
        arch="arm64",
        srtg="iBoot-1992.0.0.1.19",
        rom_base=0x100000000,
        rom_size=0x80000,
        rom_sha1="c4dcd22ae135c14244fc2b62165c85effa566bfe",
        sram_base=0x180000000,
        sram_size=0x400000,
        dram_base=0x800000000,
        nonce_length=20,
        sep_nonce_length=20,
        demotion_reg=0x20E02A000,
        sigcheck_addr=0x100007E98,
        sigcheck_patch=0xD2800000,
        heap_state=0,
        heap_write_hash=0,
        heap_check_all=0,
    ),
    DevicePlatform(
        cpid=0x8000,
        cprv=0x20,
        scep=0x01,
        arch="arm64",
        srtg='"iBoot-2234.0.0.3.3',
        rom_base=0x100000000,
        rom_size=0x80000,
        rom_sha1="9979dce30e913c888cf77234c7a7e2a7fa676f4c",
        sram_base=0x180000000,
        sram_size=0x400000,
        dram_base=0x800000000,
        nonce_length=32,
        sep_nonce_length=20,
        demotion_reg=0x2102BC000,
        sigcheck_addr=0x10000812C,
        sigcheck_patch=0xD2800000,
        heap_state=0,
        heap_write_hash=0,
        heap_check_all=0,
    ),
    DevicePlatform(
        cpid=0x8003,
        cprv=0x01,
        scep=0x01,
        arch="arm64",
        srtg="iBoot-2234.0.0.2.22",
        rom_base=0x100000000,
        rom_size=0x80000,
        rom_sha1="93d69e2430e2f0c161e3e1144b69b4da1859169b",
        sram_base=0x180000000,
        sram_size=0x400000,
        dram_base=0x800000000,
        nonce_length=32,
        sep_nonce_length=20,
        demotion_reg=0x2102BC000,
        sigcheck_addr=0x10000812C,
        sigcheck_patch=0xD2800000,
        heap_state=0,
        heap_write_hash=0,
        heap_check_all=0,
    ),
]
