class DevicePlatform:
  def __init__(self, cpid, cprv, scep, arch, srtg, rom_base, rom_size, rom_sha1, sram_base, sram_size, dram_base, nonce_length, sep_nonce_length, demotion_reg):
    self.cpid             = cpid
    self.cprv             = cprv
    self.scep             = scep
    self.arch             = arch
    self.srtg             = srtg
    self.rom_base         = rom_base
    self.rom_size         = rom_size
    self.rom_sha1         = rom_sha1
    self.sram_base        = sram_base
    self.sram_size        = sram_size
    self.dram_base        = dram_base
    self.nonce_length     = nonce_length
    self.sep_nonce_length = sep_nonce_length
    self.demotion_reg     = demotion_reg
    if self.cpid in [0x8940, 0x8947]:
      self.dfu_image_base      = 0x34000000
      self.dfu_load_base       = 0x9FF00000
      self.recovery_image_base = 0x9FF00000
      self.recovery_load_base  = 0x80000000
    if self.cpid in [0x8950, 0x8955]:
      self.dfu_image_base      = 0x10000000
      self.dfu_load_base       = 0xBFF00000
      self.recovery_image_base = 0xBFF00000
      self.recovery_load_base  = 0x80000000
    if self.cpid == 0x8960:
      self.dfu_image_base      = 0x180380000
      self.dfu_load_base       = 0x180000000 # varies (HACK: test purposes)
      self.recovery_image_base = 0x83D7F7000 # varies
      self.recovery_load_base  = 0x800000000
    if self.cpid in [0x8002, 0x8004]:
      self.dfu_image_base      = 0x48818000
      self.dfu_load_base       = 0x80000000
      self.recovery_image_base = 0x48818000
      self.recovery_load_base  = 0x80000000
    if self.cpid in [0x8010, 0x8011]:
      self.dfu_image_base      = 0x1800B0000
      self.dfu_load_base       = 0x800000000
      self.recovery_image_base = 0x1800B0000
      self.recovery_load_base  = 0x800000000
    if self.cpid in [0x8015]:
      self.dfu_image_base      = 0x18001C000
      self.dfu_load_base       = 0x800000000
      self.recovery_image_base = 0x18001C000
      self.recovery_load_base  = 0x800000000

  def name(self):
    if 0x8720 <= self.cpid <= 0x8960:
      return 's5l%xxsi' % self.cpid
    elif self.cpid in [0x7002, 0x8000, 0x8001, 0x8003]:
      return 's%xsi' % self.cpid
    else:
      return 't%xsi' % self.cpid

all_platforms = [
  DevicePlatform(cpid=0x8947, cprv=0x00, scep=0x10, arch='armv7', srtg='iBoot-1458.2',
    rom_base=0x3F000000, rom_size=0x10000, rom_sha1='d9320ddd4bdb1de79ae0601f20e7db23441ab1a7',
    sram_base=0x34000000, sram_size=0x40000,
    dram_base=0x80000000,
    nonce_length=20, sep_nonce_length=None,
    demotion_reg=0x3F500000,
  ),
  DevicePlatform(cpid=0x8950, cprv=0x20, scep=0x10, arch='armv7s', srtg='iBoot-1145.3',
    rom_base=0x3F000000, rom_size=0x10000, rom_sha1='50a8dd9863868c971aaf95a96e5152378784e4db',
    sram_base=0x10000000, sram_size=0x80000,
    dram_base=0x80000000,
    nonce_length=20, sep_nonce_length=None,
    demotion_reg=0x3F500000,
  ),
  DevicePlatform(cpid=0x8955, cprv=0x20, scep=0x10, arch='armv7s', srtg='iBoot-1145.3.3',
    rom_base=0x3F000000, rom_size=0x10000, rom_sha1='3af575cc84e54f951db2a83227737664abdc8f40',
    sram_base=0x10000000, sram_size=0x80000,
    dram_base=0x80000000,
    nonce_length=20, sep_nonce_length=None,
    demotion_reg=0x3F500000,
  ),
  DevicePlatform(cpid=0x8002, cprv=0x10, scep=0x01, arch='armv7k', srtg='iBoot-2651.0.0.1.31',
    rom_base=0x40000000, rom_size=0x100000, rom_sha1='46c14a17f54ec6079260e9253e813084ab1e634b',
    sram_base=0x48800000, sram_size=0x120000,
    dram_base=0x80000000,
    nonce_length=32, sep_nonce_length=20,
    demotion_reg=0x481BC000,
  ),
  DevicePlatform(cpid=0x8004, cprv=0x10, scep=0x01, arch='armv7k', srtg='iBoot-2651.0.0.3.3',
    rom_base=0x40000000, rom_size=0x20000, rom_sha1='8afdcd6c147ac63fddadd1b92536d1f80c0b8a21',
    sram_base=0x48800000, sram_size=0x140000,
    dram_base=0x80000000,
    nonce_length=32, sep_nonce_length=20,
    demotion_reg=0x481BC000,
  ),
  DevicePlatform(cpid=0x8960, cprv=0x11, scep=0x01, arch='arm64', srtg='iBoot-1704.10',
    rom_base=0x100000000, rom_size=0x80000, rom_sha1='2ae035c46e02ca40ae777f89a6637be694558f0a',
    sram_base=0x180000000, sram_size=0x400000,
    dram_base=0x800000000,
    nonce_length=20, sep_nonce_length=20,
    demotion_reg=0x20E02A000,
  ),
  DevicePlatform(cpid=0x8010, cprv=0x11, scep=0x01, arch='arm64', srtg='iBoot-2696.0.0.1.33',
    rom_base=0x100000000, rom_size=0x20000, rom_sha1='41a488b3c46ff06c1a2376f3405b079fb0f15316',
    sram_base=0x180000000, sram_size=0x200000,
    dram_base=0x800000000,
    nonce_length=32, sep_nonce_length=20,
    demotion_reg=0x2102BC000,
  ),
  DevicePlatform(cpid=0x8011, cprv=0x10, scep=0x01, arch='arm64', srtg='iBoot-3135.0.0.2.3',
    rom_base=0x100000000, rom_size=0x100000, rom_sha1='2fae20a11860b0e3ce1d8a6df7d3961f610ab70d',
    sram_base=0x180000000, sram_size=0x200000,
    dram_base=0x800000000,
    nonce_length=32, sep_nonce_length=20,
    demotion_reg=0x2102BC000,
  ),
  DevicePlatform(cpid=0x8015, cprv=0x11, scep=0x01, arch='arm64', srtg='iBoot-3332.0.0.1.23',
    rom_base=0x100000000, rom_size=0x100000, rom_sha1='96fccb1a63de1a2d50ff14555d3898a5af46e9b1',
    sram_base=0x180000000, sram_size=0x200000,
    dram_base=0x800000000,
    nonce_length=32, sep_nonce_length=20,
    demotion_reg=0x2352BC000,
  ),
]
