import pkgutil
import typing
from dataclasses import astuple, dataclass, field
from typing import Optional

import yaml


@dataclass
class USBConstants:
    load_address: int
    exec_magic: int
    done_magic: int
    memc_magic: int
    mems_magic: int
    usb_core_do_io: int

    @property
    def constants(self) -> typing.List[int]:
        return list(astuple(self))


@dataclass
class DevicePlatform:
    cpid: int
    cprv: int
    scep: int
    arch: str
    srtg: str
    rom_base: int
    rom_size: int
    rom_sha1: str
    sram_base: int
    sram_size: int
    dram_base: int
    nonce_length: int
    sep_nonce_length: Optional[int]
    demotion_reg: int
    sigcheck_addr: int
    sigcheck_patch: int
    dfu_image_base: int
    dfu_load_base: int
    recovery_image_base: int
    recovery_load_base: int
    usb: USBConstants
    heap_base: int = 0
    heap_offset: int = 0
    trampoline_base: int = 0
    trampoline_offset: int = 0
    page_offset: int = 0
    heap_state: int = 0
    heap_write_hash: int = 0
    heap_check_all: int = 0
    gadgets: typing.Dict[str, int] = field(default_factory=dict)
    exploit_configs: typing.Dict[str, dict] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.usb, dict):
            self.usb = USBConstants(**self.usb)

    def name(self) -> str:
        if 0x8720 <= self.cpid <= 0x8960:
            return f"s5l{self.cpid:02x}xsi"
        elif self.cpid in [0x7002, 0x8000, 0x8001, 0x8003]:
            return f"s{self.cpid:02x}si"
        else:
            return f"t{self.cpid:02x}si"

    @classmethod
    def platforms(cls) -> typing.Dict[int, "DevicePlatform"]:
        data = pkgutil.get_data("ipwndfu", "data/platforms.yaml")

        assert data

        entries = yaml.safe_load(data)

        return {
            int(entry["cpid"]): cls(**entry) for entry in entries["modern_platforms"]
        }

    @staticmethod
    def platform_for_cpid(
        cpid: typing.Union[int, str]
    ) -> typing.Optional["DevicePlatform"]:
        if isinstance(cpid, str):
            cpid = int(cpid, 16)

        return DevicePlatform.platforms()[cpid]


all_platforms = DevicePlatform.platforms().values()
