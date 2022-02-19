"""Module for interacting via the DFU interface with a given device."""

import sys
import time
from contextlib import suppress
from typing import TYPE_CHECKING, Optional

import libusbfinder
import usb  # type: ignore
import usb.backend.libusb1  # type: ignore

if TYPE_CHECKING:
    from usb.core import Device  # type: ignore

MAX_PACKET_SIZE = 0x800


def acquire_device(
    timeout: float = 5.0, match: Optional[str] = None, fatal: bool = True
) -> Optional["Device"]:
    """Creates a connection to a given device and gets basic state.

    Parameters
    ----------
    timeout : float
        How long to wait before aborting the operation
    match : str
        A string that must match the serial number string to select specific devices
    fatal : bool
        If a failure to acquire the device should exit the program
    """
    backend = usb.backend.libusb1.get_backend(
        find_library=lambda x: libusbfinder.libusb1_path()
    )
    # Keep retrying for up to timeout seconds if device is not found.
    start = time.time()
    once = False
    while not once or time.time() - start < timeout:
        once = True
        for device in usb.core.find(
            find_all=True, idVendor=0x5AC, idProduct=0x1227, backend=backend
        ):
            if match is not None and match not in device.serial_number:
                continue
            return device
        time.sleep(0.001)
    if fatal:
        print(
            f"ERROR: No Apple device in DFU Mode 0x1227 detected after {timeout:0.2f} second timeout. Exiting."
        )
        sys.exit(1)
    return None


def release_device(device: "Device") -> None:
    """Terminates a DFU session."""
    usb.util.dispose_resources(device)


def reset_counters(device: "Device"):
    assert device.ctrl_transfer(0x21, 4, 0, 0, 0, 1000) == 0


def usb_reset(device: "Device") -> None:
    """Perform a DFU bus level reset event."""
    with suppress(usb.core.USBError):
        device.reset()


def send_data(device: "Device", data: bytes):
    """Send a payload to the device."""
    index = 0
    while index < len(data):
        amount = min(len(data) - index, MAX_PACKET_SIZE)
        assert (
            device.ctrl_transfer(0x21, 1, 0, 0, data[index : index + amount], 5000)
            == amount
        )
        index += amount


def get_data(device: "Device", amount: int) -> bytes:
    """Reads a number of bytes back from the DFU interface (control endpoint 0)."""
    data = bytes()
    while amount > 0:
        part = min(amount, MAX_PACKET_SIZE)
        ret = device.ctrl_transfer(0xA1, 2, 0, 0, part, 5000)
        assert len(ret) == part
        data += ret.tobytes()
        amount -= part
    return data


def request_image_validation(device: "Device"):
    assert device.ctrl_transfer(0x21, 1, 0, 0, "", 1000) == 0
    device.ctrl_transfer(0xA1, 3, 0, 0, 6, 1000)
    device.ctrl_transfer(0xA1, 3, 0, 0, 6, 1000)
    device.ctrl_transfer(0xA1, 3, 0, 0, 6, 1000)
    usb_reset(device)
