"""Script to send a junk img4 payload to a DFU device."""

from ipwndfu import dfu, usbexec

HOST2DEVICE = 0x21
DFU_ABORT = 4

device = dfu.acquire_device()
assert device
d = usbexec.PwnedUSBDevice()

BASE = 0x17A000000 - 0x100000000

d.write_memory(0x1000019E4 + BASE, "\x1f\x20\x03\xd5\x19\x00\x80\xd2")

device.ctrl_transfer(HOST2DEVICE, DFU_ABORT, 0, 0, 0, 0)
dfu.usb_reset(device)
dfu.release_device(device)
print("Removed image_load call; all incoming images will be loaded as raw")
