from __future__ import print_function
import sys, time
import usb # pyusb: use 'pip install pyusb' to install this module
import usb.backend.libusb1
import libusbfinder

MAX_PACKET_SIZE = 0x800

def acquire_device(timeout=5.0, match=None, fatal=True):
  backend = usb.backend.libusb1.get_backend(find_library=lambda x:libusbfinder.libusb1_path())
  #print 'Acquiring device handle.'
  # Keep retrying for up to timeout seconds if device is not found.
  start = time.time()
  once = False
  while not once or time.time() - start < timeout:
      once = True
      for device in usb.core.find(find_all=True, idVendor=0x5AC, idProduct=0x1227, backend=backend):
          if match is not None and match not in device.serial_number:
              continue
          return device
      time.sleep(0.001)
  if fatal:
      print('ERROR: No Apple device in DFU Mode 0x1227 detected after %0.2f second timeout. Exiting.' % timeout)
      sys.exit(1)
  return None

def release_device(device):
    #print 'Releasing device handle.'
    usb.util.dispose_resources(device)

def reset_counters(device):
    #print 'Resetting USB counters.'
    assert device.ctrl_transfer(0x21, 4, 0, 0, 0, 1000) == 0

def usb_reset(device):
    #print 'Performing USB port reset.'
    try:
        device.reset()
    except usb.core.USBError:
        # OK: doesn't happen on Yosemite but happens on El Capitan and Sierra
        pass
        #print 'Caught exception during port reset; should still work.'

def send_data(device, data):
    #print 'Sending 0x%x of data to device.' % len(data)
    index = 0
    while index < len(data):
        amount = min(len(data) - index, MAX_PACKET_SIZE)
        assert device.ctrl_transfer(0x21, 1, 0, 0, data[index:index + amount], 5000) == amount
        index += amount

def get_data(device, amount):
    #print 'Getting 0x%x of data from device.' % amount
    data = str()
    while amount > 0:
        part = min(amount, MAX_PACKET_SIZE)
        ret = device.ctrl_transfer(0xA1, 2, 0, 0, part, 5000)
        assert len(ret) == part
        data += ret.tostring()
        amount -= part
    return data

def request_image_validation(device):
    #print 'Requesting image validation.'
    assert device.ctrl_transfer(0x21, 1, 0, 0, '', 1000) == 0
    device.ctrl_transfer(0xA1, 3, 0, 0, 6, 1000)
    device.ctrl_transfer(0xA1, 3, 0, 0, 6, 1000)
    device.ctrl_transfer(0xA1, 3, 0, 0, 6, 1000)
    usb_reset(device)
