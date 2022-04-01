#!/usr/bin/env python3
# ipwnrecovery: open-source jailbreaking tool for older iOS devices

import getopt
import sys
from contextlib import suppress

import usb  # type: ignore
from ipwndfu import recovery


def print_help():
    print("USAGE: ipwnrecovery [options]")
    print("Interact with an iOS device in Recovery Mode.\n")
    print("Basic options:")
    print("  -c cmd\t\t\trun command on device")
    print("  -f file\t\t\tsend file to device in Recovery Mode")
    print("Advanced options:")
    print("  --enable-uart\t\t\tset debug-uarts to 3 and reboot device")
    print("  --exit-recovery-loop\t\tenable auto-boot and reboot device")


if __name__ == "__main__":
    try:
        advanced = ["exit-recovery-loop", "enable-uart"]
        opts, args = getopt.getopt(sys.argv[1:], "c:f:", advanced)
    except getopt.GetoptError:
        print("ERROR: Invalid arguments provided.")
        print_help()
        sys.exit(2)

    if len(opts) == 0:
        print_help()
        sys.exit(2)

    for opt, arg in opts:
        if opt == "-c":
            device = recovery.acquire_device()
            try:
                recovery.send_command(device, arg)
            except usb.core.USBError:
                print("WARNING: Caught USBError after running command.")
            recovery.release_device(device)

        if opt == "-f":
            try:
                with open(arg, "rb") as f:
                    data = f.read()
            except IOError:
                print("ERROR: Could not read file:", arg)
                sys.exit(1)

            device = recovery.acquire_device()
            recovery.send_data(device, data)
            recovery.release_device(device)

        if opt == "--exit-recovery-loop":
            device = recovery.acquire_device()

            # TODO: getenv auto-boot first and fail if it is already true.
            recovery.send_command(device, "setenv auto-boot true")
            recovery.send_command(device, "saveenv")
            with suppress(usb.core.USBError):
                recovery.send_command(device, "reboot")

            recovery.release_device(device)

        if opt == "--enable-uart":
            device = recovery.acquire_device()

            # TODO: getenv debug-uarts first and fail if it is already 3.
            recovery.send_command(device, "setenv debug-uarts 3")
            recovery.send_command(device, "saveenv")
            with suppress(usb.core.USBError):
                recovery.send_command(device, "reboot")

            recovery.release_device(device)
