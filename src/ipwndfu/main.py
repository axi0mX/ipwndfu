#!/usr/bin/env python3
# ipwndfu: open-source jailbreaking tool for older iOS devices
# Original Author: axi0mX
"""Main entry point to the ipwndfu utility for command line."""

import argparse
import hashlib
import sys
import time
from collections import namedtuple
from struct import pack
from sys import stderr, stdout

import libusbfinder
import usb.backend.libusb1  # type: ignore
from ipwndfu import (
    SHAtter,
    alloc8,
    checkm8,
    dfu,
    image3_24Kpwn,
    limera1n,
    nor,
    steaks4uce,
    t8012_heap_fix,
    usbexec,
)
from ipwndfu.dfuexec import (
    AES_DECRYPT,
    AES_ENCRYPT,
    AES_GID_KEY,
    AES_UID_KEY,
    PwnedDFUDevice,
)
from ipwndfu.utilities import hex_dump

TARGET_SOC = None


def print_help():
    print(
        """USAGE: ipwndfu [options]
Interact with an iOS device in DFU Mode.\n
Basic options:
  -p\t\t\t\tUSB exploit for pwned DFU Mode
  -x\t\t\t\tinstall alloc8 exploit to NOR
  -f file\t\t\tsend file to device in DFU Mode
  -l\t\t\t\tList devices connected in DFU mode
Advanced options:
  --dev=<filter>\t\tTarget a specific device. e.g. `--dev=8015` or `--dev=<ecid>`
  --demote\t\t\tdemote device to enable JTAG
  --boot\t\t\tboot device
  --repair-heap\t\t\trepair device heap
  --dump=address,length\t\tdump memory to stdout
  --hexdump=address,length\thexdump memory to stdout
  --dump-rom\t\t\tdump SecureROM
  --dump-nor=file\t\tdump NOR to file
  --flash-nor=file\t\tflash NOR (header and firmware only) from file
  --24kpwn\t\t\tinstall 24Kpwn exploit to NOR
  --remove-24kpwn\t\tremove 24Kpwn exploit from NOR
  --remove-alloc8\t\tremove alloc8 exploit from NOR
  --decrypt-gid=hexdata\t\tAES decrypt with GID key
  --encrypt-gid=hexdata\t\tAES encrypt with GID key
  --decrypt-uid=hexdata\t\tAES decrypt with UID key
  --encrypt-uid=hexdata\t\tAES encrypt with UID key"""
    )


def main():
    parser = argparse.ArgumentParser(prog="ipwndfu")

    parser.add_argument("-p", dest="pwn", action="store_true")
    parser.add_argument("-x", dest="xploit", action="store_true")
    parser.add_argument("-f", dest="send_file")
    parser.add_argument("-l", dest="list", action="store_true")

    parser.add_argument("--demote", dest="demote", action="store_true")
    parser.add_argument("--repair-heap", dest="repair_heap", action="store_true")
    parser.add_argument(
        "--patch-sigchecks", dest="patch_sigchecks", action="store_true"
    )
    parser.add_argument("--boot", dest="boot", action="store_true")
    parser.add_argument("--dev", dest="match_device")
    parser.add_argument("--dump", dest="dump")
    parser.add_argument("--reset", dest="reset", action="store_true")
    parser.add_argument("--hexdump", dest="hexdump")
    parser.add_argument("--dump-rom", dest="dump_rom", action="store_true")
    parser.add_argument("--dump-nor", dest="dump_nor")
    parser.add_argument("--flash-nor", dest="flash_nor")
    parser.add_argument("--24kpwn", dest="do_24kpwn", action="store_true")
    parser.add_argument("--remove-24kpwn", dest="remove_24kpwn", action="store_true")
    parser.add_argument("--remove-alloc8", dest="remove_alloc8", action="store_true")
    parser.add_argument("--decrypt-gid", dest="decrypt_gid")
    parser.add_argument("--encrypt-gid", dest="encrypt_gid")
    parser.add_argument("--decrypt-uid", dest="decrypt_uid")
    parser.add_argument("--encrypt_uid", dest="encrypt_uid")

    # remap argparse's internally generated help function to our nicely formatted one.
    parser.print_help = print_help

    args = parser.parse_args()

    if args.list:
        r = list_devices()
        sys.exit(r)

    device = None

    if args.match_device:
        device = dfu.acquire_device(match=args.match_device)

    if args.reset:
        dump(device, "0xDEADBEEF,0xFFFFFFF", match=args.match_device)
        sys.exit()

    elif args.pwn:
        pwn(device, match_device=args.match_device)

    elif args.xploit:
        xploit()

    elif args.send_file:
        send_file(args.send_file)

    elif args.demote:
        demote(device)

    elif args.repair_heap:
        repair_heap(device, match_device=args.match_device)

    elif args.patch_sigchecks:
        patch_sigchecks(device, match_device=args.match_device)

    elif args.boot:
        boot(device)

    elif args.dump:
        dump(device, args.dump)

    elif args.hexdump:
        hexdump(device, args.hexdump)

    elif args.dump_rom:
        dump_rom(device)

    elif args.dump_nor:
        dump_nor(args.dump_nor)

    elif args.flash_nor:
        flash_nor(args.flash_nor)

    elif args.do_24kpwn:
        do_24kpwn()

    elif args.remove_24kpwn:
        remove_24kpwn()

    elif args.remove_alloc8:
        remove_alloc8()

    elif args.decrypt_gid:
        print(decrypt_gid(device, args.decrypt_gid, match=args.match_device))

    elif args.encrypt_gid:
        print(encrypt_gid(device, args.encrypt_gid))

    elif args.decrypt_uid:
        print(decrypt_uid(device, args.decrypt_uid))

    elif args.encrypt_uid:
        print(encrypt_uid(device, args.encrypt_uid))

    else:
        print_help()


def pwn(device=None, match_device=None):
    if not device:
        device = dfu.acquire_device(match=match_device)

    serial = get_serial(device.serial_number)
    serial_number = device.serial_number
    dfu.release_device(device)

    if serial.cpid in ["8720"]:
        steaks4uce.exploit()
    elif serial.cpid in ["8920", "8922"]:
        limera1n.exploit()
    elif serial.cpid in ["8930"]:
        SHAtter.exploit()
    elif serial.cpid in [
        "8947",
        "8950",
        "8960",
        "8002",
        "8004",
        "8010",
        "8011",
        "8012",
        "8015",
    ]:
        checkm8.exploit(match=match_device)
    elif serial.cpid in ["7000", "8000", "8003"]:
        checkm8.exploit_a8_a9(match=match_device)
    else:
        print("Found: " + serial_number, file=stderr)
        print("ERROR: This device is not supported.", file=stderr)
        sys.exit(1)

    if serial.cpid in ["8012"]:
        t8012_heap_fix.fix_heap()


def xploit():
    device = PwnedDFUDevice()
    if device.config.cpid != "8920":
        print(
            "This is not a compatible device. alloc8 exploit is for iPhone 3GS only.",
            file=stderr,
        )
        sys.exit(1)

    if device.config.version == "359.3":
        print(
            "WARNING: iPhone 3GS (old bootrom) was detected. Use 24Kpwn exploit for faster "
            "boots, alloc8 exploit is for testing purposes only.",
            file=stderr,
        )
        input("Press ENTER to continue.")

    print("Installing alloc8 exploit to NOR.")

    dump_data = device.nor_dump(save_backup=True)

    nor_data = nor.NorData(dump_data)

    for byte in nor_data.parts[1]:
        if byte != "\x00":
            print(
                "ERROR: Bytes following IMG2 header in NOR are not zero. alloc8 "
                "exploit was likely previously installed. Exiting.",
                file=stderr,
            )
            sys.exit(1)
    if len(nor_data.images) == 0 or len(nor_data.images[0]) < 0x24000:
        print(
            "ERROR: 24Kpwn LLB was not found. You must restore a custom 24Kpwn IPSW before using this exploit.",
            file=stderr,
        )
        sys.exit(1)

    print("Preparing modified NOR with alloc8 exploit.")
    # Remove 24Kpwn first.
    nor_data.images[0] = image3_24Kpwn.remove_exploit(nor_data.images[0])
    new_nor = alloc8.exploit(nor_data, device.config.version)
    device.flash_nor(new_nor.dump())


def send_file(device=None, filename=""):
    try:
        with open(filename, "rb") as f:
            data = f.read()
    except IOError:
        print("ERROR: Could not read file: " + filename, file=stderr)
        sys.exit(1)

    if not device:
        device = dfu.acquire_device(match=TARGET_SOC)

    dfu.reset_counters(device)
    dfu.send_data(device, data)
    dfu.request_image_validation(device)
    dfu.release_device(device)


def demote(device=None):
    if not device:
        device = dfu.acquire_device()

    serial_number = device.serial_number
    dfu.release_device(device)

    if "PWND:[checkm8]" in serial_number:
        pwned = usbexec.PwnedUSBDevice()
        old_value = pwned.read_memory_uint32(pwned.platform.demotion_reg)
        print(f"Demotion register: 0x{old_value:x}")
        if old_value & 1:
            print("Attempting to demote device.")
            pwned.write_memory_uint32(
                pwned.platform.demotion_reg, old_value & 0xFFFFFFFE
            )
            new_value = pwned.read_memory_uint32(pwned.platform.demotion_reg)
            print(f"Demotion register: 0x{new_value:x}")
            if old_value != new_value:
                print("Success!")
            else:
                print("Failed.")
        else:
            print("WARNING: Device is already demoted.")
    else:
        print(
            "ERROR: Demotion is only supported on devices pwned with checkm8 exploit.",
            file=stderr,
        )
        sys.exit(1)


def dump(device=None, dump_args="", match=None):
    if not device:
        device = dfu.acquire_device()

    arg = dump_args
    if arg.count(",") != 1:
        print(
            "ERROR: You must provide exactly 2 comma separated values: address,length",
            file=stderr,
        )
        sys.exit(1)

    raw_address, raw_length = arg.split(",")
    address = (
        int(raw_address, 16) if raw_address.startswith("0x") else int(raw_address, 10)
    )
    length = int(raw_length, 16) if raw_length.startswith("0x") else int(raw_length, 10)

    serial_number = device.serial_number
    dfu.release_device(device)

    if "PWND:[checkm8]" in serial_number:
        device = usbexec.PwnedUSBDevice(match=match)
        stdout.write(device.read_memory(address, length))
    else:
        device = PwnedDFUDevice()
        print(device.read_memory(address, length))


def hexdump(device=None, arg=""):
    if not device:
        device = dfu.acquire_device()

    if arg.count(",") != 1:
        print(
            "ERROR: You must provide exactly 2 comma separated values: address,length",
            file=stderr,
        )
        sys.exit(1)

    raw_address, raw_length = arg.split(",")
    address = (
        int(raw_address, 16) if raw_address.startswith("0x") else int(raw_address, 10)
    )
    length = int(raw_length, 16) if raw_length.startswith("0x") else int(raw_length, 10)

    serial_number = device.serial_number
    dfu.release_device(device)

    if "PWND:[checkm8]" in serial_number:
        device = usbexec.PwnedUSBDevice()
        memory_dump = device.read_memory(address, length)
        for line in hex_dump(memory_dump, address).splitlines():
            print(f"{address:x}: {line[10:]}")
            address += 16
    else:
        device = PwnedDFUDevice()
        memory_dump = device.read_memory(address, length)
        print(hex_dump(memory_dump, address))


def dump_rom(device=None):
    if not device:
        device = dfu.acquire_device()

    serial_number = device.serial_number
    dfu.release_device(device)

    if "PWND:[checkm8]" in serial_number:
        pwned = usbexec.PwnedUSBDevice()
        securerom = pwned.read_memory(pwned.platform.rom_base, pwned.platform.rom_size)
        if hashlib.sha1(securerom).hexdigest() != pwned.platform.rom_sha1:
            print(hashlib.sha1(securerom).hexdigest(), file=stderr)
            print(
                "ERROR: SecureROM was dumped, but the SHA1 hash does not match. Exiting.",
                file=stderr,
            )
            sys.exit(1)
        chip = securerom[0x200:0x240].split(" ")[2][:-1]
        kind = securerom[0x240:0x280].split("\0")[0]
        version = securerom[0x280:0x2C0].split("\0")[0][6:]
        filename = f"SecureROM-{chip}-{version}-{kind}.dump"
        with open(filename, "wb") as f:
            f.write(securerom)
        print("Saved:", filename)
    else:
        device = PwnedDFUDevice()
        securerom = device.securerom_dump()
        filename = f"SecureROM-{device.config.version}-RELEASE.dump"
        with open(filename, "wb") as f:
            f.write(securerom)

        print("SecureROM dumped to file:", filename)


def decrypt_gid(device, arg, match=None):
    """Decrypt a given byte string using the devices GID (CHIP group key)."""

    if not device:
        device = dfu.acquire_device()

    serial_number = device.serial_number
    dfu.release_device(device)

    if "PWND:[checkm8]" in serial_number:
        pwned = usbexec.PwnedUSBDevice(match=match)
        print(f"Decrypting with {pwned.platform.name()} GID key.")
        aes = pwned.aes(
            bytes.fromhex(arg), usbexec.AES_DECRYPT, usbexec.AES_GID_KEY
        ).hex()
    else:
        device = PwnedDFUDevice()
        print(f"Decrypting with S5L{device.config.cpid} GID key.")
        aes = device.aes_hex(arg, AES_DECRYPT, AES_GID_KEY)

    print(aes)
    return aes


def encrypt_gid(device, arg):
    """Encrypt a bytestring with the GID (CHIP group key)."""

    if not device:
        device = dfu.acquire_device()

    serial_number = device.serial_number
    dfu.release_device(device)

    if "PWND:[checkm8]" in serial_number:
        pwned = usbexec.PwnedUSBDevice()
        print(f"Encrypting with {pwned.platform.name()} GID key.")
        aes = pwned.aes(
            bytes.fromhex(arg), usbexec.AES_ENCRYPT, usbexec.AES_GID_KEY
        ).hex()
    else:
        device = PwnedDFUDevice()
        print(f"Encrypting with S5L{device.config.cpid} GID key.")
        aes = device.aes_hex(arg, AES_ENCRYPT, AES_GID_KEY)

    print(aes)
    return aes


def decrypt_uid(device, arg):
    """Decrypt a byte string with the device specific (user key)."""

    if not device:
        device = dfu.acquire_device()

    serial_number = device.serial_number
    dfu.release_device(device)

    if "PWND:[checkm8]" in serial_number:
        pwned = usbexec.PwnedUSBDevice()
        print(f"Decrypting with {pwned.platform.name()} device-specific UID key.")
        aes = pwned.aes(
            bytes.fromhex(arg), usbexec.AES_DECRYPT, usbexec.AES_UID_KEY
        ).hex()
    else:
        device = PwnedDFUDevice()
        print("Decrypting with device-specific UID key.")
        aes = device.aes_hex(arg, AES_DECRYPT, AES_UID_KEY)

    print(aes)
    return aes


def encrypt_uid(device, arg):
    """Encrypt a byte string with a device specific (user key)."""

    if not device:
        device = dfu.acquire_device()

    serial_number = device.serial_number
    dfu.release_device(device)

    if "PWND:[checkm8]" in serial_number:
        pwned = usbexec.PwnedUSBDevice()
        print(f"Encrypting with {pwned.platform.name()} device-specific UID key.")
        aes = pwned.aes(
            bytes.fromhex(arg), usbexec.AES_ENCRYPT, usbexec.AES_UID_KEY
        ).hex()
    else:
        device = PwnedDFUDevice()
        print("Encrypting with device-specific UID key.")
        aes = device.aes_hex(arg, AES_ENCRYPT, AES_UID_KEY)

    print(aes)
    return aes


def list_devices():
    timeout = 5
    displayed_serials = []

    backend = usb.backend.libusb1.get_backend(
        find_library=lambda x: libusbfinder.libusb1_path()
    )
    start = time.time()
    once = False
    while not once or time.time() - start < timeout:
        once = True
        for device in usb.core.find(
            find_all=True, idVendor=0x5AC, idProduct=0x1227, backend=backend
        ):
            if device.serial_number in displayed_serials:
                continue
            print(device.serial_number)
            displayed_serials.append(device.serial_number)
        time.sleep(0.001)

    if len(displayed_serials) < 1:
        print(
            "ERROR: No Apple device in DFU Mode 0x1227 detected after %0.2f second timeout. Exiting."
            % timeout
        )
        return 1
    else:
        return 0


def repair_heap(device=None, match_device=None):
    if not device:
        device = dfu.acquire_device(match=match_device)
    serial = get_serial(device.serial_number)
    if serial.pwned:
        pwned = usbexec.PwnedUSBDevice()
        heap_base = pwned.heap_base()
        heap_offset = pwned.heap_offset()
        heap_state = pwned.platform.heap_state
        heap_write_hash = pwned.platform.heap_write_hash
        heap_check_all = pwned.platform.heap_check_all
        if any(
            addr == 0
            for addr in [
                heap_base,
                heap_offset,
                heap_state,
                heap_write_hash,
                heap_check_all,
            ]
        ):
            print("Device not supported for --repair-heap")
            return
        block1 = pack("<8Q", 0, 0, 0, heap_state, 2, 132, 128, 0)
        block2 = pack("<8Q", 0, 0, 0, heap_state, 2, 8, 128, 0)
        pwned.write_memory(heap_base + heap_offset, block1)
        pwned.write_memory(heap_base + heap_offset + 0x80, block2)
        pwned.write_memory(heap_base + heap_offset + 0x100, block2)
        pwned.write_memory(heap_base + heap_offset + 0x180, block2)
        pwned.execute(0, heap_write_hash, heap_base + heap_offset)
        pwned.execute(0, heap_write_hash, heap_base + heap_offset + 0x80)
        pwned.execute(0, heap_write_hash, heap_base + heap_offset + 0x100)
        pwned.execute(0, heap_write_hash, heap_base + heap_offset + 0x180)
        pwned.execute(0, heap_check_all)
        dfu.request_image_validation(device)
        dfu.release_device(device)
        print("Heap repaired.")
    else:
        print("Device not in pwndfu mode!")


def patch_sigchecks(device=None, match_device=None):
    if not device:
        device = dfu.acquire_device(match=match_device)
    serial = get_serial(device.serial_number)
    if serial.pwned:
        pwned = usbexec.PwnedUSBDevice()
        sigcheck_addr = pwned.platform.sigcheck_addr
        sigcheck_patch = pwned.platform.sigcheck_patch
        result = pwned.read_memory_uint32(sigcheck_addr)
        if any(addr == 0 for addr in [sigcheck_addr, sigcheck_patch]):
            print("Device not supported for --patch-sigchecks")
            return
        if result == sigcheck_patch:
            print("Signature checks are already patched out!")
            return
        trampoline_base = pwned.trampoline_base()
        trampoline_offset = pwned.trampoline_offset()
        page_offset = pwned.page_offset()
        addr_list = [page_offset]
        shellcode = checkm8.prepare_shellcode("patch_ttbr_page_arm64", addr_list)
        pwned.write_memory(trampoline_base + trampoline_offset, shellcode)
        pwned.execute(0, trampoline_base + trampoline_offset)
        pwned.write_memory_uint32(sigcheck_addr, sigcheck_patch)
        pwned.execute(
            0, trampoline_base + trampoline_offset + 0x30
        )  # offset of _inv_tlbi
        result = pwned.read_memory_uint32(sigcheck_addr)
        # print(f"DEBUG: pwned.read_memory_uint32(sigcheck_addr)): {hex(result)}")
        if result == sigcheck_patch:
            print("Successfully patched signature checks!")
        else:
            print("Failed to patch signature checks!")
    else:
        print("Device not in pwndfu mode!")


def boot(device=None):
    if not device:
        device = dfu.acquire_device()

    serial_number = device.serial_number
    dfu.release_device(device)

    if (
        "CPID:8015" not in serial_number
        and not any(f"BDID:{bdid}" in serial_number for bdid in ["6", "14"])
    ) or "PWND:[checkm8]" not in serial_number:
        print(serial_number)
        print(
            "ERROR: Option --boot is currently only supported on iPhone X pwned with checkm8.",
            file=stderr,
        )
    else:
        heap_base = 0x1801E8000
        heap_write_offset = 0x5000
        heap_write_hash = 0x10000D4EC
        heap_check_all = 0x10000DB98
        heap_state = 0x1800086A0
        nand_boot_jump = 0x10000188C
        bootstrap_task_lr = 0x180015F88
        dfu_bool = 0x1800085B0
        dfu_notify = 0x1000098B4
        dfu_state = 0x1800085E0
        trampoline = 0x180018000
        block1 = pack("<8Q", 0, 0, 0, heap_state, 2, 132, 128, 0)
        block2 = pack("<8Q", 0, 0, 0, heap_state, 2, 8, 128, 0)
        device = usbexec.PwnedUSBDevice()
        device.write_memory(heap_base + heap_write_offset, block1)
        device.write_memory(heap_base + heap_write_offset + 0x80, block2)
        device.write_memory(heap_base + heap_write_offset + 0x100, block2)
        device.write_memory(heap_base + heap_write_offset + 0x180, block2)
        device.execute(0, heap_write_hash, heap_base + heap_write_offset)
        device.execute(0, heap_write_hash, heap_base + heap_write_offset + 0x80)
        device.execute(0, heap_write_hash, heap_base + heap_write_offset + 0x100)
        device.execute(0, heap_write_hash, heap_base + heap_write_offset + 0x180)
        device.execute(0, heap_check_all)
        print("Heap repaired.")

        with open("bin/t8015_shellcode_arm64.bin") as f:
            shellcode = f.read()

            device.write_memory(
                trampoline, checkm8.asm_arm64_branch(trampoline, trampoline + 0x400)
            )
            device.write_memory(trampoline + 0x400, shellcode)

            device.write_memory_ptr(bootstrap_task_lr, nand_boot_jump)
            device.write_memory(dfu_bool, "\x01")
            device.execute(0, dfu_notify, dfu_state)
            print("Booted.")


def dump_nor(arg):
    device = PwnedDFUDevice()
    if device.config.cpid != "8920":
        print(
            "This is not a compatible device. Dumping NOR is only supported on iPhone 3GS.",
            file=stderr,
        )
        sys.exit(1)
    nor_data = device.nor_dump(save_backup=False)
    with open(arg, "wb") as f:
        f.write(nor_data)

    print(f"NOR dumped to file: {arg}")


def flash_nor(arg):
    print("Flashing NOR from file:", arg)
    new_nor = None
    with open(arg, "rb") as f:
        new_nor = f.read()

    if new_nor[:4] != "IMG2"[::-1]:
        print(
            "ERROR: Bad IMG2 header magic. This is not a valid NOR. Exiting.",
            file=stderr,
        )
        sys.exit(1)

    device = PwnedDFUDevice()
    if device.config.cpid != "8920":
        print(
            "This is not a compatible device. Flashing NOR is only supported on iPhone 3GS.",
            file=stderr,
        )
        sys.exit(1)
    device.nor_dump(save_backup=True)
    device.flash_nor(new_nor)


def do_24kpwn(device=None):
    """Use the 24kpwn technique against the selected device."""

    print(
        "*** based on 24Kpwn exploit (segment overflow) by chronic, CPICH, ius, MuscleNerd, "
        "Planetbeing, pod2g, posixninja, et al. ***"
    )

    if not device:
        device = PwnedDFUDevice()

    if device.config.version != "359.3":
        print("Only iPhone 3GS (old bootrom) is supported.", file=stderr)
        sys.exit(1)

    dump_data = device.nor_dump(save_backup=True)

    print("Preparing modified NOR with 24Kpwn exploit.")
    nor_data = nor.NorData(dump_data)
    for byte in nor_data.parts[1]:
        if byte != "\x00":
            print(
                "ERROR: Bytes following IMG2 header in NOR are not zero. "
                "alloc8 exploit was likely previously installed. Exiting.",
                file=stderr,
            )
            sys.exit(1)

    if len(nor_data.images) == 0:
        print(
            "ERROR: 24Kpwn exploit cannot be installed, because NOR has no valid LLB. Exiting.",
            file=stderr,
        )
        sys.exit(1)

    # Remove existing 24Kpwn exploit.
    if len(nor_data.images[0]) > 0x24000:
        nor_data.images[0] = image3_24Kpwn.remove_exploit(nor_data.images[0])
    nor_data.images[0] = image3_24Kpwn.exploit(
        nor_data.images[0], device.securerom_dump()
    )
    device.flash_nor(nor_data.dump())


def remove_24kpwn(device=None):
    """Remove a 24kpwn exploit from a device."""

    if not device:
        device = PwnedDFUDevice()
    if device.config.cpid != "8920":
        print(
            "This is not a compatible device. 24Kpwn exploit is only supported on iPhone 3GS.",
            file=stderr,
        )
        sys.exit(1)

    print(
        "WARNING: This feature is for researchers only. Device will probably not boot into "
        "iOS until it is restored in iTunes."
    )
    input("Press ENTER to continue.")

    dump_data = device.nor_dump(save_backup=True)

    nor_data = nor.NorData(dump_data)

    if len(nor_data.images) == 0:
        print(
            "ERROR: NOR has no valid LLB. It seems that 24Kpwn exploit is not installed. Exiting.",
            file=stderr,
        )
        sys.exit(1)
    if len(nor_data.images[0]) <= 0x24000:
        print(
            "ERROR: LLB is not oversized. It seems that 24Kpwn exploit is not installed. Exiting.",
            file=stderr,
        )
        sys.exit(1)

    print("Preparing modified NOR without 24Kpwn exploit.")
    nor_data.images[0] = image3_24Kpwn.remove_exploit(nor_data.images[0])
    device.flash_nor(nor_data.dump())


def remove_alloc8(device=None):
    """Remove alloc8 exploit from a device."""

    if device is None:
        device = PwnedDFUDevice()

    if device.config.cpid != "8920":
        print(
            "This is not a compatible device. alloc8 exploit is for iPhone 3GS only.",
            file=stderr,
        )
        sys.exit(1)

    print(
        "WARNING: This feature is for researchers only. Device will probably not "
        "boot into iOS until it is restored in iTunes.",
        file=stderr,
    )
    input("Press ENTER to continue.")

    dump_data = device.nor_dump(save_backup=True)

    nor_data = nor.NorData(dump_data)

    if len(nor_data.images) < 700:
        print(
            "ERROR: It seems that alloc8 exploit is not installed. There are less than 700 images in NOR. Exiting.",
            file=stderr,
        )
        sys.exit(1)

    print("Preparing modified NOR without alloc8 exploit.")
    new_nor = alloc8.remove_exploit(nor_data)
    device.flash_nor(new_nor.dump())


# this bit nicely divvys up a standard DFU usb serial string into a usable 'object' representing its fields

SerialNumber = namedtuple(
    "SerialNumber",
    ["cpid", "cprv", "cpfm", "scep", "bdid", "ecid", "ibfl", "srtg", "pwned"],
)


def get_serial(_serial) -> SerialNumber:
    """Parse a serial number (from the USB device) into its key-value pairings."""

    tokens = _serial.split(" ")
    cpid = ""
    cprv = ""
    cpfm = ""
    scep = ""
    bdid = ""
    ecid = ""
    ibfl = ""
    srtg = ""
    pwned = False
    for t in tokens:
        v = t.split(":")[-1]
        if "CPID:" in t:
            cpid = v
        elif "CPRV" in t:
            cprv = v
        elif "CPFM" in t:
            cpfm = v
        elif "SCEP" in t:
            scep = v
        elif "BDID" in t:
            bdid = v
        elif "ECID" in t:
            ecid = v
        elif "IBFL" in t:
            ibfl = v
        elif "SRTG" in t:
            srtg = v
        elif "PWND" in t:
            pwned = True
    return SerialNumber(cpid, cprv, cpfm, scep, bdid, ecid, ibfl, srtg, pwned)


if __name__ == "__main__":
    main()
