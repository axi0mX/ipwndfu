import subprocess
import sys
from collections import namedtuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def from_hex_str(dat: str) -> bytes:
    return bytes(bytearray.fromhex(dat))


def apply_patches(binary, patches):
    for (offset, data) in patches:
        binary = binary[:offset] + data + binary[offset + len(data) :]
    return binary


def aes_decrypt(data: bytes, iv: bytes, key: bytes) -> bytes:
    cipher = Cipher(algorithm=algorithms.AES(key), mode=modes.CBC(iv))
    decrypter = cipher.decryptor()

    return decrypter.update(data) + decrypter.finalize()


def hex_dump(data, address):
    p = subprocess.Popen(
        ["xxd", "-o", str(address)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    (stdout, stderr) = p.communicate(input=data)

    if p.returncode != 0 or len(stderr) > 0:
        print(f"ERROR: xxd failed: {stderr}")
        sys.exit(1)

    return stdout


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
