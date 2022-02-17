import subprocess
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


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
