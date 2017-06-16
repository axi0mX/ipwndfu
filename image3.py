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

    def shrink24KpwnCertificate(self):
        for i in range(len(self.tags)):
            tag = self.tags[i]
            if tag[0] == 'CERT'[::-1] and len(tag[3]) >= 3072:
                data = tag[3][:3072]
                assert data[-1] == '\x00'
                data = data.rstrip('\x00')
                self.tags[i] = ('CERT'[::-1], 12 + len(data), len(data), data)
                break

    def newImage3(self, decrypted=True):
        typeTag = self.getTags('TYPE'[::-1])
        assert len(typeTag) == 1
        versTag = self.getTags('VERS'[::-1])
        assert len(versTag) <= 1
        dataTag = self.getTags('DATA'[::-1])
        assert len(dataTag) == 1
        sepoTag = self.getTags('SEPO'[::-1])
        assert len(sepoTag) <= 2
        bordTag = self.getTags('BORD'[::-1])
        assert len(bordTag) <= 2
        kbagTag = self.getTags('KBAG'[::-1])
        assert len(kbagTag) <= 2
        shshTag = self.getTags('SHSH'[::-1])
        assert len(shshTag) <= 1
        certTag = self.getTags('CERT'[::-1])
        assert len(certTag) <= 1

        (tagMagic, tagTotalSize, tagDataSize, tagData) = dataTag[0]
        if len(kbagTag) > 0 and decrypted:
          newTagData = self.getDecryptedPayload()
          kbagTag = []
        else:
          newTagData =  tagData
        assert len(tagData) == len(newTagData)

        return Image3.createImage3FromTags(self.type, typeTag + [(tagMagic, tagTotalSize, tagDataSize, newTagData)] + versTag + sepoTag + bordTag + kbagTag + shshTag + certTag)
