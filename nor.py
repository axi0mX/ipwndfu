import binascii, struct

NOR_SIZE = 0x100000

class NorData():
    def __init__(self, dump):
        assert len(dump) == NOR_SIZE

        (img2_magic, self.block_size, unused, firmware_block, firmware_block_count) = struct.unpack('<4s4I', dump[:20])
        (img2_crc,) = struct.unpack('<I', dump[48:52])
        assert img2_crc == binascii.crc32(dump[:48]) & 0xffffffff

        self.firmware_offset = self.block_size * firmware_block
        self.firmware_length = self.block_size * firmware_block_count
        self.parts = [
          dump[0:52],
          dump[52:512],
          dump[512:self.firmware_offset],
          dump[self.firmware_offset:self.firmware_offset + self.firmware_length],
          dump[self.firmware_offset + self.firmware_length:]
        ]

        self.images = []
        offset = 0
        while 1:
            (magic, size) = struct.unpack('<4sI', self.parts[3][offset:offset+8])
            if magic != 'Img3'[::-1] or size == 0:
                break
            self.images.append(self.parts[3][offset:offset + size])
            offset += size

    def dump(self):
        # Replace self.parts[3] with content of self.images
        all_images = ''.join(self.images)
        all_images += '\xff' * (self.firmware_length - len(all_images))
        dump = self.parts[0] + self.parts[1] + self.parts[2] + all_images + self.parts[4]
        assert len(dump) == NOR_SIZE
        return dump
