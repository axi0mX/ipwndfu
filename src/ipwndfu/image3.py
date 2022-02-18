from __future__ import annotations

import binascii
import dataclasses
import struct

from ipwndfu.dfuexec import PwnedDFUDevice
from ipwndfu.utilities import aes_decrypt


@dataclasses.dataclass
class Image3Tag:
    tag_magic: bytes
    tag_total_size: int
    tag_data_size: int
    tag_data: bytes


class Image3:
    magic: bytes
    total_size: int
    data_size: int
    signed_size: int
    type: bytes
    tags: list[Image3Tag]

    def __init__(self, data):
        (
            self.magic,
            self.total_size,
            self.data_size,
            self.signed_size,
            self.type,
        ) = struct.unpack("4s3I4s", data[0:20])
        self.tags = []
        pos = 20
        while pos < 20 + self.data_size:
            (_tag_magic, _tag_total_size, _tag_data_size) = struct.unpack(
                "4s2I", data[pos : pos + 12]
            )
            tag = Image3Tag(
                _tag_magic,
                _tag_total_size,
                _tag_data_size,
                data[pos + 12 : pos + _tag_total_size],
            )
            self.tags.append(tag)

            pos += _tag_total_size
            if _tag_total_size == 0:
                break

    @staticmethod
    def create_image3_from_tags(img_type, tags):
        data_size = 0
        signed_size = 0
        for tag in tags:
            data_size += 12 + len(tag.tag_data)
            if tag.tag_magic[::-1] not in ["CERT", "SHSH"]:
                signed_size += 12 + len(tag.tag_data)

        # total_size must be rounded up to 64-byte boundary
        total_size = 20 + data_size
        remainder = total_size % 64
        if remainder != 0:
            total_size += 64 - remainder

        data_bytes = struct.pack(
            "4s3I4s", "Img3"[::-1], total_size, data_size, signed_size, img_type
        )
        for (tag_magic, tag_total_size, tag_data_size, tag_data) in tags:
            data_bytes += (
                struct.pack("4s2I", tag_magic, tag_total_size, tag_data_size) + tag_data
            )
        return data_bytes + b"\x00" * (total_size - len(data_bytes))

    def get_tags(self, magic) -> list[Image3Tag]:
        matches = []
        for tag in self.tags:
            if tag.tag_magic == magic:
                matches.append(tag)
        return matches

    def get_keybag(self):
        keybags = self.get_tags("KBAG"[::-1])
        for tag in keybags:
            (kbag_type, aes_type) = struct.unpack("<2I", tag.tag_data[:8])
            if kbag_type == 1:
                return tag.tag_data[8 : 8 + 48]
        return None

    def get_payload(self):
        data = self.get_tags(b"DATA"[::-1])
        if len(data) == 1:
            return data[0].tag_data

    def get_decrypted_payload(self):
        keybag = self.get_keybag()
        device = PwnedDFUDevice()
        decrypted_keybag = device.decrypt_keybag(keybag)
        return aes_decrypt(
            self.get_payload(),
            binascii.hexlify(decrypted_keybag[:16]),
            binascii.hexlify(decrypted_keybag[16:]),
        )

    def shrink24_kpwn_certificate(self):
        for i in range(len(self.tags)):
            tag = self.tags[i]
            if tag.tag_magic == b"CERT"[::-1] and len(tag.tag_data) >= 3072:
                data = tag.tag_data[:3072]
                assert data[-1] == b"\x00"
                data = data.rstrip(b"\x00")
                self.tags[i] = Image3Tag(b"CERT"[::-1], 12 + len(data), len(data), data)
                break

    def new_image3(self, decrypted=True):
        type_tag = self.get_tags(b"TYPE"[::-1])
        assert len(type_tag) == 1
        vers_tag = self.get_tags(b"VERS"[::-1])
        assert len(vers_tag) <= 1
        data_tag = self.get_tags(b"DATA"[::-1])
        assert len(data_tag) == 1
        sepo_tag = self.get_tags(b"SEPO"[::-1])
        assert len(sepo_tag) <= 2
        bord_tag = self.get_tags(b"BORD"[::-1])
        assert len(bord_tag) <= 2
        kbag_tag = self.get_tags(b"KBAG"[::-1])
        assert len(kbag_tag) <= 2
        shsh_tag = self.get_tags(b"SHSH"[::-1])
        assert len(shsh_tag) <= 1
        cert_tag = self.get_tags(b"CERT"[::-1])
        assert len(cert_tag) <= 1

        (tag_magic, tag_total_size, tag_data_size, tag_data) = data_tag[0]
        if len(kbag_tag) > 0 and decrypted:
            new_tag_data = self.get_decrypted_payload()
            kbag_tag = []
        else:
            new_tag_data = tag_data
        assert len(tag_data) == len(new_tag_data)

        return Image3.create_image3_from_tags(
            self.type,
            type_tag
            + [Image3Tag(tag_magic, tag_total_size, tag_data_size, new_tag_data)]
            + vers_tag
            + sepo_tag
            + bord_tag
            + kbag_tag
            + shsh_tag
            + cert_tag,
        )
