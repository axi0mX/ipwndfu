import hashlib, os, platform, cStringIO, tarfile

class VersionConfig:
    def __init__(self, version, bottle, bottle_sha256, dylib_patches, dylib_sha256):
        self.version = version
        self.bottle = bottle
        self.bottle_sha256 = bottle_sha256
        self.dylib_patches = dylib_patches
        self.dylib_sha256 = dylib_sha256

configs = [
    VersionConfig(
        version='10.12',
        bottle='libusb-1.0.21.sierra.bottle',
        bottle_sha256='e42e21cc9b7cd4223eb8050680ada895bdfcaf9c7e33534002cd21af2f84baf8',
        dylib_patches=[(0x9ae9, '\xe9\x56\x01\x00\x00')],
        dylib_sha256='5041490ac354a8b98fc7a80fcd227e2e9ff725a4a263230d120d4a85aa5eed0d'),
    VersionConfig(
        version='10.11',
        bottle='libusb-1.0.21.el_capitan.bottle',
        bottle_sha256='e4902b528d0ea0df0d433e349709d3708a9e08191fd2f3c6d5f5ab2989766b9f',
        dylib_patches=[(0x9adb, '\xe9\x56\x01\x00\x00')],
        dylib_sha256='c8149efd998a364eaa27f94d53ad2e873ebb431c4cfe181c9b15f0b40bc972cf'),
    VersionConfig(
        version='10.10',
        bottle='libusb-1.0.21.yosemite.bottle',
        bottle_sha256='8831059f7585ed973d983dd82995e1732c240a78f4f7a82e5d5c7dfe27d49941',
        dylib_patches=[],
        dylib_sha256='8e89265251d119f3422a760cf3472ecc46b7c3d22598600905dd5595a1ec146a'),
    VersionConfig(
        version='10.9',
        bottle='libusb-1.0.20.mavericks.bottle',
        bottle_sha256='a156b5968853363f5465d7a281cdc536d03d77f26fd98ed7196363b0af41bbb0',
        dylib_patches=[],
        dylib_sha256='8a92a030d4552cb4cd1d8df171389ca174ab9aa6f0a0b7b19a80bfb3042ee11a'),
    VersionConfig(
        version='10.8',
        bottle='libusb-1.0.19.mountain_lion.bottle.1',
        bottle_sha256='d5c4bd99b359a8319d49e06b6b13fc529f91a5bd61ce5a8ff14c291b44b676da',
        dylib_patches=[],
        dylib_sha256='0490800ca9ff82d37c310a09f9bd29aaa87143cf86b35d94b170617ec9d127bb'),
]

dir = os.path.dirname(__file__)
BOTTLE_PATH_FORMAT = os.path.join(dir, 'bottles', '%s.tar.gz')
DYLIB_PATH_FORMAT = os.path.join(dir, '%s.dylib')
DYLIB_NAME = 'libusb-1.0.0.dylib'

def apply_patches(binary, patches):
    for (offset, data) in patches:
        binary = binary[:offset] + data + binary[offset + len(data):]
    return binary

def libusb1_path_internal():
    version = platform.mac_ver()[0]
    if version == '':
        # We're not running on a Mac.
        return None
    if version.startswith('10.13'):
        # HACK: Use macOS Sierra libusb bottle on macOS High Sierra.
        version = '10.12'

    for config in configs:
        if version.startswith(config.version):
            path = DYLIB_PATH_FORMAT % config.bottle
            try:
                f = open(path, 'rb')
                dylib = f.read()
                f.close()
                if hashlib.sha256(dylib).hexdigest() == config.dylib_sha256:
                    return path
                print 'WARNING: SHA256 hash of existing dylib does not match.'
            except IOError:
                pass

            f = open(BOTTLE_PATH_FORMAT % config.bottle, 'rb')
            bottle = f.read()
            f.close()
            if hashlib.sha256(bottle).hexdigest() != config.bottle_sha256:
                print 'ERROR: SHA256 hash of bottle does not match.'
                sys.exit(1)

            tar = tarfile.open(fileobj=cStringIO.StringIO(bottle))
            for member in tar.getmembers():
                if member.name.endswith(DYLIB_NAME):
                    patched_dylib = apply_patches(tar.extractfile(member.name).read(), config.dylib_patches)
                    if hashlib.sha256(patched_dylib).hexdigest() != config.dylib_sha256:
                        print 'ERROR: SHA256 hash of new dylib does not match.'
                        sys.exit(1)
                    f = open(path, 'wb')
                    f.write(patched_dylib)
                    f.close()
                    return path

    # No match found.
    return None

cached_path = libusb1_path_internal()

def libusb1_path():
    return cached_path
