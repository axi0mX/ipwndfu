from ipwndfu.utilities import SerialNumber, get_serial, magic_to_cigam


def test_always_passes():
    assert True


def test_serial_number():
    sample = "CPID:8010 CPRV:11 CPFM:03 SCEP:01 BDID:0C ECID:000E459A38F34D26 IBFL:3C SRTG:[iBoot-2696.0.0.1.33]"

    serial = get_serial(sample)
    assert isinstance(serial, SerialNumber)

def test_magic_to_cigam():
    sample = b"execexec"
    cigam = magic_to_cigam(sample)
    assert cigam == b"execexec"[::-1]
