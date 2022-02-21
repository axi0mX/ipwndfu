from ipwndfu.utilities import SerialNumber, get_serial


def test_always_passes():
    assert True


def test_serial_number():
    sample = "CPID:8010 CPRV:11 CPFM:03 SCEP:01 BDID:0C ECID:000E459A38F34D26 IBFL:3C SRTG:[iBoot-2696.0.0.1.33]"

    serial = get_serial(sample)
    assert isinstance(serial, SerialNumber)
