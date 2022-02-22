from ipwndfu.device_platform import DevicePlatform, all_platforms


def test_load_platforms() -> None:
    assert len(all_platforms) > 1


def test_get_t8012_platform() -> None:
    platform = DevicePlatform.platform_for_cpid(0x8012)

    assert platform


def test_order_usb_constants() -> None:
    platform = DevicePlatform.platform_for_cpid(0x8015)

    PROPER_ORDER = [
        0x18001C000,
        0x6578656365786563,
        0x646F6E65646F6E65,
        0x6D656D636D656D63,
        0x6D656D736D656D73,
        0x10000B9A8,
    ]

    assert platform.usb.constants == PROPER_ORDER
