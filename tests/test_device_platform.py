from ipwndfu.device_platform import DevicePlatform, all_platforms


def test_load_platforms() -> None:
    assert len(all_platforms) > 1


def test_get_t8012_platform() -> None:
    platform = DevicePlatform.platform_for_cpid(0x8012)

    assert platform
