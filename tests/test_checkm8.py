from typing import TYPE_CHECKING

import pytest

from ipwndfu import checkm8
from ipwndfu.device_platform import all_platforms

if TYPE_CHECKING:
    from ipwndfu.device_platform import DevicePlatform


def name_of_platform(platform: "DevicePlatform") -> str:
    return platform.name()


@pytest.mark.parametrize("platform", all_platforms, ids=name_of_platform)
def test_generate_overwrites(platform: "DevicePlatform") -> None:
    checkm8_platform = checkm8.Checkm8.from_platform(platform)

    if not checkm8_platform.overwrite.pack:
        return

    overwrite = checkm8_platform.overwrite.generate_overwrite(platform)

    assert isinstance(overwrite, bytes)
    assert len(overwrite) > checkm8_platform.overwrite.preamble


@pytest.mark.parametrize("platform", all_platforms, ids=name_of_platform)
def test_generate_device_config(platform: "DevicePlatform") -> None:
    checkm8_platform = checkm8.Checkm8.from_platform(platform)

    config = checkm8_platform.device_config()

    assert config
