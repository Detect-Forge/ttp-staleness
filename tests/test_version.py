import re

import detect_forge


def test_version_is_semver_string() -> None:
    assert isinstance(detect_forge.__version__, str)
    assert re.match(r"^\d+\.\d+\.\d+", detect_forge.__version__)
