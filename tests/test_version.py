import re

import ttp_staleness


def test_version_is_semver_string() -> None:
    assert isinstance(ttp_staleness.__version__, str)
    assert re.match(r"^\d+\.\d+\.\d+", ttp_staleness.__version__)
