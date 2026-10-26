"""
Fixtures for the doctests in the documentation pages.
"""

from collections.abc import Iterator

import pytest

from x690.types import X690Type


@pytest.fixture(autouse=True)
def isolated_type_registry() -> Iterator[None]:
    """
    Remove the types a page registers once its doctests have run.
    """
    registry = X690Type._X690Type__registry  # type: ignore[attr-defined]
    saved = dict(registry)
    yield
    registry.clear()
    registry.update(saved)
