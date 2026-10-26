"""
Fixtures for the doctests in the documentation pages.
"""

from collections.abc import Iterator

import pytest

from x690 import types


@pytest.fixture(autouse=True)
def isolated_type_registry() -> Iterator[None]:
    """
    Remove the types a page registers once its doctests have run.
    """
    registry = types._REGISTRY
    saved = dict(registry)
    yield
    registry.clear()
    registry.update(saved)
