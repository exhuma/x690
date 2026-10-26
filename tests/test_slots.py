"""
Memory layout of the built-in types.
"""

import pytest

from x690.types import X690Type
from x690.util import TypeClass, TypeNature


@pytest.mark.parametrize("cls", X690Type.all(), ids=lambda cls: cls.__name__)
def test_no_instance_dict(cls: type[X690Type[object]]) -> None:
    """
    Ensure built-in types store their state in slots, without a per-instance
    dictionary, so that large decoded documents stay small in memory.
    """
    assert not hasattr(cls(), "__dict__")


def test_custom_type_without_slots() -> None:
    """
    Ensure a custom type that declares no slots still works.
    """

    class Custom(X690Type[bytes]):
        TYPECLASS = TypeClass.PRIVATE
        NATURE = [TypeNature.PRIMITIVE]
        TAG = 1

    instance = Custom(b"abc")
    instance.note = "custom attribute"  # type: ignore[attr-defined]
    assert bytes(instance) == b"\xc1\x03abc"
