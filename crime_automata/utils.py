from collections.abc import Container, Iterable
import string
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .automata import CRIMEAutomaton

HEX_BYTES = b"0123456789abcdef"
ALPHABETIC_BYTES = (string.ascii_letters).encode("latin-1")
ALPHANUMERIC_BYTES = (string.ascii_letters + string.digits).encode("latin-1")
ASCII_PRINTABLE_BYTES = (string.printable).encode("latin-1")
ASCII_BYTES = bytes(range(128))
ALL_BYTES = bytes(range(256))

EPS = 1e-7


def dedup(ls: Iterable) -> list:
    """Deduplicate an iterable while retaining the relative orders."""
    lsd = []  # :)
    seen = set()
    for x in ls:
        if x in seen:
            continue
        lsd.append(x)
        seen.add(x)
    return lsd


def fine_dedup(ls: Iterable[Container]) -> list[Container]:
    """Deduplicate an iterable of containers while keeping the relative orders.

    We remove any object contained in another object with two scans, first
    looking left and then looking right. In the end, no object should contain
    a different object in the deduplicated list. NB: Do not expect to get nice
    results if the containing relation is not a partial order."""

    lsd_left: list[Container] = []

    for x in ls:
        for target in lsd_left:
            if x in target:
                break
        else:
            lsd_left.append(x)

    lsd: list[Container] = []

    for x in reversed(lsd_left):
        for target in lsd:
            if x in target:
                break
        else:
            lsd.append(x)

    return list(reversed(lsd))


def charset_with_fallback(
    charset: bytes | None, machine: "CRIMEAutomaton | None"
) -> bytes:
    if charset is None:
        assert machine is not None
        return machine.charset
    return charset
