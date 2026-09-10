from random import Random
from typing import TYPE_CHECKING

from .compilable import Compilable, CustomCompilable
from .randbytes import RandBytes
from .utils import charset_with_fallback

if TYPE_CHECKING:
    from .automata import CRIMEAutomaton


class Filler(Compilable):
    def __init__(self, machine: "CRIMEAutomaton | None" = None):
        super().__init__(machine=machine)


class NullFiller(Filler):
    def __bytes__(self) -> bytes:
        return b""


class SimpleFiller(Filler):
    def __init__(self, content: bytes = b""):
        super().__init__(machine=None)
        self.content: bytes = content

    def __bytes__(self) -> bytes:
        return self.content


class RandomFiller(Filler):
    def __init__(self, length: int, charset: bytes | None = None):
        super().__init__(machine=None)
        assert length >= 0
        self.length: int = length
        self.charset: bytes | None = charset

    def __call__(self, rng: Random | None) -> bytes | None:
        charset = charset_with_fallback(self.charset, self.machine)
        return RandBytes(charset, rng).randbytes(self.length)


class CustomFiller(CustomCompilable, Filler):
    pass
