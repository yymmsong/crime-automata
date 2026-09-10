from collections.abc import Callable, Iterable
from random import Random
from typing import TYPE_CHECKING, Any

from .compilable import Compilable, CustomCompilable
from .utils import dedup, fine_dedup

if TYPE_CHECKING:
    from .automata import CRIMEAutomaton


class Dictionary(Compilable):
    def __init__(self, machine: "CRIMEAutomaton | None" = None):
        super().__init__(machine=machine)
        self.words: list[bytes] = []

    def flush(self) -> None:
        self.words = []
        super().flush()

    def __contains__(self, word: bytes) -> bool:
        return word in self.words

    def contains_as_substring(self, word: bytes) -> bool:
        for target in self.words:
            if word in target:
                return True
        return False

    def append(self, word: bytes) -> None:
        # word = word() if callable(word) else word
        self.words.append(word)
        if not self.frozen:
            self.output = None

    def extend(self, words: Iterable[bytes]) -> None:
        self.words.extend(words)
        if not self.frozen:
            self.output = None

    def insert(self, index: int, word: bytes) -> None:
        # word = word() if callable(word) else word
        self.words.insert(index, word)
        if not self.frozen:
            self.output = None

    def remove_at(self, index: int) -> None:
        self.words.pop(index)
        if not self.frozen:
            self.output = None


class NullDictionary(Dictionary):
    def __bytes__(self) -> bytes:
        return b""


class SimpleDictionary(Dictionary):
    """A simple dictionary."""

    def __init__(
        self, sep: bytes = b"-", bound: bytes | None = None, reverse: bool = False
    ):
        super().__init__(machine=None)
        self.sep: bytes = sep
        if bound is None:
            bound = sep
        self.bound: bytes = bound
        self.reverse: bool = reverse

    def __bytes__(self) -> bytes:
        if len(self.words) == 0:
            return b""
        words = reversed(self.words) if self.reverse else self.words
        return self.bound + self.sep.join(words) + self.bound


class SimpleDictionaryDedup(SimpleDictionary):
    """A simple dictionary that deduplicates its entries in the output."""

    def __init__(
        self,
        sep: bytes = b"-",
        bound: bytes | None = None,
        fine_grained: bool = False,
        reverse: bool = False,
    ):
        super().__init__(sep=sep, bound=bound, reverse=reverse)
        self.fine_grained: bool = fine_grained

    def __bytes__(self) -> bytes:
        if len(self.words) == 0:
            return b""
        words = reversed(self.words) if self.reverse else self.words
        dedup_words: list[Any] = (
            fine_dedup(words) if self.fine_grained else dedup(words)
        )
        return self.bound + self.sep.join(dedup_words) + self.bound


class CustomDictionary(CustomCompilable, Dictionary):
    pass
