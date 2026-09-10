from collections.abc import Callable, Iterable
from itertools import chain
from math import gcd
from random import Random
from typing import Sequence, TYPE_CHECKING

from .collisions import DeflateInstanceSet
from ..gadgets import (
    Gadget,
    CustomOrRandomGadget,
    ParallelGadget,
    RandomGadget,
)
from .params import DeflateStrategy
from ..randbytes import RandBytes
from ..utils import charset_with_fallback, dedup

if TYPE_CHECKING:
    from ..automata import CRIMEAutomaton
    from .automata import DeflateAutomaton

__all__ = [
    "DeflateGadget",
    "GenericGadget",
    "SimpleAlign",
    "MatchAlign",
    "RandomMisalign",
    "DefaultAlign",
    "MatchNOP",
    "RandomNOP",
    "DefaultNOP",
    "TargetMatch",
    "ByteMatch",
    "Unmatch",
    "TelescopedMatch",
    "RandomTelescopedMatch",
    "BaseAmplify",
    "DistanceChainAmplify",
    "MatchChainFastAmplify",
    "MatchChainLazyAmplify",
    "MatchChainAutomatedAmplify",
    "CollisionAmplify",
    "AltCollisionAmplify",
    "QuickCollisionAmplify",
    "ShortNOT",
    "LongFastNOT",
    "LongGeneralNOT",
    "LongLazyNOT",
    "LongAutomatedNOT",
    "DefaultNOT",
    "ANDTargetMatch",
    "BaseORTargetMatch",
    "GeneralORTargetMatch",
    "LazyORTargetMatch",
    "AutomatedORTargetMatch",
]


WORD_TYPE = bytes | Callable[[Gadget], bytes]


def squash_callable_words(words: Iterable[WORD_TYPE], gadget: Gadget) -> list[bytes]:
    return [word(gadget) if callable(word) else word for word in words]


# ----- generic gadget ----


class DeflateGadget(Gadget):
    """A DEFLATE gadget."""

    def __init__(self, machine: "DeflateAutomaton | None" = None):
        """Basically in place to please the static type checker."""
        super().__init__(machine=machine)
        self.machine: "DeflateAutomaton | None" = machine  # satisfy type checker

    @staticmethod
    def _add_to_dict(
        wordlist: Iterable[WORD_TYPE] | None = None,
        use_dict_1: bool = False,
        should_dedup: bool = False,
    ) -> Callable[["DeflateGadget"], None] | None:
        """A helper method to generate an action that adds some byte strings
        to a dictionary of the DEFLATE automaton specified by `use_dict_1`.

        The reason why we do not let the caller pass the dictionary as an
        argument explicitly is that we expect the generated action to work even
        if the dictionary or the automaton is changed later.

        Args:
            wordlist: The byte strings (or functions that return a byte string)
                to be added to a dictionary. If `wordlist` is `None`, then this
                method returns `None`; otherwise, this method returns an
                action, which, on invocation, adds byte strings in `wordlist`
                to a dictionary of the automaton. Default `None`.
            use_dict_1: If this value is `True`, then we add the byte strings
                to `dict_1`; else, we add them to `dict_2. Default `False`.
            should_dedup: Whether to deduplicate (a squashed copy of) the
                wordlist prior to adding it to a dictionary. Note that only
                duplicates in the wordlist are removed. Default `False`.

        Returns:
            An action, which is a function that takes a `DeflateGadget` object
            intended to be `self`) and has no return values, or `None`.
        """
        if wordlist is None:
            return None

        wordlist_cp: list[WORD_TYPE] = [word for word in wordlist]

        def action(gadget: "DeflateGadget") -> None:
            if gadget.machine is None:
                return None

            words: list[bytes] = squash_callable_words(wordlist_cp, gadget)
            if should_dedup:
                words = dedup(words)

            if use_dict_1:
                gadget.machine.dict_1.extend(words)
            else:
                gadget.machine.dict_2.extend(words)

        return action


class GenericGadget(DeflateGadget):
    def __init__(
        self,
        content: bytes,
        words_1: Iterable[WORD_TYPE] | None = None,
        words_2: Iterable[WORD_TYPE] | None = None,
    ):
        super().__init__()
        self.content: bytes = content
        if words_1 is None:
            words_1 = []
        self.words_1: Iterable[WORD_TYPE] = words_1
        if words_2 is None:
            words_2 = []
        self.words_2: Iterable[WORD_TYPE] = words_2

    def __call__(self, rng: Random | None = None) -> bytes:
        self.actions = [
            self._add_to_dict(self.words_1, use_dict_1=True),
            self._add_to_dict(self.words_2, use_dict_1=False),
        ]
        return self.content

    def sanity_check(self) -> bool:
        if len(self.content) < 2:  # states are not well-defined
            return False
        if self.machine is None:
            return True
        for word in chain(self.words_1, self.words_2):
            if callable(word):
                continue
            if len(word) < self.machine.params.min_match:
                return False
        return True


# ----- align gadgets -----


class SimpleAlign(DeflateGadget):
    """An align gadget constructed by repeating a very short byte string `b`
    by `count` times, such as `@@@@@@` for `b=b"@"` and `count=6`."""

    def __init__(self, b: bytes, count: int):
        super().__init__()
        assert count >= 0
        self.b: bytes = b
        self.count: int = count

    def __bytes__(self) -> bytes:
        return self.b * self.count

    def sanity_check(self) -> bool:
        return self.machine is None or (
            len(self.b) * self.count >= self.machine.params.min_match
        )


class MatchAlign(CustomOrRandomGadget, DeflateGadget):
    """An align gadget, constructed using a match in the sliding window
    (possibly added to a dictionary by setting `is_known=False`).

    A random byte string with the specified length and charset will be used
    and added to a dictionary if no match is explicitly provided."""

    def __init__(
        self,
        match: bytes | None = None,
        length: int | None = None,
        charset: bytes | None = None,
        is_known: bool = False,
    ):
        assert match is not None or not is_known
        CustomOrRandomGadget.__init__(
            self, content=match, length=length, charset=charset
        )
        DeflateGadget.__init__(self)
        self.is_known: bool = is_known

    def get_length(self) -> int:
        if self.length is None:
            assert self.machine is not None
            length = self.machine.params.min_match + 3
            if self.machine.params.max_insert is not None:
                length = max(length, self.machine.params.max_insert + 1)
            assert length >= 0
            return length
        return self.length

    def __call__(self, rng: Random | None = None) -> bytes | None:
        output = CustomOrRandomGadget.__call__(self, rng)
        if output is not None and not self.is_known:
            self.actions = [self._add_to_dict([output], use_dict_1=False)]
        return output

    def sanity_check(self) -> bool:
        if self.machine is None:
            return True
        length = self.get_length()
        if (
            self.machine.params.max_insert is not None
            and length > self.machine.params.max_insert
        ):
            return False
        return length >= self.machine.params.min_match


class RandomMisalign(RandomGadget, DeflateGadget):
    """A misalign gadget, constructed as a random byte string."""

    def sanity_check(self) -> bool:
        return self.machine is None or self.length >= self.machine.params.min_match


DefaultAlign = SimpleAlign


# ----- NOP gadgets -----


class MatchNOP(DeflateGadget):
    """A NOP gadget, constructed using a match in the sliding window
    (possibly added to a dictionary by setting `is_known=False`)."""

    def __init__(self, match: bytes, is_known: bool):
        super().__init__()
        self.match: bytes = match
        self.is_known: bool = is_known

    def __call__(self, rng: Random | None = None) -> bytes:
        match = self.match
        wordlist: list[WORD_TYPE] = [self.compound_word(1, match[:-1])]
        if not self.is_known:
            wordlist.append(self.match)
        self.actions = [self._add_to_dict(wordlist, use_dict_1=False)]
        return self.match

    def sanity_check(self) -> bool:
        return self.machine is None or len(self.match) >= self.machine.params.min_match


class RandomNOP(RandomGadget, DeflateGadget):
    """A NOP gadget, constructed as a random byte string."""

    def __call__(self, rng: Random | None) -> bytes:
        content = RandomGadget.__call__(self, rng)
        wordlist: list[WORD_TYPE] = [
            self.compound_word(1, content[:-1]),
            content,
        ]
        self.actions = [self._add_to_dict(wordlist, use_dict_1=False)]
        return content

    def sanity_check(self) -> bool:
        return self.machine is None or self.length >= self.machine.params.min_match


DefaultNOP = RandomNOP


# ----- match gadgets -----


class TargetMatch(DeflateGadget):
    """A generalized byte-match gadget."""

    def __init__(self, target: bytes, add_prefix: bool = False):
        super().__init__()
        self.target = target
        self.add_prefix = add_prefix

    def __call__(self, rng: Random | None) -> bytes | None:
        if self.add_prefix:
            self.actions = [self._add_to_dict([self.target[:-1]], use_dict_1=False)]
        return self.target

    def sanity_check(self) -> bool:
        return self.machine is None or len(self.target) >= self.machine.params.min_match


class ByteMatch(TargetMatch):
    """A byte-match gadget."""

    def __init__(self, prefix: bytes, guess: bytes, add_prefix: bool = False):
        # assert len(guess) == 1
        super().__init__(target=prefix + guess, add_prefix=add_prefix)


class Unmatch(DeflateGadget):
    """An unmatch gadget."""

    def __init__(self, target: bytes, sep: bytes):
        """Initialize an unmatch gadget.

        Args:
            target: The target to match, e.g. `b"secret=1"`.
            sep: a *one-byte* separator, e.g. `b"/"`.
        """
        super().__init__()
        self.target = target
        self.sep = sep  # should be of length 1

    def __call__(self, rng: Random | None = None) -> bytes:
        self.actions = [
            self._add_to_dict([self.target[1:] + self.sep], use_dict_1=False)
        ]
        return self.target + self.sep

    def sanity_check(self) -> bool:
        if len(self.sep) != 1:
            return False
        if self.machine is None:
            return True
        min_match = self.machine.params.min_match
        max_lazy = self.machine.params.max_lazy
        return (
            max_lazy is not None
            and len(self.target) >= min_match
            and len(self.target) <= max_lazy
            # and len(self.target[1:] + self.sep) >= min_match
        )


class TelescopedMatch(TargetMatch):
    """A telescoped-match gadget."""

    def __init__(
        self,
        target: bytes,
        k: int | None,
        seps: Sequence[bytes] | None = None,
        little_endian: bool = True,
        add_prefix: bool = False,
    ):
        """Initialize a telescoped-match gadget.

        Args:
            target: The target to match, e.g. `b"secret=1"`.
            k: The number of parts in the gadget, e.g. `5`, or `None`, in which
                case we first try to set `k=len(seps)+1` and, if `sep` is also
                `None`, we use the largest possible `k`, which may not be what
                you really want, so take care!
            seps: The separators between two parts of the gadget, e.g.
                `[b"A", b"B", b"C", b"D"]`. Default `None`, which means no
                separators are used.
            little_endian: Whether the parts are ordered from the shortest to
                the longest, or vice versa. Default `True`. Note that it should
                be undesirable in general to set `little_endian=False`.
            add_prefix: Whether to add `target[:-1]` to `dict_2`. Default
                `False`.
        """
        if k is not None:
            assert k > 0 and len(target) > k
            assert seps is None or len(seps) >= k - 1
        super().__init__(target=target, add_prefix=add_prefix)

        self.k: int | None = k
        self.seps: Sequence[bytes] | None = seps
        self.little_endian: bool = little_endian

    def _get_k(self) -> int:
        if self.k is not None:
            return self.k
        if self.seps is not None:
            return len(self.seps) + 1
        assert self.machine is not None
        return max(len(self.target) - self.machine.params.min_match + 1, 1)

    def _get_seps(self, k: int, rng: Random | None) -> Sequence[bytes] | None:
        if self.seps is None:
            return [b""] * (k - 1)
        return self.seps

    def __call__(self, rng: Random | None) -> bytes | None:
        super().__call__(rng)
        k: int = self._get_k()
        seps = self._get_seps(k, rng)
        if seps is None:
            return None

        result = self.target[k - 1 :] if self.little_endian else self.target
        for i, sep in enumerate(seps, start=1):
            if i >= k:
                break
            index = k - i - 1 if self.little_endian else i
            result += sep + self.target[index:]

        return result

    def sanity_check(self) -> bool:
        # more checks can be done.
        if self.machine is None:
            return True
        k = self._get_k()
        if len(self.target) - k + 1 < self.machine.params.min_match:
            return False
        return True


class RandomTelescopedMatch(TelescopedMatch):
    def __init__(
        self,
        target: bytes,
        k: int | None,
        sep_len: int,
        distinct_seps: bool,
        charset: bytes | None = None,
        little_endian: bool = True,
        add_prefix: bool = False,
    ):
        assert sep_len > 0
        self.sep_len = sep_len
        self.distinct_seps = distinct_seps
        self.charset = charset
        super().__init__(
            target=target,
            k=k,
            seps=None,
            little_endian=little_endian,
            add_prefix=add_prefix,
        )

    def _get_seps(self, k: int, rng: Random | None) -> Sequence[bytes] | None:
        charset = charset_with_fallback(self.charset, self.machine)
        rbg = RandBytes(charset, rng)
        if self.distinct_seps:
            if len(charset) ** self.sep_len < k - 1:
                return None
            seps: list[bytes] = []
            seen = set()
            for _ in range(k - 1):
                while True:
                    cand_sep = rbg.randbytes(self.sep_len)
                    if cand_sep not in seen:
                        seps.append(cand_sep)
                        seen.add(cand_sep)
                    break
            return seps
        else:
            return [rbg.randbytes(self.sep_len) for _ in range(k - 1)]


# ----- match-based amplify gadgets -----


class BaseAmplify(DeflateGadget):
    """Base class for amplify gadgets."""

    def __init__(
        self,
        length: int,
        k: int | None,
        charset: bytes | None = None,
        should_dedup: bool = True,
        aligned: bool = True,
        reverse: bool = False,
        double: bool = False,
        overlap: int = 0,
    ):
        """Initialize an amplify gadget.

        Note that the parameters `reverse`, `double` and `overlap` may not make
        sense or not yet supported for some types of amplify gadgets.

        Args:
        length: The length of the gadget.
        k: The length of a "segment" of the gadget; if `None` is provided, then
            the smallest possible value of `k` will be used on compilation.
        charset: The allowed bytes for this gadget, or `None` if it's the same
            as the allowed bytes for the automaton; default `None`.
        should_dedup: Perform deduplication on the entries to be added to the
            dictionaries or not; the default value is `True`.
        aligned: Whether to truncate `length` on initalization such that the
            last segment in the gadget does not use more than necessary bytes,
            which usually means rounding down `length` to the nearest multiple
            of `k`. Default `True`.
        reverse: If set to `True`, then the amplify gadget intends to decrease
            the compressed length if it is in the `True` state; otherwise, if
            set to `False`, as done by default, the gadget intends to increase
            the compressed length for the state `True` instead. Note that,
            irrespective of the value of `reverse`, the amplify gadget does not
            intend to change the state of the automaton.
        double: Whether to repeat every other segement; default `False`. Note
            that setting `double=True` generally makes the query shorter (by
            shrinking the dictionaries) but more error-prone.
        overlap: If set to a positive integer, then the gadget is designed such
            that the words in `dict_2` can be combined into a very long byte
            string, where each word has an overlap of at least `overlap` bytes
            with an adjacent word in the very long byte string. A higher value
            of `overlap` makes the query shorter but more error-prone.
        """
        assert k is None or 0 < k <= length
        super().__init__()
        self.length: int = length
        self.k: int | None = k
        self.charset: bytes | None = charset
        self.should_dedup: bool = should_dedup
        self.aligned: bool = aligned
        self.reverse: bool = reverse
        self.double: bool = double
        self.overlap: int = overlap

    def _get_words(
        self, content: bytes, k: int
    ) -> tuple[list[WORD_TYPE], list[WORD_TYPE]]:
        raise NotImplementedError()

    def _get_words_reverse(
        self, content: bytes, k: int
    ) -> tuple[list[WORD_TYPE], list[WORD_TYPE]]:
        raise NotImplementedError()

    def _get_content(self, rng: Random | None, length: int, k: int) -> bytes:
        charset = charset_with_fallback(self.charset, self.machine)
        return RandBytes(charset, rng).randbytes(length)

    def _get_content_double(self, rng: Random | None, length: int, k: int) -> bytes:
        raise NotImplementedError()

    def _get_content_and_words_overlap(
        self, rng: Random | None, length: int, k: int
    ) -> tuple[bytes, WORD_TYPE | None, WORD_TYPE | None]:
        raise NotImplementedError()

    def _get_k(self) -> int:
        """Get the value of `k`, or try to use the smallest possible `k` based
        on the DEFLATE parameters if `k=None`."""
        assert self.k is not None
        return self.k

    def _get_length(self, k: int) -> int:
        """Get the value of `length`, taking alignment into consideration."""
        if self.aligned:
            return self.length - self.length % k
        return self.length

    def __call__(self, rng: Random | None) -> bytes:
        k = self._get_k()
        length = self._get_length(k)
        # first compute the output
        if self.overlap > 0:
            content, big_word_1, big_word_2 = self._get_content_and_words_overlap(
                rng, length, k
            )
        elif self.double:
            content = self._get_content_double(rng, length, k)
        else:
            content = self._get_content(rng, length, k)

        # then compute the words
        words_1, words_2 = (
            self._get_words_reverse(content, k)
            if self.reverse
            else self._get_words(content, k)
        )

        if self.overlap > 0:
            if big_word_1 is not None:
                words_1 = [big_word_1]
            if big_word_2 is not None:
                words_2 = [big_word_2]

        self.actions = [
            self._add_to_dict(words_1, True, self.should_dedup),
            self._add_to_dict(words_2, False, self.should_dedup),
        ]
        return content

    def sanity_check(self) -> bool:
        if self.double:
            if self.overlap > 0:
                return False
            if not self.should_dedup:
                return False
        if self.k is not None and self.k < self.overlap + 1:
            return False
        return True


class DistanceChainAmplify(BaseAmplify):
    def __init__(
        self,
        length: int,
        k: int | None,
        charset: bytes | None = None,
        should_dedup: bool = True,
        aligned: bool = True,
        reverse: bool = False,
        double: bool = False,
        overlap: int = 0,
    ):
        super().__init__(
            length=length,
            k=k,
            charset=charset,
            should_dedup=should_dedup,
            aligned=aligned,
            reverse=reverse,
            double=double,
            overlap=overlap,
        )

    def _get_words(
        self, content: bytes, k: int
    ) -> tuple[list[WORD_TYPE], list[WORD_TYPE]]:
        m = len(content) // k

        words_1: list[WORD_TYPE] = [self.compound_word(1, content[: k - 1])]
        words_2: list[WORD_TYPE] = [content[:k]]
        for i in range(k, (m - 1) * k, k):
            words_1.append(content[i - 1 : i - 1 + k])
            words_2.append(content[i : i + k])
        words_1.append(content[(m - 1) * k - 1 : -1])
        words_2.append(content[(m - 1) * k :])
        return words_1, words_2

    def _get_words_reverse(
        self, content: bytes, k: int
    ) -> tuple[list[WORD_TYPE], list[WORD_TYPE]]:
        words_1, words_2 = self._get_words(content, k)
        return words_2, words_1

    def _get_content_double(self, rng: Random | None, length: int, k: int) -> bytes:
        # length = 19, k = 3, m = 6
        # normal: Both the first and the last bytes should alternate
        # <secret=><1ab><cde><fde><fgh><igh><ijkl>
        # <secret=1><abc><def><def><ghi><ghi><jklm>
        # reverse: The first byte should alternate, the last can be the same
        # <secret=1><abc><dec><def><ghf><ghi><jklm>
        # <secret=><1ab><cde><cde><fgh><fgh><ijkl>
        # Because we're extremely lazy we'll just alternate both bytes
        charset = charset_with_fallback(self.charset, self.machine)
        rbg = RandBytes(charset, rng)

        m = length // k
        content = rbg.randbytes(k - int(self.reverse))
        head, tail = None, content[-1]

        for _ in range((m - 1) // 2):
            head = rbg.randbyte_with_taboo(head)
            tail = rbg.randbyte_with_taboo(tail)
            content += (
                bytes([head] + [rbg.randbyte() for _ in range(k - 2)] + [tail]) * 2
            )

        content += rbg.randbytes(length - len(content))
        return content

    def _get_content_and_words_overlap(
        self, rng: Random | None, length: int, k: int
    ) -> tuple[bytes, WORD_TYPE | None, WORD_TYPE | None]:
        # length = 19, k = 3, m = 6, overlap = 2
        # big_word = abcdefghi
        # <secret=><1gh><ifg><hef><gde><fcd><eabc>
        # <secret=1><ghi><fgh><efg><def><cde><abcd>
        # The i-th byte and the (i+k+1)-th byte should preferably differ
        charset = charset_with_fallback(self.charset, self.machine)
        rbg = RandBytes(charset, rng)

        m = length // k
        assert k > self.overlap

        last_seg_len = k + (length % k)
        word_len = last_seg_len + (m - 1) * (k - self.overlap)
        if self.overlap + 1 == k:
            big_word_ls = [rbg.randbyte() for _ in range(last_seg_len)]
            for i in range(1, m):
                if i < k - 1:
                    big_word_ls.append(rbg.randbyte())
                else:
                    big_word_ls.append(rbg.randbyte_with_taboo(big_word_ls[-k - 1]))
            big_word = bytes(big_word_ls)
        else:
            big_word = rbg.randbytes(word_len)

        content = b""
        for i in range(word_len, last_seg_len, self.overlap - k):
            content += big_word[i - k : i]
        content += big_word[:last_seg_len]

        if self.reverse:
            return content, big_word, None
        else:
            return content, None, big_word

    def _get_k(self) -> int:
        if self.k is None:
            assert self.machine is not None
            k = max(self.machine.params.min_match, self.overlap + 1)
            # assert 0 < k <= self.length
            return k
        return self.k

    def sanity_check(self) -> bool:
        if not super().sanity_check():
            return False
        if self.machine is None:
            return True
        k = self._get_k()
        if k < self.machine.params.min_match:
            return False
        max_insert = self.machine.params.max_insert
        if (
            self.overlap > 0
            and max_insert is not None
            and k > max_insert + 1
            and not self.reverse
        ):
            # The gadget may work or may not work at this point, but before I
            # have time to figure it out just choose parameters more wisely svp
            return False
        return True


class MatchChainFastAmplify(BaseAmplify):
    def __init__(
        self,
        length: int,
        k: int | None,
        k_prime: int | None = None,
        charset: bytes | None = None,
        should_dedup: bool = True,
        aligned: bool = True,
        reverse: bool = False,
        double: bool = False,
        overlap: int = 0,
    ):
        assert not (k is None and k_prime is not None)
        assert k is None or k_prime is None or 0 <= k_prime < k
        self.k_prime = k_prime

        super().__init__(
            length=length,
            k=k,
            charset=charset,
            should_dedup=should_dedup,
            aligned=aligned,
            reverse=reverse,
            double=double,
            overlap=overlap,
        )

    def _get_words(
        self, content: bytes, k: int
    ) -> tuple[list[WORD_TYPE], list[WORD_TYPE]]:
        k_prime = self._get_k_prime(k)
        m = len(content) // k
        words_1: list[WORD_TYPE] = [self.compound_word(1, content[: k_prime - 1])]
        words_2: list[WORD_TYPE] = [content[:k]]
        for i in range(k, (m - 1) * k, k):
            words_1.append(content[i - 1 : i + k_prime - 1])
            words_2.append(content[i : i + k])
        # Note that the right index for the last word in word_1 is unoptimized,
        # because we don't know what follows the current gadget.
        words_1.append(content[(m - 1) * k - 1 : -1])
        words_2.append(content[(m - 1) * k :])
        return words_1, words_2

    def _get_words_reverse(
        self, content: bytes, k: int
    ) -> tuple[list[WORD_TYPE], list[WORD_TYPE]]:
        # NB: we can still squeeze a few more bytes from this construction
        k_prime = self._get_k_prime(k)
        m = len(content) // k

        words_1: list[WORD_TYPE] = [content[: (k - 2) + k_prime]]
        words_2: list[WORD_TYPE] = [self.compound_word(1, content[: k - 1])]

        for i in range(2 * k - 1, m * k - 1, k):
            words_1.append(content[i - 1 : i + k_prime - 1])
        for i in range(k - 1, (m - 1) * k - 1, k):
            words_2.append(content[i : i + k])

        # Note that the right index for the last word in word_1 is unoptimized,
        # because we don't know what follows the current gadget.
        words_1.append(content[(m - 1) * k + k_prime - 2 :])
        words_2.append(content[(m - 1) * k - 1 : -1])
        return words_1, words_2

    def _get_content_double(self, rng: Random | None, length: int, k: int) -> bytes:
        # length = 25, k = 4, k_prime = 3, m = 6
        # normal: The first and the last bytes should alternate
        # <secret=><1ab><c><def><g><hef><g><hij><k><lij><k><lmnop>
        # <secret=1><abcd>  <efgh>  <efgh>  <ijkl>  <ijkl>  <mnopq>
        # reverse: ibid.
        # <secret=1>  <abcde><f><gde><f><ghi><j><khi><j><klm><nopq>
        # <secret=><1abc><defg>  <defg>  <hijk>  <hijk>  <lmnop>
        m = length // k
        charset = charset_with_fallback(self.charset, self.machine)
        rbg = RandBytes(charset, rng)

        content = rbg.randbytes(k - 1 if self.reverse else k)
        head, tail = None, content[-1]
        for _ in range((m - 1) // 2):
            head = rbg.randbyte_with_taboo(head)
            tail = rbg.randbyte_with_taboo(tail)
            content += (
                bytes([head] + [rbg.randbyte() for _ in range(k - 2)] + [tail]) * 2
            )

        content += rbg.randbytes(length - len(content))
        return content

    def _get_content_and_words_overlap(
        self, rng: Random | None, length: int, k: int
    ) -> tuple[bytes, WORD_TYPE | None, WORD_TYPE | None]:
        # length = 25, k = 4, k_prime = 3, m = 6, overlap = 3
        # big_word = abcdefghij
        # <secret=><1gh><i><jfg><h><ief><g><hde><f><gcd><e><fabcd>
        # <secret=1><ghij>  <fghi>  <efgh>  <defg>  <cdef>  <abcde>
        # Good to at least adjust the last byte of each segment
        charset = charset_with_fallback(self.charset, self.machine)
        rbg = RandBytes(charset, rng)

        m = length // k
        assert k > self.overlap

        last_seg_len = k + (length % k)
        word_len = last_seg_len + (m - 1) * (k - self.overlap)

        big_word_ls = [rbg.randbyte() for _ in range(last_seg_len)]
        taboo_byte: int | None = None
        for i in range(m - 1):
            big_word_ls.extend([rbg.randbyte() for _ in range(k - self.overlap - 1)])
            big_word_ls.append(rbg.randbyte_with_taboo(taboo_byte))
            taboo_byte = big_word_ls[-k - 1]
        big_word = bytes(big_word_ls)

        content = b""
        for i in range(0, word_len - last_seg_len, k - self.overlap):
            content += big_word[-(i + k) : -i]
        content += big_word[:last_seg_len]

        return content, None, big_word

    def _get_k(self) -> int:
        if self.k is None:
            assert self.machine is not None
            min_match = self.machine.params.min_match
            max_lazy = self.machine.params.max_lazy
            if max_lazy is None:
                max_lazy = 0
            # k = max(min_match, max_lazy) + 1 # the smallest `k` that works
            # here we try to use a large (but not too large) `k` such that the
            # difference between`k` and `k_prime` is large enough
            k = min(max(min_match, max_lazy) + min_match - 2, min_match + 4)
            # assert 0 < k <= self.length
            return k
        return self.k

    def _get_k_prime(self, k: int) -> int:
        """Get the value of `k_prime`, automatically choosing one if needed."""
        if self.k_prime is not None:
            return self.k_prime
        if self.machine is None:
            return k - 1
        min_match = self.machine.params.min_match
        max_lazy = self.machine.params.max_lazy
        if max_lazy is None:
            max_lazy = 0
        if self.reverse:
            return k - min_match + 2
        return min(max(min_match, max_lazy, k - min_match + 2), k - 1)

    def sanity_check(self) -> bool:
        # Note that this gadget can only be used when `min_match > 2`
        if not super().sanity_check():
            return False
        if self.reverse and self.overlap > 0:  # unimplemented, use NOT instead
            return False
        if self.machine is None:
            return True
        min_match = self.machine.params.min_match
        max_lazy = self.machine.params.max_lazy
        k = self._get_k()
        k_prime = self._get_k_prime(k)
        return (
            k_prime >= min_match
            and k > k_prime
            and k < k_prime + min_match - 1
            and (max_lazy is None or k_prime >= max_lazy)
            and (not self.reverse or k_prime == k - min_match + 2)
        )


class MatchChainLazyAmplify(BaseAmplify):
    def __init__(
        self,
        length: int,
        k: int | None,
        k_prime: int | None = None,
        charset: bytes | None = None,
        should_dedup: bool = True,
        aligned: bool = True,
        reverse: bool = False,
        double: bool = False,
    ):
        assert not (k is None and k_prime is not None)
        assert k is None or k_prime is None or 0 <= k_prime < k
        self.k_prime = k_prime

        super().__init__(
            length=length,
            k=k,
            charset=charset,
            should_dedup=should_dedup,
            aligned=aligned,
            reverse=reverse,
            double=double,
            overlap=0,  # not implemented
        )

    def _get_words(
        self, content: bytes, k: int
    ) -> tuple[list[WORD_TYPE], list[WORD_TYPE]]:
        k_prime = self._get_k_prime(k)
        m = len(content) // k
        words_1: list[WORD_TYPE] = [self.compound_word(1, content[: k - 2])]
        words_2: list[WORD_TYPE] = [content[1 : k + 1]]
        for i in range(k, (m - 1) * k, k):
            words_1.append(content[i - 1 : i + k_prime - 1])
            words_2.append(content[i + 1 : i + k + 1])
        # Note that the right index for the last word in word_1 is unoptimized,
        # because we don't know what follows the current gadget.
        words_1.append(content[(m - 1) * k - 1 : -1])
        words_2.append(content[(m - 1) * k + 1 :])
        return words_1, words_2

    def _get_words_reverse(
        self, content: bytes, k: int
    ) -> tuple[list[WORD_TYPE], list[WORD_TYPE]]:
        # Note: I sacrificed one byte (or more?) for simplicity here
        m = len(content) // k
        k_prime = self._get_k_prime(k)
        words_1: list[WORD_TYPE] = [content[1 : k + k_prime - 3]]
        words_2: list[WORD_TYPE] = [self.compound_word(1, content[: k - 2])]
        for i in range(k, (m - 1) * k, k):
            words_1.append(content[i + k - 3 : i + k + k_prime - 3])
            words_2.append(content[i - 1 : i + k - 1])
        words_1.append(content[(m - 1) * k + k_prime - 3 :])
        words_2.append(content[(m - 1) * k - 1 : -1])
        return words_1, words_2

    def _get_content_double(self, rng: Random | None, length: int, k: int) -> bytes:
        # length = 31, k = 5, k_prime = 4, m = 6
        # normal: The first byte should alternate, the last ok to repeat
        # <secret=><1abc><d><efbc><d><efgh><i><jkgh><i><jklm><n><oplmno>
        # <secret=1><a><bcdef><bcdef>  <ghijk>  <ghijk>  <lmnop>  <lmnop>
        # reverse: ibid.
        # <secret=1><a><bcdef><g><hief><g><hijk><l><mnjk><l><mnop><qrstu>
        # <secret=><1abcd><efghi>  <efghi>  <jklmn>  <jklmn>  <opqrst>
        m = length // k
        charset = charset_with_fallback(self.charset, self.machine)
        rbg = RandBytes(charset, rng)

        content = rbg.randbytes(k - 1 if self.reverse else 1)
        head, tail = None, content[-1]
        for _ in range((m - int(self.reverse)) // 2):
            head = rbg.randbyte_with_taboo(head)
            tail = rbg.randbyte_with_taboo(tail)
            content += (
                bytes([head] + [rbg.randbyte() for _ in range(k - 2)] + [tail]) * 2
            )

        if length < len(content):
            assert not self.reverse and length + 1 == len(content)
            content = content[:length]
        else:
            content += rbg.randbytes(length - len(content))
        return content

    def _get_k(self) -> int:
        if self.k is None:
            assert self.machine is not None
            min_match = self.machine.params.min_match
            max_lazy = self.machine.params.max_lazy
            if max_lazy is None:
                max_lazy = 0
            # solve the constraints you have in `sanity_check()`
            ideal_k = min_match * 2 - 3 if min_match >= 4 else 5
            k = min(max(min_match + 1, ideal_k), max_lazy)
            # assert 0 < k <= self.length
            return k
        return self.k

    def _get_k_prime(self, k: int) -> int:
        if self.k_prime is not None:
            return self.k_prime
        if self.machine is None:
            return k - 1
        min_match = self.machine.params.min_match
        max_lazy = self.machine.params.max_lazy
        if max_lazy is None:
            max_lazy = 0
        return min(max(min_match, k - min_match + 3), k - 1)

    def sanity_check(self) -> bool:
        if not super().sanity_check():
            return False
        if self.overlap > 0:  # not implemented
            return False
        if self.machine is None:
            return True
        min_match = self.machine.params.min_match
        max_lazy = self.machine.params.max_lazy
        if max_lazy is None:
            max_lazy = 0
        if max_lazy < 4:
            return False

        k = self._get_k()
        k_prime = self._get_k_prime(k)

        if k_prime < min_match or k_prime >= k:
            return False

        if k - 2 >= min_match:  # first segment
            if k - 1 >= max_lazy:  # normal
                return False
            if self.reverse and k_prime <= 2:  # reverse
                return False
        base_len = k - k_prime + 2
        if base_len >= min_match:  # subsequent segments need lazy matching
            if base_len >= max_lazy or base_len >= k_prime:  # can't improve
                return False
            if k != k_prime + 1:  # only lazy match once
                return False
            # here `k > 4 and max_lazy > 3 and min_match <= 3`
        return True


class MatchChainAutomatedAmplify(ParallelGadget):
    def __init__(
        self,
        length: int,
        k: int | None,
        k_prime: int | None = None,
        charset: bytes | None = None,
        should_dedup: bool = True,
        aligned: bool = True,
        reverse: bool = False,
        double: bool = False,
    ):
        """Initialize a match-based amplify gadget that automatically decides
        whether to use the construction for `deflate_fast` or the construction
        for `deflate_slow`.

        See the documentation of the constructor of the `GenericAmplify` gadget
        for the meaning of each parameter.
        """

        fast_gadget = MatchChainFastAmplify(
            length=length,
            k=k,
            k_prime=k_prime,
            charset=charset,
            should_dedup=should_dedup,
            aligned=aligned,
            reverse=reverse,
            double=double,
        )
        slow_gadget = MatchChainLazyAmplify(
            length=length,
            k=k,
            k_prime=k_prime,
            charset=charset,
            should_dedup=should_dedup,
            aligned=aligned,
            reverse=reverse,
            double=double,
        )
        super().__init__(gadgets=[fast_gadget, slow_gadget])


# ----- collsion-based amplify gadgets -----


class CollisionAmplify(DeflateGadget):
    def __init__(
        self,
        max_len: int,
        instance: DeflateInstanceSet,
        nop_gadget: DeflateGadget | None,
        auto_expand: bool = False,
        optimize_expand: int = 0,
        no_dict: bool = False,
        add_colls_to_dict: bool = False,
        mirroring_gadget: "CollisionAmplify | None" = None,
        min_expand: int | None = None,
        skip_validation: bool = False,
        aligned: bool = True,
        charset: bytes | None = None,
    ):
        """Initialize a collision-based amplify gadget.

        Args:
            max_len: The maximum length of the gadget.
            instance: A DEFLATE instance set.
            nop_gadget: A NOP gadget for separation.
            auto_expand: Whether to automatically expand the instance set on
                compilation using the parameters given instead of fixing it on
                initalization; default `False`. Note that enabling this option
                may make the gadget error-prone and it is generally recommended
                to find an instance set with desired parameters manually or
                semi-automatically.
            optimize_expand: The maximum number of options to try for
                auto expansion, keeping the instance set with the smallest
                average length; a larger `optimize_expand` may improve the
                efficiency of the gadget but may also slow down compilation
                and make the gadget more unstable; default `0`.
            no_dict: If set to `True`, then the gadget does not add any entry
                to the dictionaries; default `False`.
            add_colls_to_dict: If set to `True`, then the gadget also adds each
                individual collision to the dictionaries, which is useful if
                `max_chain` is very small; default `False`.
            mirroring_gadget: Default `None`. By setting `mirroring_gadget` to
                a collision-based amplify gadget preceding the current gadget
                in the automaton, the gadget will at compile time take the
                instance set from the gadget being mirrored during expansion,
                allowing the two to share the same expanded instance set. Note
                that this option is only meaningful if `auto_expand=True`.
                NB: Please pay attention to `no_dict` if you are enabling this
                option. Either set `no_dict=False` for the mirrored gadget or
                this gadget, but not both at the same time.
                NB2: This option cannot be used if `max_insert=None` and
                the segment length (2 * total length of instance set) is
                smaller than `max_match`.
            min_expand: Default `None`. If set to an integer, then the auto
                expansion process will use the specified value (or larger
                values in some cases) as `min_expand` instead.
                It is advised to set `min_expand` to a larger value when
                `max_chain` is large to speed up auto expansion.
            skip_validation: Default `False`. If set to `True`, then the
                auto expansion process does not check whether the expanded
                instance set satisfies all desired properties. This can be
                used to speed up auto expansion if `max_chain` is large.
            aligned: Default `True`. If the gadget does not need to keep the
                state, then it can be disabled to squeeze out more space by
                producing output that is precisely `max_len` bytes.
            charset: The allowed bytes for this gadget, or `None` if it's the
                same as the allowed bytes for the automaton; default `None`.
        """

        super().__init__()
        if mirroring_gadget is not None:
            assert auto_expand
        if min_expand is not None:
            assert min_expand >= 0

        self.max_len: int = max_len
        self.instance: DeflateInstanceSet = instance
        self.orig_instance: DeflateInstanceSet = instance
        self.auto_expand: bool = auto_expand
        self.optimize_expand: int = optimize_expand
        self.no_dict: bool = no_dict
        self.add_colls_to_dict: bool = add_colls_to_dict
        self.nop_gadget: DeflateGadget | None = nop_gadget
        self.mirroring_gadget: CollisionAmplify | None = mirroring_gadget
        self.min_expand: int | None = min_expand
        self.skip_validation: bool = skip_validation
        self.aligned: bool = aligned
        self.charset: bytes | None = charset

        assert self.instance.m >= 2

    def expand_instance(self, rng: Random | None = None) -> DeflateInstanceSet | None:
        """Expand the instance set to a suitable instance set.

        Note that this method is not guaranteed to generate a valid instance,
        mainly because there are too many constraints and I don't have time to
        write all of them down properly. Again, when this method doesn't work,
        try to find an instance set manually instead by tweaking the original
        instance set and testing in a simulated attack environment."""
        if self.mirroring_gadget is not None:
            return self.mirroring_gadget.instance
        if self.machine is None:
            return None
        max_chain = self.machine.params.max_chain
        if max_chain is None:
            return None
        max_lazy = self.machine.params.max_lazy
        max_insert = self.machine.params.max_insert

        # assert (max_lazy is None) != (max_insert is None)
        orig_inst = self.orig_instance
        k, m = orig_inst.k, orig_inst.m

        min_coll_len = min(min(len(s) for s in row) for row in orig_inst.colls)
        is_slow_inst = orig_inst.is_deflate_slow_instance()
        min_expand = int(self.nop_gadget is not None)
        if self.min_expand is not None:
            min_expand = self.min_expand
        charset = charset_with_fallback(self.charset, self.machine)

        # if max_lazy is not None:
        if is_slow_inst:
            is_consistent = orig_inst.is_consistent_deflate_slow_instance()
            if is_consistent:
                min_k = max_chain // (4 * m) + 1
                max_k = (max_chain - 4) // (2 * m)
                val_func = DeflateInstanceSet.is_consistent_deflate_slow_instance
            else:
                assert m == 2, "can't help you with this instance set"
                min_k = max_chain // 4 + 1
                max_k = (max_chain - 4) // 2
                val_func = DeflateInstanceSet.is_deflate_slow_instance
            if min_k <= k <= max_k:  # the original instance works
                return None

            best_expanded_inst_slow: DeflateInstanceSet | None = None
            cnter_slow: int = 0
            for new_k in range(min_k, min(max_k + 1, min_k + 5)):
                if m == 2 and new_k % 2 != 0:
                    continue
                expanded_inst = orig_inst.expand_to_max_match(
                    charset=charset,
                    target_k=new_k,
                    min_expand=min_expand,
                    val_func=None if self.skip_validation else val_func,
                    rng=rng,
                )
                if expanded_inst is None:
                    continue
                if (
                    best_expanded_inst_slow is None
                    or expanded_inst.average_length()
                    < best_expanded_inst_slow.average_length()
                ):
                    best_expanded_inst_slow = expanded_inst
                cnter_slow += 1
                if cnter_slow > self.optimize_expand:
                    break
            return best_expanded_inst_slow
        elif max_lazy is not None:
            if max_lazy <= min_coll_len + 5:  # can still do deflate fast
                min_expand = max(min_expand, min_coll_len - max_lazy)
            else:
                return None

        is_fast_inst = orig_inst.is_consistent_deflate_fast_instance()
        if not is_fast_inst:
            return None
        # Again, to make things less nasty, we assume (without checking!)
        # that the instance set doesn't have double collisions with length
        # below or equal to `max_insert`, otherwise you should DIY
        min_k = max_chain // (2 * m) + 1
        if self.add_colls_to_dict:
            max_k = (max_chain - 1) // m
        else:
            max_k = (max_chain - 2) // m
        # if is_slow_inst and max_insert is not None:
        #     min_expand = max(min_expand, max_insert - min_coll_len)

        best_expanded_inst_fast: DeflateInstanceSet | None = None
        cnter_fast: int = 0
        for new_k in range(min_k, min(max_k + 1, min_k + 5)):
            if m == 2 and new_k % 2 != 0:
                continue
            expanded_inst = orig_inst.expand_to_max_match(
                charset=charset,
                target_k=new_k,
                min_expand=min_expand,
                val_func=(
                    None
                    if self.skip_validation
                    else DeflateInstanceSet.is_consistent_deflate_fast_instance
                ),
                rng=rng,
            )
            if expanded_inst is None:
                continue
            if (
                best_expanded_inst_fast is None
                or expanded_inst.average_length()
                < best_expanded_inst_fast.average_length()
            ):
                best_expanded_inst_fast = expanded_inst
            cnter_fast += 1
            if cnter_fast > self.optimize_expand:
                break
        return best_expanded_inst_fast

    def instantiate_template(
        self, colls: list[list[bytes]], k: int, m: int
    ) -> tuple[bytes | None, bytes | None, list[bytes]]:
        assert m >= 2
        seq1_colls: list[bytes] = []
        seq2_colls: list[bytes] = []
        if m == 2:
            if k % 2 != 0:
                return None, None, []
            seq1_colls = list(
                chain.from_iterable(
                    [
                        [colls[i + 1][0], colls[i][0], colls[i + 1][1], colls[i][1]]
                        for i in range(0, k, 2)
                    ]
                )
            )
            seq2_colls = list(
                chain.from_iterable(
                    [
                        [colls[i][0], colls[i + 1][0], colls[i][1], colls[i + 1][1]]
                        for i in range(0, k, 2)
                    ]
                )
            )
        else:
            seq1_colls = list(
                chain.from_iterable(
                    [
                        ([row[0]] if m % 2 == 1 else [])
                        + [(row[(m & 1) + (j ^ 1)]) for j in range(m - (m % 2))]
                        for row in colls
                    ]
                )
            )
            seq2_colls = list(chain.from_iterable([[s for s in row] for row in colls]))
        return b"".join(seq1_colls), b"".join(seq2_colls), seq2_colls

    def bind(self, machine: "CRIMEAutomaton | None", should_flush: bool = True) -> None:
        super().bind(machine, should_flush=should_flush)
        if self.nop_gadget is not None:
            self.nop_gadget.bind(machine=machine, should_flush=True)
        # if self.auto_expand:
        #    self.instance = self.expand_instance() or self.orig_instance

    def set_prev_gadget(self, gadget: "Gadget | None") -> None:
        super().set_prev_gadget(gadget)
        if self.nop_gadget is not None:
            self.nop_gadget.set_prev_gadget(gadget)

    def _compile_nop_gadget(self, rng: Random | None) -> bytes | None:
        if self.nop_gadget is None:
            return None
        nop_output = self.nop_gadget.compile(
            rng, force_recompile=True, execute_actions=False
        )
        self.actions = self.nop_gadget.actions
        return nop_output

    def _get_nop_on_the_fly(self, rng: Random | None, last_byte: int) -> bytes | None:
        if self.machine is None:
            return None
        charset = charset_with_fallback(self.charset, self.machine)
        min_match = self.machine.params.min_match
        nop_output = RandBytes(charset, rng).randbytes(min_match + 2) + bytes(
            [last_byte]
        )
        wordlist: list[WORD_TYPE] = [
            self.compound_word(1, nop_output[:-1]),
            nop_output,
        ]
        self.actions = [self._add_to_dict(wordlist, use_dict_1=False)]
        return nop_output

    def _get_words(self, segment: bytes, nop_output: bytes) -> list[WORD_TYPE]:
        wordlist: list[WORD_TYPE] = [nop_output[-1:] + segment[:-1]]
        return wordlist

    def _get_output(self, segment: bytes, nop_output: bytes) -> bytes | None:
        is_special_fast = False
        seg_len = len(segment)

        n = (self.max_len - len(nop_output)) // seg_len
        # try to keep the difference in LZ77 pointer positions
        if self.machine is not None and self.aligned:
            max_match = self.machine.params.max_match
            if seg_len < max_match and (2 * max_match) % seg_len == 0:
                omega = (2 * max_match) // seg_len
                if omega % 2 == 0:
                    omega //= 2
                else:
                    is_special_fast = self.machine.params.max_insert is not None
                if is_special_fast:
                    # you're (perhaps unknowingly) dealing with a very tricky
                    # case. Fortunately I can help you with that :) good luck!
                    if self.mirroring_gadget is None:
                        n -= (n - 1 - (omega + 1) // 2) % omega
                    else:
                        n -= n % omega
                else:
                    n -= (n - 1) % omega
                    # now omega | (n - 1), so (max_match / seg_len) | (n - 1)
                    assert (n - 1) * seg_len % max_match == 0

        if n == 0 and self.aligned:
            return None  # or raise an exception

        if self.aligned:
            return nop_output + segment * n
        else:
            return (nop_output + segment * (n + 1))[: self.max_len]

    def __call__(self, rng: Random | None) -> bytes | None:
        if self.auto_expand:
            self.instance = self.expand_instance(rng) or self.orig_instance

        colls = [row[:] for row in self.instance.colls]
        k, m = self.instance.k, self.instance.m
        assert m >= 2

        if self.nop_gadget is None:
            nop_output = self._get_nop_on_the_fly(rng, colls[-1][-1][-1])
        else:
            nop_output = self._compile_nop_gadget(rng)
        if nop_output is None:
            return None

        tail_coll = colls[-1][-1] = colls[-1][-1][:-1] + nop_output[-1:]

        seq1, seq2, seq2_colls = self.instantiate_template(colls, k, m)
        if seq1 is None or seq2 is None:
            return None
        segment = seq1 + seq2

        if not self.no_dict:
            wordlist: list[WORD_TYPE] = self._get_words(segment, nop_output)
            if self.add_colls_to_dict and seq2_colls is not None:
                wordlist.extend(seq2_colls)
            else:
                wordlist.append(tail_coll)
            self.actions.append(self._add_to_dict(wordlist, use_dict_1=False))

        return self._get_output(segment, nop_output)

    def sanity_check(self) -> bool:
        if self.machine is None:
            return True
        min_match = self.machine.params.min_match
        colls = self.instance.colls
        min_coll_len = min(min(len(s) for s in row) for row in colls)
        if min_coll_len < min_match:
            return False
        if self.nop_gadget is not None and not self.nop_gadget.sanity_check():
            return False
        if self.mirroring_gadget and not self.aligned:
            return False
        if self.auto_expand is True:
            return True
        # more checks can be added
        return True


class AltCollisionAmplify(CollisionAmplify):
    """An alternative construction for a collision-based amplify gagdet, which
    works by aligning the collisions."""

    def __init__(
        self,
        max_len: int,
        instance: DeflateInstanceSet,
        l: int | None,
        nop_gadget: DeflateGadget | None,
        auto_expand: bool = False,
        no_dict: bool = False,
        add_colls_to_dict: bool = False,
        mirroring_gadget: "AltCollisionAmplify | None" = None,
        min_expand: int | None = None,
        skip_validation: bool = False,
        aligned: bool = True,
        relax_align: bool = False,
        charset: bytes | None = None,
    ):
        """Initialize an alternative collision-based amplify gadget.

        The argument `l` indicates the expected length of each collision; if
        `None` is provided, then it will be computed or chosen automatically.

        The argument `relax_align` (default `False`) denotes whether to keep the
        states while squeezing out more space by truncating the last segment.
        This can cause problems when mirroring gadgets.

        Please refer to the docstring of the `__init__()` method in
        `CollisionAmplify` for a description of the other arguments.
        """

        if not auto_expand:
            l = len(self.instance.colls[0][0])
            assert all(len(s) == l for row in self.instance.colls for s in row)
        self.l: int | None = l

        assert (not relax_align) or aligned  # relax_align => aligned
        self.relax_align = relax_align

        super().__init__(
            max_len=max_len,
            instance=instance,
            nop_gadget=nop_gadget,
            auto_expand=auto_expand,
            optimize_expand=0,
            no_dict=no_dict,
            add_colls_to_dict=add_colls_to_dict,
            mirroring_gadget=mirroring_gadget,
            min_expand=min_expand,
            skip_validation=skip_validation,
            aligned=aligned,
            charset=charset,
        )

    def expand_instance(self, rng: Random | None = None) -> DeflateInstanceSet | None:
        """Expand the instance set to a suitable instance set.

        Note that this method is not guaranteed to generate a valid instance,
        because the requirements for a suitable instance set is not specified
        for the alternative construction."""

        if self.mirroring_gadget is not None:
            return self.mirroring_gadget.instance
        if self.machine is None:
            return None
        max_chain = self.machine.params.max_chain
        if max_chain is None:
            return None
        max_lazy = self.machine.params.max_lazy
        max_insert = self.machine.params.max_insert

        orig_inst = self.orig_instance
        k, m = orig_inst.k, orig_inst.m
        min_coll_len = min(min(len(s) for s in row) for row in orig_inst.colls)
        max_coll_len = max(max(len(s) for s in row) for row in orig_inst.colls)

        min_expand = 1
        if self.min_expand is not None:
            min_expand = self.min_expand

        l = self._get_l(min_expand=min_expand)
        if l is None or l < max_coll_len + min_expand:  # no hope
            return None

        is_slow_inst = orig_inst.is_deflate_slow_instance()
        charset = charset_with_fallback(self.charset, self.machine)

        if is_slow_inst:
            is_consistent = orig_inst.is_consistent_deflate_slow_instance()
            if is_consistent:
                min_k = max_chain // (4 * m) + 1
                max_k = (max_chain - 4) // (2 * m)
                val_func = DeflateInstanceSet.is_consistent_deflate_slow_instance
            else:
                assert m == 2, "can't help you with this instance set"
                min_k = max_chain // 4 + 1
                max_k = (max_chain - 4) // 2
                val_func = DeflateInstanceSet.is_deflate_slow_instance
            if min_k <= k <= max_k:  # the original instance works
                return None

            for new_k in range(min_k, min(max_k + 1, min_k + 5)):
                if m == 2 and new_k % 2 != 0:
                    continue
                expanded_inst = orig_inst.expand_to_fixed_len(
                    charset=charset,
                    target_k=new_k,
                    target_l=l,
                    val_func=None if self.skip_validation else val_func,
                    rng=rng,
                )
                if expanded_inst is not None:
                    return expanded_inst
            return None
        elif max_lazy is not None:
            if max_lazy <= min_coll_len + 5:  # can still do deflate fast
                min_expand = max(min_expand, min_coll_len - max_lazy)
            else:
                return None

        is_fast_inst = orig_inst.is_consistent_deflate_fast_instance()
        if not is_fast_inst:
            return None
        # Again, to make things less nasty, we assume (without checking!)
        # that the instance set doesn't have double collisions with length
        # below or equal to `max_insert`, otherwise you should DIY
        min_k = max_chain // (2 * m) + 1
        if self.add_colls_to_dict:
            max_k = (max_chain - 1) // m
        else:
            max_k = (max_chain - 2) // m
        # if is_slow_inst and max_insert is not None:
        #     min_expand = max(min_expand, max_insert - min_coll_len)

        l = self._get_l(min_expand=min_expand)
        if l is None or l < max_coll_len + min_expand:  # no hope
            return None

        for new_k in range(min_k, min(max_k + 1, min_k + 5)):
            if m == 2 and new_k % 2 != 0:
                continue
            expanded_inst = orig_inst.expand_to_fixed_len(
                charset=charset,
                target_k=new_k,
                target_l=l,
                val_func=(
                    None
                    if self.skip_validation
                    else DeflateInstanceSet.is_consistent_deflate_fast_instance
                ),
                rng=rng,
            )
            if expanded_inst is not None:
                return expanded_inst
        return None

    def _get_l(self, min_expand: int) -> int | None:
        if self.l is None:
            assert self.machine is not None
            max_match = self.machine.params.max_match
            max_lazy = self.machine.params.max_lazy
            max_coll_len = max(
                max(len(s) for s in row) for row in self.orig_instance.colls
            )
            min_l = max_coll_len + min_expand
            for l in range(min_l, max_match):
                if gcd(l, max_match) == 1:
                    continue
                if max_lazy is not None and l < max_lazy and gcd(l, max_match) == 2:
                    continue
                return l
            return None
        else:
            return self.l

    def _get_output(self, segment: bytes, nop_output: bytes) -> bytes | None:
        seg_len, nop_len = len(segment), len(nop_output)
        n_unaligned = n = (self.max_len - nop_len) // seg_len
        l = len(self.instance.colls[0][0])
        num_colls = (self.max_len - nop_len) // l
        # try to keep the difference in LZ77 pointer positions
        if self.machine is not None and self.aligned:
            max_match = self.machine.params.max_match
            omega_n = max_match // gcd(max_match, seg_len)
            omega_colls = max_match // gcd(max_match, l)
            if self.machine.params.max_insert is None:
                if self.mirroring_gadget is None:
                    n -= (n - 1) % omega_n
                    num_colls -= (num_colls - (seg_len // l)) % omega_colls
                else:
                    n -= n % omega_n
                    num_colls -= num_colls % omega_colls
            else:  # give up
                pass
        if self.aligned:
            if self.relax_align:
                return nop_output + (segment * (n_unaligned + 1))[: num_colls * l]
            else:
                return nop_output + segment * n
        else:
            return (nop_output + segment * (n + 1))[: self.max_len]

    def sanity_check(self) -> bool:
        if self.machine is not None:
            if self.machine.params.max_insert is not None:
                if self.aligned:  # cannot really guarantee alignment
                    return False
                if self.mirroring_gadget is not None:
                    return False
        return super().sanity_check()


class QuickCollisionAmplify(DeflateGadget):
    """A collision-based amplify gadget for the `deflate_fast` strategy with
    `max_chain=1` or any similar strategies, such as the `deflate_quick`
    strategy, used at level 1 in zlib-ng."""

    def __init__(
        self,
        max_len: int,
        k: int | None,
        nop_gadget: DeflateGadget | None,
        min_glue_len: int | None = None,
        repeat_glue: bool = True,
        aligned: bool = True,
        charset: bytes | None = None,
    ):
        """Initialize a quick collision-based amplify gadget.

        This gadget can also be used for the Snappy-style compressor at
        level 1 in zlib-go, but there the query cannot span multiple DEFLATE
        blocks, meaning the amplification cannot be arbitrarily large.

        Args:
            max_len: The maximum length of the gadget.
            k: The length of each collision in the gadget, or `None`, in which
                case `k` will be set to `min_match` during compilation.
            nop_gadget: A NOP gadget for separation.
            min_glue_len: The minimum length of a glue string `glue`, appended
                (once or twice) to every `4m` collisions to form a segment of
                length `max_match`. The default value of `min_glue_len` is
                `None`, in which case it will be set to `min_match` during
                compilation.
            repeat_glue: Whether to repeat `glue` within each segment; default
                `True`, which requires that `max_match` be even. If set to
                `False`, the case where `max_match` is odd is supported, but
                the dictionary will become slightly longer.
            aligned: Default `True`. If the gadget does not need to keep the
                state, then it can be disabled to squeeze out more space by
                producing output that is precisely `max_len` bytes.
            charset: The allowed bytes for this gadget, or `None` if it's the
                same as the allowed bytes for the automaton; default `None`.
        """

        super().__init__()

        self.max_len: int = max_len
        self.k: int | None = k
        self.nop_gadget: DeflateGadget | None = nop_gadget
        self.min_glue_len: int | None = min_glue_len
        self.repeat_glue: bool = repeat_glue
        self.aligned: bool = aligned
        self.charset: bytes | None = charset

    def bind(self, machine: "CRIMEAutomaton | None", should_flush: bool = True) -> None:
        super().bind(machine, should_flush=should_flush)
        if self.nop_gadget is not None:
            self.nop_gadget.bind(machine=machine, should_flush=True)

    def set_prev_gadget(self, gadget: "Gadget | None") -> None:
        super().set_prev_gadget(gadget)
        if self.nop_gadget is not None:
            self.nop_gadget.set_prev_gadget(gadget)

    def _compile_nop_gadget(self, rng: Random | None) -> bytes | None:
        if self.nop_gadget is None:
            return None
        nop_output = self.nop_gadget.compile(
            rng, force_recompile=True, execute_actions=False
        )
        self.actions = self.nop_gadget.actions
        return nop_output

    def _get_k(self) -> int:
        if self.k is None:
            assert self.machine is not None
            return self.machine.params.min_match
        return self.k

    def _get_glue_length(self) -> int:
        assert self.machine is not None
        min_match = self.machine.params.min_match
        max_match = self.machine.params.max_match
        # assert max_match % 2 == 0 or not self.repeat_glue

        glue_count = 1 + int(self.repeat_glue)
        min_glue_len = min_match if self.min_glue_len is None else self.min_glue_len

        k = self._get_k()
        m = (max_match - glue_count * min_glue_len) // (4 * k)
        glue_length = (max_match - 4 * k * m) // glue_count

        # assert min_glue_len <= glue_length < max_match
        # assert 4 * k * m + glue_count * glue_length == max_match

        return glue_length

    def _get_nop_on_the_fly(self, rng: Random | None) -> bytes | None:
        if self.machine is None:
            return None
        charset = charset_with_fallback(self.charset, self.machine)
        min_match = self.machine.params.min_match
        nop_output = RandBytes(charset, rng).randbytes(min_match + 2)
        wordlist: list[WORD_TYPE] = [
            self.compound_word(1, nop_output[:-1]),
            nop_output,
        ]
        self.actions = [self._add_to_dict(wordlist, use_dict_1=False)]
        return nop_output

    def __call__(self, rng: Random | None) -> bytes | None:
        if self.machine is None:  # must fix machine so that we know max_match
            return None
        max_match = self.machine.params.max_match

        if self.nop_gadget is None:
            nop_output = self._get_nop_on_the_fly(rng)
        else:
            nop_output = self._compile_nop_gadget(rng)
        if nop_output is None:
            return None

        tail_byte = bytes([nop_output[-1]])

        k = self._get_k()
        glue_length = self._get_glue_length()
        charset = charset_with_fallback(self.charset, self.machine)

        rbg = RandBytes(charset, rng)
        coll_1 = rbg.randbytes(k)
        coll_2 = bytes([rbg.randbyte_with_taboo(coll_1[0])]) + rbg.randbytes(k - 1)
        glue = (
            bytes([rbg.randbyte_with_taboo([coll_1[0], coll_2[0]])])
            + rbg.randbytes(glue_length - 2)
            + tail_byte
        )
        if self.repeat_glue:
            glue += glue

        m = (max_match - len(glue)) // (4 * k)
        segment = (coll_1 + coll_1 + coll_2 + coll_2) * m + glue
        # assert len(segment) == max_match, segment

        wordlist: list[WORD_TYPE] = [tail_byte + segment]
        if not self.repeat_glue:
            alt_segment = (coll_2 + coll_2 + coll_1 + coll_1) * m + glue
            wordlist += [tail_byte + alt_segment]
            segment += alt_segment

        self.actions.append(self._add_to_dict(wordlist, use_dict_1=False))

        n = (self.max_len - len(nop_output)) // len(segment)
        if n == 0 and self.aligned:
            return None  # or raise an exception

        if self.aligned:
            return nop_output + segment * n
        else:
            return (nop_output + segment * (n + 1))[: self.max_len]

    def sanity_check(self) -> bool:
        if self.machine is None:
            return False
        strategy = self.machine.params.strategy
        if strategy not in (DeflateStrategy.ng_quick, DeflateStrategy.go_quick):
            return False
        # miniz with max_chain <= 3 may or may not work depending on whether
        # `tdefl_compress_normal` is used or not; please check this yourself

        min_match = self.machine.params.min_match
        max_match = self.machine.params.max_match
        if max_match % 2 != 0 and self.repeat_glue:
            return False

        k = self._get_k()
        glue_length = self._get_glue_length()
        if k < min_match or glue_length < min_match:
            return False
        if self.repeat_glue:
            glue_length += glue_length
        if glue_length >= max_match or (max_match - glue_length) % (4 * k) != 0:
            return False
        if self.nop_gadget is not None and not self.nop_gadget.sanity_check():
            return False
        return True


# ----- logical gadgets -----


class ShortNOT(CustomOrRandomGadget, DeflateGadget):

    def __init__(
        self,
        content: bytes | None = None,
        length: int | None = None,
        charset: bytes | None = None,
    ):
        CustomOrRandomGadget.__init__(
            self, content=content, length=length, charset=charset
        )
        DeflateGadget.__init__(self)

    def get_length(self) -> int:
        if self.length is None:
            assert self.machine is not None
            length = self.machine.params.min_match - 1
            assert length >= 0
            return length
        return self.length

    def __call__(self, rng: Random | None) -> bytes | None:
        output = CustomOrRandomGadget.__call__(self, rng)
        if output is not None:
            self.actions = [
                self._add_to_dict([self.compound_word(1, output)], use_dict_1=False)
            ]
        return output

    def sanity_check(self) -> bool:
        if self.machine is None:
            return True
        return self.get_length() == self.machine.params.min_match - 1


class LongFastNOT(CustomOrRandomGadget, DeflateGadget):

    def __init__(
        self,
        content: bytes | None = None,
        k: int | None = None,
        charset: bytes | None = None,
    ):
        assert k is None or k > 0
        self.k = k
        CustomOrRandomGadget.__init__(
            self, content=content, length=None, charset=charset
        )
        DeflateGadget.__init__(self)

    def _get_k(self) -> int:
        if self.k is None:
            if self.length is None:
                assert self.machine is not None
                k = self.machine.params.min_match
            else:
                k = (self.length + 1) // 2
            assert k > 0
            return k
        return self.k

    def get_length(self) -> int:
        if self.length is None:
            k = self._get_k()
            return 2 * k - 1
        return self.length

    def __call__(self, rng: Random | None) -> bytes | None:
        k = self._get_k()
        output = CustomOrRandomGadget.__call__(self, rng)
        if output is not None:
            self.actions = [
                self._add_to_dict(
                    [
                        self.compound_word(1, output[: k - 1]),
                        output[:-1],
                        output[k - 1 :],
                    ],
                    use_dict_1=False,
                )
            ]
        return output

    def sanity_check(self) -> bool:
        if self.machine is None:
            return True
        k = self._get_k()
        if k < self.machine.params.min_match:
            return False
        length = self.get_length()
        if length < 2 * k - 1:
            return False
        max_lazy = self.machine.params.max_lazy
        return max_lazy is None or k >= max_lazy


class LongGeneralNOT(CustomOrRandomGadget, DeflateGadget):
    def __init__(
        self,
        content: bytes | None = None,
        k: int | None = None,
        charset: bytes | None = None,
    ):
        assert k is None or k > 0
        self.k = k
        CustomOrRandomGadget.__init__(
            self, content=content, length=None, charset=charset
        )
        DeflateGadget.__init__(self)

    def _get_k(self) -> int:
        if self.k is None:
            assert self.machine is not None
            if self.length is None:
                k = self.machine.params.min_match
            else:
                k = self.length - self.machine.params.min_match + 1
            assert k > 0
            return k
        return self.k

    def get_length(self) -> int:
        if self.length is None:
            assert self.machine is not None
            k = self._get_k()
            return k + self.machine.params.min_match - 1
        return self.length

    def __call__(self, rng: Random | None) -> bytes | None:
        k = self._get_k()
        output = CustomOrRandomGadget.__call__(self, rng)
        if output is not None:
            length = len(output)
            self.actions = [
                self._add_to_dict(
                    [
                        self.compound_word(1, output[:-k]),
                        output[min(1, length - k - 1) : -1],
                        output[-k:],
                    ],
                    use_dict_1=False,
                )
            ]
        return output

    def sanity_check(self) -> bool:
        if self.machine is None:
            return True
        min_match = self.machine.params.min_match
        k = self._get_k()
        if min_match == 2:
            return k == 2
        if k < min_match:
            return False
        length = self.get_length()
        if length != k + min_match - 1:
            return False
        # we don't need to check the length of the second word, which is
        # mid_len = length - 2 >= k so the second word (1) >= min_match
        # (2) can't be improved by lazy matching with the last word
        return True


class LongLazyNOT(CustomOrRandomGadget, DeflateGadget):
    def __init__(
        self,
        content: bytes | None = None,
        k: int | None = None,
        charset: bytes | None = None,
    ):
        assert k is None or k > 0
        self.k = k
        CustomOrRandomGadget.__init__(
            self, content=content, length=None, charset=charset
        )
        DeflateGadget.__init__(self)

    def _get_k(self) -> int:
        if self.k is None:
            assert self.machine is not None
            if self.length is None:
                k = self.machine.params.min_match + 1
            else:
                k = self.length // 2 + 1
            assert k > 0
            return k
        return self.k

    def get_length(self) -> int:
        if self.length is None:
            assert self.machine is not None
            k = self._get_k()
            return max(2 * (k - 1), k + 2)
        return self.length

    def __call__(self, rng: Random | None) -> bytes | None:
        k = self._get_k()
        output = CustomOrRandomGadget.__call__(self, rng)
        if output is not None:
            self.actions = [
                self._add_to_dict(
                    [
                        self.compound_word(1, output[: k - 1]),
                        output[1:-1],
                        output[k - 1 :],
                    ],
                    use_dict_1=False,
                )
            ]
        return output

    def sanity_check(self) -> bool:
        if self.machine is None:
            return True
        min_match = self.machine.params.min_match
        max_lazy = self.machine.params.max_lazy
        if max_lazy is None:
            return False
        k = self._get_k()
        if k < min_match + 1 or k - 1 >= max_lazy:
            return False
        length = self.get_length()
        mid_len = length - 2
        if mid_len <= k - 1:
            return False
        # let fin_len = length - k + 1
        # mid_len - fin_len = k-3 >= min_match - 2 >= 0
        # the second word can't be improved by the last word w/ lazy matching
        return True


class LongAutomatedNOT(ParallelGadget):
    def __init__(
        self,
        content: bytes | None = None,
        k: int | None = None,
        charset: bytes | None = None,
    ):
        long_fast_not = LongFastNOT(content=content, k=k, charset=charset)
        long_gen_not = LongGeneralNOT(content=content, k=k, charset=charset)
        # `long_lazy_not` is probably not going to be used in most cases,
        # but we include it here for completeness
        long_lazy_not = LongLazyNOT(content=content, k=k, charset=charset)
        super().__init__(gadgets=[long_fast_not, long_gen_not, long_lazy_not])


DefaultNOT = ShortNOT


class ANDTargetMatch(DeflateGadget):

    def __init__(
        self, match_gadget: TargetMatch, nop_gadget: DeflateGadget | None = None
    ):
        """Initialize an AND-target-match gadget.

        Args:
            match_gadget: The target-match gadget used in this gadget.
            nop_gadget: An optional NOP gadget that precedes the match gadget.
        """
        super().__init__()
        self.match_gadget = match_gadget
        self.nop_gadget = nop_gadget

    def bind(self, machine: "CRIMEAutomaton | None", should_flush: bool = True) -> None:
        super().bind(machine, should_flush=should_flush)
        self.match_gadget.bind(machine=machine, should_flush=True)
        if self.nop_gadget is not None:
            self.nop_gadget.bind(machine=machine, should_flush=True)

    def set_prev_gadget(self, gadget: "Gadget | None") -> None:
        super().set_prev_gadget(gadget)
        if self.nop_gadget is None:
            self.match_gadget.set_prev_gadget(gadget)
        else:
            self.match_gadget.set_prev_gadget(self.nop_gadget)
            self.nop_gadget.set_prev_gadget(gadget)

    def __call__(self, rng: Random | None) -> bytes | None:
        if self.nop_gadget is not None:
            nop_output = self.nop_gadget.compile(
                rng, force_recompile=True, execute_actions=False
            )
            if nop_output is None:
                return None
            self.actions = self.nop_gadget.actions
        else:
            nop_output = b""

        # we ignore the actions of match as we add match_output[:-1] anyway
        match_output = self.match_gadget.compile(
            rng, force_recompile=True, execute_actions=False
        )
        if match_output is None:  # in place to satisfy the type checker
            return None

        def action(self: DeflateGadget) -> None:
            if self.machine is None:
                return
            prev = nop_output[-1:] if len(nop_output) > 0 else self._last_bytes(1)
            self.machine.dict_2.append(prev + match_output[:-1])

        self.actions.append(action)
        return nop_output + match_output

    def sanity_check(self) -> bool:
        if not self.match_gadget.sanity_check():
            return False
        if self.nop_gadget is not None and not self.nop_gadget.sanity_check():
            return False
        # It should be mostly fine at this point except for a few corner cases;
        # e.g., if `min_match=2`, then this gadget may affect the previous one
        # when lazy matching is enabled and the nop gadget is not of 2 bytes in
        # length, but since `min_match=2` is weird anyway I'm letting it slide.
        return True


class BaseORTargetMatch(DeflateGadget):

    def __init__(
        self,
        match_gadget: TargetMatch,
        glue_content: bytes | None = None,
        glue_length: int | None = None,
        glue_charset: bytes | None = None,
        k: int | None = None,
    ):
        """Initialize an OR-target-match gadget.

        Args:
            match_gadget: The target-match gadget used in this gadget.
            glue_content: A short byte string ("glue") between the match gadget
                and its preceding gadgets, where some byte in "glue" preferably
                does not occur elsewhere, or `None`.
            glue_length: If `glue_content=None`, then the automaton will try to
                generate a random string of `glue_length` bytes as the glue, or
                choose `glue_length` automatically if it is `None`; otherwise,
                `glue_length` is ignored.
            glue_charset: The character set used to generate the glue, which
                is allowed to be `None` (by default) if the glue content has
                been specified or the character set is intended to be the same
                as that of the automaton.
            k: A value that controls the actions of the gadget; more precisely,
                the last word to be added to a dictionary for this gadget is
                the last `k` bytes of the match gadget. Its value is to be
                determined automatically when `None` is provided.
        """
        super().__init__()
        self.match_gadget = match_gadget
        self.match_len = len(match_gadget.target)
        self.glue_content: bytes | None = glue_content
        self.glue_length: int | None = (
            glue_length if glue_content is None else len(glue_content)
        )
        self.glue_charset: bytes | None = glue_charset
        self.k: int | None = k

    def bind(self, machine: "CRIMEAutomaton | None", should_flush: bool = True) -> None:
        super().bind(machine, should_flush=should_flush)
        self.match_gadget.bind(machine=machine, should_flush=True)

    def _get_k(self) -> int:
        if self.k is None:
            assert self.machine is not None
            return self.machine.params.min_match
        return self.k

    def _get_glue_length(self) -> int:
        raise NotImplementedError("Override this method")

    def _get_words(self, glue: bytes, match_output: bytes) -> list[WORD_TYPE]:
        raise NotImplementedError("Override this method")

    def __call__(self, rng: Random | None) -> bytes | None:
        if self.glue_content is not None:
            glue = self.glue_content
        else:
            charset = charset_with_fallback(self.glue_charset, self.machine)
            glue_length = self._get_glue_length()
            assert glue_length is not None
            glue = RandBytes(charset, rng).randbytes(glue_length)

        match_output = self.match_gadget.compile(
            rng, force_recompile=True, execute_actions=False
        )
        if match_output is None:  # in place to satisfy the type checker
            return None

        wordlist = self._get_words(glue, match_output)
        self.actions = [
            self._add_to_dict(wordlist, use_dict_1=False)
        ] + self.match_gadget.actions

        return glue + match_output

    def sanity_check(self) -> bool:
        return self.match_gadget.sanity_check()


class GeneralORTargetMatch(BaseORTargetMatch):
    def _get_glue_length(self) -> int:
        if self.glue_length is not None:
            return self.glue_length
        assert self.machine is not None
        return self.machine.params.min_match  # min_match - 1 is also fine

    def _get_words(self, glue: bytes, match_output: bytes) -> list[WORD_TYPE]:
        k = self._get_k()
        return [  # if you're wondering: the order matters!
            glue + match_output[:-k],
            self.compound_word(1, glue),
            match_output[-k:],
        ]

    def _get_k(self) -> int:
        if self.k is not None:
            return self.k
        # If max_insert is present, then having a too large `k` might cause
        # unwanted interactions for some dictionary types used. Here we try
        # to do something about this so as to minimize its confusion to users.
        if self.machine is not None:
            max_insert = self.machine.params.max_insert
            if max_insert is not None:
                return min(self.match_len - 1, max_insert)  # >= min_match
        return self.match_len - 1

    def sanity_check(self) -> bool:
        if not super().sanity_check():
            return False
        if self.machine is None:
            return True

        glue_len = self._get_glue_length()
        k = self._get_k()
        mid_len = glue_len + self.match_len - k
        min_match = self.machine.params.min_match
        max_lazy = self.machine.params.max_lazy

        if (
            glue_len < min_match - 1
            or mid_len < min_match
            or k < min_match
            or self.match_len < min_match + 1
            or k > self.match_len
        ):
            return False
        if max_lazy is None:
            return True
        if glue_len + 1 < max_lazy and glue_len + 1 < mid_len:
            return False
        if glue_len == 1 and mid_len < max_lazy and mid_len < self.match_len:
            return False
        return True


class LazyORTargetMatch(BaseORTargetMatch):
    def _get_glue_length(self) -> int:
        if self.glue_length is not None:
            return self.glue_length
        assert self.machine is not None
        return self.machine.params.min_match

    def _get_words(self, glue: bytes, match_output: bytes) -> list[WORD_TYPE]:
        k = self._get_k()
        return [
            self.compound_word(1, glue),
            glue[1:] + match_output[:-k],
            match_output[-k:],
        ]

    def sanity_check(self) -> bool:
        if not super().sanity_check():
            return False
        if self.machine is None:
            return True

        glue_len = self._get_glue_length()
        k = self._get_k()
        mid_len = glue_len - 1 + self.match_len - k
        min_match = self.machine.params.min_match
        max_lazy = self.machine.params.max_lazy

        if glue_len < min_match or k < min_match:
            return False
        if max_lazy is None or glue_len >= max_lazy or mid_len <= glue_len:
            return False
        # Here we know `mid_len >= glue_len + 1`, therefore we have:
        # (a) `mid_len >= min_match + 1`, and
        # (b) `glue_len - 1 + match_len - k >= glue_len + 1`,
        #     implying `match_len >= k + 2 >= min_match + 2`.
        if glue_len == 2 and mid_len < max_lazy and mid_len < self.match_len - 1:
            # The lazy match can further be improved by the match prefix;
            # note that the final condition is equivalent to `glue_len < k`.
            return False
        return True


class AutomatedORTargetMatch(ParallelGadget):
    def __init__(
        self,
        match_gadget: TargetMatch,
        glue_content: bytes | None = None,
        glue_length: int | None = None,
        glue_charset: bytes | None = None,
        k: int | None = None,
    ):
        or_match_gadgets = [
            or_match(
                match_gadget,
                glue_content=glue_content,
                glue_length=glue_length,
                glue_charset=glue_charset,
                k=k,
            )
            for or_match in (GeneralORTargetMatch, LazyORTargetMatch)
        ]

        super().__init__(gadgets=or_match_gadgets)


# A note on XOR-match:
# For anyone looking for the implementation of an XOR-match gadget, I don't
# have time to implement this properly but let me say it should be possible
# without relying on hash collisions (I don't want to go into this too much)
# when `max_insert < 258`, i.e., not every substring is inserted into the
# hash table; the idea is to have a trapdoor-NOT gadget that can be turned
# into a NOP gadget depending on whether some substrings are inserted, which
# can be easily done by adding and removing a match in a long NOT gadget.
# Roughly, an XOR-match gadget consists of one or more NOP(-like) gadgets
# around length `max_insert`, carefully designed such that depending on the
# starting state different strings will be inserted into the hash table;
# they are followed by a match gadget and then a trapdoor-NOT gadget. As one
# can see this construction is very error-prone at best. An alternative could
# be using more than two states (temporarily). In practice the best one can
# do is to forgo the XOR functionality or imitate it through the more stable
# gadgets I have implemented here (and pay attention to their interactions).
