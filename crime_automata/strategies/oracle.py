from collections.abc import Callable
from enum import IntEnum
from random import Random, SystemRandom
from typing import Any

from .. import randbytes, utils


class CompressionLengthOracle:
    """An oracle that returns the compressed length of the query together with
    other data.

    The oracle helps to abstract away the details involved in interacting with
    the target."""

    def __init__(self):
        pass

    def set_secret(self, secret: bytes) -> None:
        raise NotImplementedError()

    def __call__(self, query: bytes) -> int:
        """Query the compression length oracle.

        Args:
            query: the query to make.

        Returns:
            The length of the compressed data."""
        raise NotImplementedError()


class WrapperCompressionLengthOracle(CompressionLengthOracle):
    """A compression length oracle, built by wrapping around an existing
    procedure, which can be, e.g., real-world interactions."""

    def __init__(self, procedure: Callable[[bytes], int]):
        super().__init__()
        self.procedure = procedure

    def __call__(self, query: bytes) -> int:
        return self.procedure(query)


class Placeholder(IntEnum):
    SECRET = 0
    QUERY = 1
    NOISE = 2


class TestCompressionLengthOracle(CompressionLengthOracle):
    """A compression length oracle that facilitates testing."""

    def __init__(
        self,
        template: bytes | list[bytes | int | Placeholder],
        compress: Callable[[Any], bytes],
        secret: bytes = b"",
        noise_lens: list[Callable[[Random], int] | int] | None = None,
        noise_charset=utils.ALL_BYTES,
        pad_len: Callable[[int, Random | None], int] | int | None = None,
        rng: Random | None = None,
    ):
        """Initialize a test compression length oracle.

        Args:
            template: A template for how the data to be compressed should look
                like. The template can be a byte string, in which case it is
                assumed that no noise is present and the query is to be
                appended to the end of the template. Or the template can be a
                list of byte strings and integers, where 0 is a placeholder for
                the secret, 1 is a placeholder for the query, and 2 is a
                placeholder for any noise.
                On each call, the placeholders will be replaced by query and
                noise as specified, and then the byte strings in the list will
                be concatenated to form the byte string to be compressed.
            compress: The compression method to use.
            secret: The secret embedded in the data. This parameter has no
                effect if there are no secret placeholders in the template.
                If the secret is supposed to be fixed, then one can hardcode
                it in the template instead of setting this parameter.
            noise_lens: The noise lengths. Each entry in `noise_lens` can
                either be an integer that represents the noise length or
                a method that returns on call the noise length (so that the
                noise lengths can be randomized); default `None`.
            noise_charset: The character set to use for noise generation, which
                is all byte values by default.
            pad_len: The padding length. Like `noise_lens`, it can be a fixed
                integer representing the padding length, or a method that takes
                the size of the compressed data and an optional RNG as input
                and returns an integer that represents the padding length. The
                default is `None`, meaning no padding will be used.
            rng: A random number generator, possibly used for generating noise
                lengths, noise, and the padding length. If using the same RNG
                for different purposes doesn't sound ideal to you for some
                reason, there's also the option of programming `noise_lens` or
                `pad_len` to use different (hard-coded) RNGs.
        """
        super().__init__()

        self.template: bytes | list[bytes | int | Placeholder] = template
        self.compress: Callable[[Any], bytes] = compress
        self.secret: bytes = secret
        if noise_lens is None:
            noise_lens = []
        self.noise_lens: list[Callable[[Random], int] | int] = noise_lens
        self.pad_len: Callable[[int, Random | None], int] | int | None = pad_len
        if rng is None:  # default to high-quality randomness
            rng = SystemRandom()
        self.rng: Random = rng

        self.rbg = randbytes.RandBytes(noise_charset, rng)

    def set_secret(self, secret: bytes) -> None:
        self.secret = secret

    def _compress(self, query: bytes) -> bytes:
        if isinstance(self.template, list):
            data = bytearray()
            secret_replaced = False
            query_replaced = False
            noise_cnt = 0
            for s in self.template:
                if isinstance(s, int):
                    if s == Placeholder.SECRET:
                        assert not secret_replaced, "too many secret placeholders"
                        data.extend(self.secret)
                        secret_replaced = True
                    elif s == Placeholder.QUERY:
                        assert not query_replaced, "too many query placeholders"
                        data.extend(query)
                        query_replaced = True
                    elif s == Placeholder.NOISE:
                        noise_len = self.noise_lens[noise_cnt]
                        noise_cnt += 1
                        if callable(noise_len):
                            noise_len = noise_len(self.rng)
                        data.extend(self.rbg.randbytes(noise_len))
                    else:
                        raise ValueError(f"invalid placeholder {s}")
                else:
                    data.extend(s)
            if not query_replaced:
                data.extend(query)  # put query in the end by default
            # print(data)
            return self.compress(data)
        else:
            # assert len(self.noise_lens) == 0
            return self.compress(self.template + query)

    def __call__(self, query: bytes) -> int:
        compressed = self._compress(query)
        l = len(compressed)
        if self.pad_len is not None:
            if callable(self.pad_len):
                return l + self.pad_len(l, self.rng)
            return l + self.pad_len
        return l


class ValidityCheckOracle(CompressionLengthOracle):
    """A compression length oracle for validity checks."""

    def __init__(
        self,
        template: bytes | list[bytes | int | Placeholder],
        compress: Callable[[Any], bytes],
    ):
        """Initialize a validity check compression length oracle.

        Args:
            template: A template for how the data to be compressed should look
                like. The template can be a byte string, in which case it is
                assumed that no noise is present and the query is to be
                appended to the end of the template. Or the template can be a
                list of byte strings and integers, where the integer `0` is a
                placeholder for the secret, and `1` is a placeholder for the
                query. On each call, the placeholders will be replaced by the
                secret and the query as specified, and then the byte strings
                in the list will be concatenated to form the byte string to be
                compressed.
            compress: The compression method to use.
        """
        super().__init__()

        self.template: bytes | list[bytes | int | Placeholder] = template
        self.secret: bytes = b""
        self.compress: Callable[[Any], bytes] = compress

    def set_secret(self, secret: bytes) -> None:
        self.secret = secret

    def _compress(self, query: bytes) -> bytes:
        if isinstance(self.template, list):
            data = bytearray()
            secret_replaced = False
            query_replaced = False
            for s in self.template:
                if isinstance(s, int):
                    if s == Placeholder.SECRET:
                        assert not secret_replaced, "too many secret placeholders"
                        data.extend(self.secret)
                        secret_replaced = True
                    elif s == Placeholder.QUERY:
                        assert not query_replaced, "too many query placeholders"
                        data.extend(query)
                        query_replaced = True
                else:
                    data.extend(s)
            if not secret_replaced:  # put the secret in the beginning by default
                data[0:0] = self.secret
            if not query_replaced:
                data.extend(query)  # put the query in the end by default
            return self.compress(data)
        else:
            return self.compress(self.secret + self.template + query)

    def __call__(self, query: bytes) -> int:
        return len(self._compress(query))
