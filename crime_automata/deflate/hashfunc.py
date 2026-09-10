from collections.abc import Callable

from ..hashfunc import HashFunc


class DeflateHash(HashFunc):

    def __init__(self, func: Callable[[bytes], int], min_match: int, hash_bits: int):
        HashFunc.__init__(self, func=func, input_len=min_match, range_bits=hash_bits)
        self.min_match: int = min_match
        self.hash_bits: int = hash_bits
