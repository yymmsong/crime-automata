from collections.abc import Callable
from itertools import product


class HashFunc:
    """A hash function that maps bytes of length `input_len` to an integer
    within the range `[0, 2^range_bits)`."""

    def __init__(self, func: Callable[[bytes], int], input_len: int, range_bits: int):
        if input_len <= 0 or range_bits <= 0:
            raise ValueError("input_len and range_bits must be positive.")
        self.func: Callable[[bytes], int] = func
        self.input_len: int = input_len
        self.range_bits: int = range_bits

    def __call__(self, data: bytes | str) -> int:
        """Return the hash value of the data, truncating the data to its prefix
        of length `input_len` when necessary."""
        if isinstance(data, str):
            data = data.encode("utf-8")
        if len(data) < self.input_len:
            raise ValueError("Input is too short.")
        return self.func(data[: self.input_len])

    def check_compact(self, colls: list[bytes], is_double: bool = False) -> bool:
        """Check if a set of strings is compact, which means every string has a
        length of `input_len` if `is_double=False`, or `input_len+1` if
        `is_double=True`."""
        target_len = self.input_len + int(is_double)

        for s in colls:
            if len(s) != target_len:
                return False
        return True

    def check_colliding(self, colls: list[bytes]) -> bool:
        """Check if a set of strings is colliding."""
        if len(colls) < 1:
            return False

        val = 0
        for i, s in enumerate(colls):
            if len(s) < self.input_len:
                return False
            cur_val = self(s)
            if i == 0:
                val = cur_val
            elif val != cur_val:
                return False

        return True

    def check_weakly_double_colliding(self, colls: list[bytes]) -> bool:
        """Check if a set of strings is weakly double-colliding."""
        return self.check_colliding(colls) and self.check_colliding(
            [s[1:] for s in colls]
        )

    def check_double_colliding(self, colls: list[bytes]) -> bool:
        """Check if a set of strings is double-colliding."""
        return self.check_colliding(colls + [s[1:] for s in colls])

    def check_strongly_double_colliding(self, colls: list[bytes], c: int) -> bool:
        """Check if a set of strings is strongly double-colliding with regard
        to a specified byte `c`."""
        assert 0 <= c < 256
        if len(colls) < 1:
            return False
        target = bytes([c] * (self.input_len + 1))
        return self.check_double_colliding([target] + colls)

    def find_all_collisions_at(self, val: int, charset: bytes) -> list[bytes]:
        collisions = []
        for s_tup in product(charset, repeat=self.input_len):
            s = bytes(s_tup)
            if self.func(s) == val:
                collisions.append(s)
        return collisions

    def compute_collision_counts(self, charset: bytes) -> list[tuple[int, int]]:
        table_size = 1 << self.range_bits
        cnts = [0] * table_size
        for s_tup in product(charset, repeat=self.input_len):
            s = bytes(s_tup)
            cnts[self.func(s)] += 1
        return sorted(list(zip(range(table_size), cnts)), key=lambda x: -x[1])

    def find_all_double_collisions_at(self, val: int, charset: bytes) -> list[bytes]:
        collisions = self.find_all_collisions_at(val, charset)
        double_colls = []
        charset_bytes = tuple(bytes([x]) for x in charset)
        for s in collisions:
            for c in charset_bytes:
                if self.func(s[1:] + c) == val:
                    double_colls.append(s + c)
        return double_colls
