from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from .hashfunc import DeflateHash


__all__ = [
    "DeflateStrategy",
    "DeflateParams",
    # zlib
    "get_zlib_hash",
    "ZLIB_DEFAULT_HASH",
    "ZLIB_PARAMS_RAW",
    "ZLIB_PARAMS",
    "ZLIB_DEFAULT_PARAMS",
    # gzip
    "get_gzip_hash",
    "GZIP_DEFAULT_HASH",
    "GZIP_PARAMS",
    "GZIP_DEFAULT_PARAMS",
    # zlib-ng
    "zlib_ng_hash_func",
    "ZLIB_NG_HASH",
    "ZLIB_NG_PARAMS_RAW",
    "ZLIB_NG_WITHOUT_NEW_STRATEGIES_PARAMS",
    "ZLIB_NG_PARAMS",
    "ZLIB_NG_ROLLING_HASH",
    # zlib-cloudflare
    "zlib_cf_hash_func",
    "ZLIB_CLOUDFLARE_DEFAULT_HASH",
    "ZLIB_CLOUDFLARE_PARAMS",
    # zlib-chromium
    "zlib_cr_hash_func",
    "ZLIB_CHROMIUM_DEFAULT_HASH",
    "ZLIB_CHROMIUM_PARAMS",
    # zlib-go
    "zlib_go_hash_func",
    "zlib_go_quick_hash_func",
    "ZLIB_GO_HASH",
    "ZLIB_GO_QUICK_HASH",
    "GO_PARAMS",
    # miniz
    "get_miniz_hash",
    "MINIZ_DEFAULT_HASH",
    "MINIZ_PARAMS_RAW",
    "MINIZ_PARAMS",
    "MINIZ_DEFAULT_PARAMS",
]


class DeflateStrategy(Enum):
    others = 0
    stored = 1
    fast = 2
    slow = 3

    # The go_quick strategy is essentially Snappy. It starts to skip entries
    # after not finding matches for a while (match skipping). The hash table
    # is one-dimensional.
    go_quick = 4

    # ng_quick uses an 1D hash table and does not insert positions within a
    # match to the hash table.
    ng_quick = 5

    # essentially deflate_fast with a `fizzle_matches` procedure that may move
    # the start position of a match leftward by shrinking the previous match
    ng_medium = 6

    # essentially deflate_{fast,slow} but with slightly tweaked parameters
    miniz = 7


@dataclass
class DeflateParams:
    """Class for DEFLATE parameters."""

    good_length: int | None
    max_lazy: int | None
    max_insert: int | None
    nice_match: int | None
    max_chain: int | None
    strategy: DeflateStrategy
    min_match: int
    max_match: int = 258
    hash_func: DeflateHash | None = None


# ----- hash function and DEFLATE parameters defined in zlib/Gzip -----
def get_zlib_hash(min_match: int = 3, hash_bits: int = 15) -> DeflateHash:
    hash_shift = (hash_bits + min_match - 1) // min_match
    hash_mask = (1 << hash_bits) - 1

    def zlib_hash_func(s: bytes) -> int:
        h = 0
        for c in s:
            h = ((h << hash_shift) ^ c) & hash_mask
        return h

    return DeflateHash(zlib_hash_func, min_match, hash_bits)


get_gzip_hash = get_zlib_hash

ZLIB_DEFAULT_HASH = get_zlib_hash(min_match=3, hash_bits=15)
GZIP_DEFAULT_HASH = ZLIB_DEFAULT_HASH

# https://github.com/madler/zlib/blob/v1.3.2/deflate.c
# good, lazy, insert, nice, chain, strategy
ZLIB_PARAMS_RAW = [
    (None, None, None, None, None, DeflateStrategy.stored),
    (4, None, 4, 8, 4, DeflateStrategy.fast),
    (4, None, 5, 16, 8, DeflateStrategy.fast),
    (4, None, 6, 32, 32, DeflateStrategy.fast),
    (4, 4, None, 16, 16, DeflateStrategy.slow),
    (8, 16, None, 32, 32, DeflateStrategy.slow),
    (8, 16, None, 128, 128, DeflateStrategy.slow),
    (8, 32, None, 128, 256, DeflateStrategy.slow),
    (32, 128, None, 258, 1024, DeflateStrategy.slow),
    (32, 258, None, 258, 4096, DeflateStrategy.slow),
]

ZLIB_PARAMS = [
    DeflateParams(*params, min_match=3, hash_func=ZLIB_DEFAULT_HASH)
    for params in ZLIB_PARAMS_RAW
]
ZLIB_DEFAULT_PARAMS = ZLIB_PARAMS[6]

GZIP_PARAMS = ZLIB_PARAMS
GZIP_DEFAULT_PARAMS = ZLIB_DEFAULT_PARAMS


# ----- hash function and DEFLATE parameters defined in zlib_ng-----
def zlib_ng_hash_func(s: bytes) -> int:
    val = int.from_bytes(s[:4], "little", signed=False)
    return ((val * 2654435761) & ((1 << 32) - 1)) >> 16


ZLIB_NG_HASH = DeflateHash(zlib_ng_hash_func, min_match=4, hash_bits=16)

# https://github.com/zlib-ng/zlib-ng/blob/2.3.3/deflate.c
# good, lazy, insert, nice, chain, strategy
ZLIB_NG_PARAMS_RAW = [
    ZLIB_PARAMS_RAW[0],
    (None, None, None, None, None, DeflateStrategy.ng_quick),
    (4, None, 4, 8, 4, DeflateStrategy.fast),
    (4, None, 6 * 16, 16, 6, DeflateStrategy.ng_medium),
    (4, None, 12 * 16, 32, 24, DeflateStrategy.ng_medium),
    (8, None, 16 * 16, 32, 32, DeflateStrategy.ng_medium),
    (8, None, 16 * 16, 128, 128, DeflateStrategy.ng_medium),
] + ZLIB_PARAMS_RAW[7:]

ZLIB_NG_WITHOUT_NEW_STRATEGIES_PARAMS = [
    DeflateParams(*params, min_match=4, hash_func=ZLIB_NG_HASH)
    for params in ZLIB_PARAMS_RAW
]
ZLIB_NG_PARAMS = [
    DeflateParams(*params, min_match=4, hash_func=ZLIB_NG_HASH)
    for params in ZLIB_NG_PARAMS_RAW
]

ZLIB_NG_ROLLING_HASH = ZLIB_DEFAULT_HASH
ZLIB_NG_WITHOUT_NEW_STRATEGIES_PARAMS[9].min_match = 3
ZLIB_NG_WITHOUT_NEW_STRATEGIES_PARAMS[9].hash_func = ZLIB_NG_ROLLING_HASH
ZLIB_NG_PARAMS[9].min_match = 3
ZLIB_NG_PARAMS[9].hash_func = ZLIB_NG_ROLLING_HASH


# ----- hash function and DEFLATE parameters defined in Cloudflare's fork of zlib -----
def zlib_cf_hash_func(hash_bits: int = 15) -> Callable[[bytes], int]:
    try:
        import crc32c

        hash_mask = (1 << hash_bits) - 1

        def hash_cf(s: bytes) -> int:
            return crc32c.crc32c(s) & hash_mask

        return hash_cf

    except ImportError as e:
        # If `crc32c` can't be imported, delay raising the exception until use
        def hash_cf(s: bytes) -> int:
            raise ModuleNotFoundError("No module named 'crc32c'")

    return hash_cf


ZLIB_CLOUDFLARE_DEFAULT_HASH = DeflateHash(
    zlib_cf_hash_func(hash_bits=15), min_match=4, hash_bits=15
)

# https://github.com/RJVB/zlib-cloudflare/blob/gcc.amd64/deflate.c
ZLIB_CLOUDFLARE_PARAMS = [
    DeflateParams(*params, min_match=4, hash_func=ZLIB_CLOUDFLARE_DEFAULT_HASH)
    for params in ZLIB_PARAMS_RAW
]


# ----- hash function and DEFLATE parameters defined in Chromium's fork of zlib -----
def zlib_cr_hash_func(hash_bits: int = 15) -> Callable[[bytes], int]:
    # https://chromium.googlesource.com/chromium/src/third_party/zlib/+/refs/heads/main/contrib/optimizations/insert_string.h
    hash_mask = (1 << hash_bits) - 1

    def hash_cr(s: bytes) -> int:
        val = int.from_bytes(s[:4], "little", signed=False)
        # we actually do not need to mod 2^32, because `hash_bits <= 16`
        val = (val * 66521 + 66521) & ((1 << 32) - 1)
        return (val >> 16) & hash_mask

    return hash_cr


ZLIB_CHROMIUM_DEFAULT_HASH = DeflateHash(
    zlib_cr_hash_func(hash_bits=15), min_match=4, hash_bits=15
)

# https://chromium.googlesource.com/chromium/src/third_party/zlib/+/refs/heads/main/deflate.c
# actually `min_match = 3`, but you can't really find 3-byte matches most of
# the time when using the default hash function, so we use 4 for simplicity
ZLIB_CHROMIUM_PARAMS = [
    DeflateParams(*params, min_match=4, hash_func=ZLIB_CHROMIUM_DEFAULT_HASH)
    for params in ZLIB_PARAMS_RAW
]


# ----- hash function and DEFLATE parameters defined in Go's `flate` package -----
# https://cs.opensource.google/go/go/+/refs/tags/go1.25.9:src/compress/flate/deflate.go
GO_HASH_BITS = 17
GO_QUICK_HASH_BITS = 14


def zlib_go_hash_func(s: bytes) -> int:
    val = int.from_bytes(s[:4], "big", signed=False)
    return ((val * 506832829) & ((1 << 32) - 1)) >> (32 - GO_HASH_BITS)


def zlib_go_quick_hash_func(s: bytes) -> int:
    val = int.from_bytes(s[:4], "little", signed=False)
    return ((val * 506832829) & ((1 << 32) - 1)) >> (32 - GO_QUICK_HASH_BITS)


ZLIB_GO_HASH = DeflateHash(zlib_go_hash_func, min_match=4, hash_bits=GO_HASH_BITS)
ZLIB_GO_QUICK_HASH = DeflateHash(
    zlib_go_quick_hash_func, min_match=4, hash_bits=GO_QUICK_HASH_BITS
)

GO_PARAMS = [
    DeflateParams(*params, min_match=4, hash_func=ZLIB_GO_HASH)
    for params in ZLIB_PARAMS_RAW
]
GO_PARAMS[1] = DeflateParams(
    None,
    None,
    None,
    None,
    None,
    strategy=DeflateStrategy.go_quick,
    min_match=4,
    hash_func=ZLIB_GO_QUICK_HASH,
)

# ----- hash function and DEFLATE parameters (implicitly) defined in miniz -----
# https://github.com/richgel999/miniz/blob/master/miniz_tdef.c

get_miniz_hash = get_zlib_hash
MINIZ_DEFAULT_HASH = ZLIB_DEFAULT_HASH

# good, lazy, insert, nice, chain, strategy
# here good has a slightly different meaning: after reaching good, the maximum
# number of probes becomes 6, 9, 33, 66, 129, 192, 375, resp., for levels 4-10,
# instead of 3, 7, 31, 63, 127, 192, 375 (divided by 4). Note that the actual
# number of probes performed may be smaller because it also depends on other
# factors, such as how many "pseudomatches" are found during the search.
MINIZ_PARAMS_RAW = [
    (None, None, None, None, None, DeflateStrategy.stored),
    (None, None, None, 128, 3, DeflateStrategy.miniz),
    (None, None, None, 128, 6, DeflateStrategy.miniz),
    (None, None, None, 128, 33, DeflateStrategy.miniz),
    (32, 128, None, 128, 18, DeflateStrategy.miniz),
    (32, 128, None, 128, 33, DeflateStrategy.miniz),
    (32, 128, None, 128, 129, DeflateStrategy.miniz),
    (32, 128, None, 128, 258, DeflateStrategy.miniz),
    (32, 128, None, 128, 513, DeflateStrategy.miniz),
    (32, 128, None, 128, 768, DeflateStrategy.miniz),
    (32, 128, None, 128, 1500, DeflateStrategy.miniz),
]

MINIZ_PARAMS = [
    DeflateParams(*params, min_match=3, hash_func=MINIZ_DEFAULT_HASH)
    for params in MINIZ_PARAMS_RAW
]
MINIZ_DEFAULT_PARAMS = MINIZ_PARAMS[6]
