from collections.abc import Callable
import itertools
from random import Random

from .hashfunc import DeflateHash
from ..randbytes import RandBytes


def is_diverse(colls: list[bytes]) -> bool:
    """Check if a list of strings `coll` is diverse; i.e., if each string
    starts with a different character."""
    if len(colls) < 2:
        return False

    first_bytes = set(s[0] for s in colls if s)
    return len(first_bytes) == len(colls)


def count_colls(seq: bytes, hash_func: DeflateHash, v: int) -> int:
    """Return the number of collisions in the byte string `seq` with regard to
    `hash_func` at the hash value `v`."""
    min_match = hash_func.min_match
    cnt = 0
    for i in range(len(seq) - min_match + 1):
        if hash_func(seq[i : i + min_match]) == v:
            cnt += 1
    return cnt


def count_coll_sums(seq: bytes, hash_func: DeflateHash, v: int) -> list[int]:
    """Compute the prefix sums for the number of collisions in the byte string
    `seq` with regard to `hash_func` at the hash value `v`."""
    min_match = hash_func.min_match
    l = len(seq)
    counts = [0] * l
    for i in range(l - min_match + 1):
        if hash_func(seq[i : i + min_match]) == v:
            counts[i] = 1

    for i in range(1, l):
        counts[i] += counts[i - 1]

    return counts


class DeflateInstanceSet:
    """An instance set used to instantiate templates for collision-based
    amplification on DEFLATE.

    Note that a `DeflateInstanceSet` object is assumed to be immutable.
    """

    def __init__(
        self,
        colls: list[list[bytes]],
        hash_func: DeflateHash | None = None,
        allow_repeats: bool = False,
    ):
        """Initialize a DEFLATE instance set.

        Args:
            colls: The list of collisions.
            hash_func: The hash function that the instance set targets.
            allow_repeats: Whether to allow repeated strings in the instance
                set. By default this is set to `False`, but in some cases one
                may wish to set `allow_repeats=True` in order to first build
                instance sets with possible repeats and remove them later.
        """
        k = len(colls)
        assert k > 0
        m = len(colls[0])
        assert m > 0
        for row in colls:
            assert len(row) == m
            for s in row:
                assert len(s) > 0

        self.colls: list[list[bytes]] = colls
        self.k: int = k
        self.m: int = m
        self.hash_func: DeflateHash | None = hash_func

        if not allow_repeats:
            assert self.has_no_repeats()
        assert self.is_colwise_diverse()

    def total_length(self) -> int:
        """Sum up the lengths of the collisions and return."""
        return sum(len(s) for row in self.colls for s in row)

    def average_length(self) -> float:
        """Return the average length of a collision."""
        return self.total_length() / (self.k * self.m)

    def has_no_repeats(self) -> bool:
        """Check if no byte string in the DEFLATE instance set appears more
        than once."""
        # return len(set([s for row in self.colls for s in row])) == self.k * self.m
        seen = set()
        for row in self.colls:
            for s in row:
                if s in seen:
                    return False
                seen.add(s)
        return True

    def is_colwise_diverse(self) -> bool:
        """Check if every element in the Cartesian product of the elements in
        `colls` when grouped by columns is diverse."""
        first_bytes_cols = [set(row[i][0] for row in self.colls) for i in range(self.m)]
        cnt = sum(len(s) for s in first_bytes_cols)
        return cnt == len(set.union(*first_bytes_cols))

    def is_consistent(self, predicate: Callable[[list[bytes]], bool]) -> bool:
        """Check if an instance set is consistent; here we slightly tweak the
        notion so that the caller must specify the disired collision val_func
        (colliding, double-colliding, ...) in the argument `predicate`."""
        return predicate([s for row in self.colls for s in row])

    def _is_row_colliding(self, predicate: Callable[[list[bytes]], bool]) -> bool:
        for row in self.colls:
            if not predicate(row):
                return False
        return True

    def _is_col_colliding(self, predicate: Callable[[list[bytes]], bool]) -> bool:
        for j in range(self.m):
            if not predicate([self.colls[i][j] for i in range(self.k)]):
                return False
        return True

    def is_non_overlapping(self, idx: int) -> tuple[bool, list[bytes]]:
        """Check if an instance set is non-overlapping; if not, also return
        the first counterexample found."""
        assert idx >= 0
        colls_flat = [s for row in self.colls for s in row]
        first_bytes = list(set(s[0] for s in colls_flat))

        for t_1, b_2 in itertools.product(colls_flat, first_bytes):
            lhs = t_1[idx:] + bytes([b_2])
            for t_3, t_4 in itertools.product(colls_flat, colls_flat):
                if t_1 == t_3 or b_2 == t_4[0]:
                    continue
                if lhs in (t_3 + t_4):
                    return False, [t_1, bytes([b_2]), t_3, t_4]

        return True, []

    def is_deflate_fast_instance(self, skip_coll_check: bool = False) -> bool:
        # check #1 is done in __init__
        assert self.hash_func is not None
        if not skip_coll_check and not self._is_col_colliding(
            self.hash_func.check_colliding
        ):  # check #2
            return False
        if not self.is_non_overlapping(idx=0):  # check #3
            return False
        return True

    def is_deflate_slow_instance(self, skip_coll_check: bool = False) -> bool:
        # check #1 is done in __init__
        assert self.hash_func is not None
        if not skip_coll_check and not self._is_col_colliding(
            self.hash_func.check_double_colliding
        ):  # check #2
            return False
        if not self.is_non_overlapping(idx=1):  # check #3
            return False
        return True

    def is_consistent_deflate_fast_instance(self) -> bool:
        assert self.hash_func is not None
        return self.is_consistent(
            self.hash_func.check_colliding
        ) and self.is_deflate_fast_instance(skip_coll_check=True)

    def is_consistent_deflate_slow_instance(self) -> bool:
        assert self.hash_func is not None
        return self.is_consistent(
            self.hash_func.check_double_colliding
        ) and self.is_deflate_slow_instance(skip_coll_check=True)

    def expand_by_random_padding(
        self,
        charset: bytes,
        target_k: int,
        cand_func: Callable[[list[list[bytes]], int, int], tuple[int, int]],
        allow_repeats: bool = False,
        max_retry: int = 10,
        itemwise_max_retry: int = 1000,
        val_func: Callable[["DeflateInstanceSet"], bool] | None = None,
        rng: Random | None = None,
    ) -> "DeflateInstanceSet | None":
        """Derive from the current DEFLATE instance set a larger instance set
        with `k=target_k` by repeatedly appending random bytes to each of the
        byte strings in the instance set, where the index of the byte string
        and the number of random bytes are provided by the candidate function
        `cand_func`, until the desired number of strings have been collected.

        Note that some combinations of `charset` and `cand_func` can never
        produce the desired new instance set, or only succeed with a negligible
        probability; in the latter case, instead of setting `max_retry` to a
        very large value, it is advised to expand the instance set by yourself,
        otherwise the function may not be able to halt in a short time.

        Args:
            charset: The byte string we (uniformly) sample random bytes from.
            target_k: The desired `k` of the new instance set.
            cand_func: A candidate function, which is a stateless function that
                takes the row-index and column-index of the new collision we
                wish to generate and outputs (a) the row-index of the byte
                string from which we generate the new collision (the col-index
                is assumed to remain the same) and (b) the number of random
                bytes to append to that string.
            allow_repeats: Whether to allow repeated strings in the expanded
                instance set; default `False`.
            max_retry: The maximum number of retries perfomed before giving up
                on finding an expanded instance set that is valid and satisfies
                `val_func` (if specified); default `10`.
            itemwise_max_retry: The maximum number of retries performed before
                giving up for generating a string in the expanded instance set
                such that it is distinct from the strings already generated if
                no repeats are allowed; default `1000`.
            val_func: A function that maps an instance set to a Boolean value,
                or (by default) `None`; in the former case, the expanded
                instance set will be required to satisfy `val_func`.
            rng: The random number generator; if (by default) `None` is given,
                then the method uses `SystemRandom()`.

        Returns:
            The expanded instance set, or `None` if the operation failed.
        """
        rbg = RandBytes(charset, rng)

        seen_ls: list[set[bytes]] = (
            [] if allow_repeats else [set() for _ in range(self.m)]
        )

        for _ in range(max_retry + 1):
            new_colls: list[list[bytes]] = []
            for i in range(target_k):
                new_row = []
                for j in range(self.m):
                    found = False
                    for _ in range(itemwise_max_retry):
                        i_old, pad_len = cand_func(self.colls, i, j)
                        cand = self.colls[i_old][j] + rbg.randbytes(pad_len)
                        if allow_repeats or cand not in seen_ls[j]:
                            new_row.append(cand)
                            found = True
                            break
                    if not found:
                        return None
                new_colls.append(new_row)
            try:
                new_inst = DeflateInstanceSet(
                    new_colls, self.hash_func, allow_repeats=allow_repeats
                )
            except:
                continue

            if val_func is None or val_func(new_inst):
                return new_inst

        return None

    def expand_by_fixed_size(
        self,
        charset: bytes,
        target_k: int,
        num_bytes: int,
        allow_repeats: bool = False,
        max_retry: int = 10,
        itemwise_max_retry: int = 1000,
        val_func: Callable[["DeflateInstanceSet"], bool] | None = None,
        rng: Random | None = None,
    ) -> "DeflateInstanceSet | None":
        """Derive from the current DEFLATE instance set a larger instance set
        with `k=target_k` by repeatedly appending `num_bytes` random bytes to
        each of the byte strings in the instance set, until the desired number
        of byte strings have been collected.

        Heuristically, if no repeats are allowed and we do not exclude repeats
        during the process, then the expanded instance set contains no repeats
        w.p. around  `(1-(target_k/k)**2/len(charset)**num_bytes)**(m*k)`.

        See the documentation of the `expand_by_random_padding` method for more
        information.
        """
        assert num_bytes >= 0
        k = self.k

        return self.expand_by_random_padding(
            charset=charset,
            target_k=target_k,
            cand_func=lambda _, i, __: (i % k, num_bytes),
            allow_repeats=allow_repeats,
            max_retry=max_retry,
            itemwise_max_retry=itemwise_max_retry,
            val_func=val_func,
            rng=rng,
        )

    def expand_to_fixed_len(
        self,
        charset: bytes,
        target_k: int,
        target_l: int,
        max_retry: int = 10,
        itemwise_max_retry: int = 1000,
        val_func: Callable[["DeflateInstanceSet"], bool] | None = None,
        rng: Random | None = None,
    ) -> "DeflateInstanceSet | None":
        """Derive from the current DEFLATE instance set a larger instance set
        with `k=target_k` by repeatedly appending random bytes to each of the
        byte strings in the instance set, such that each padded string has a
        length of `target_l`, until the desired number of byte strings have
        been collected.

        Beware of the cases where it may take a very long time or be impossible
        to expand the instance set using the parameters provided.

        See the documentation of the `expand_by_random_padding` method for more
        information.
        """
        for row in self.colls:
            for s in row:
                assert len(s) <= target_l
        k = self.k

        return self.expand_by_random_padding(
            charset=charset,
            target_k=target_k,
            cand_func=lambda colls, i, j: (i % k, target_l - len(colls[i % k][j])),
            allow_repeats=False,
            max_retry=max_retry,
            itemwise_max_retry=itemwise_max_retry,
            val_func=val_func,
            rng=rng,
        )

    def expand_to_max_match(
        self,
        charset: bytes,
        target_k: int,
        max_match: int = 258,
        min_expand: int = 1,
        max_pad_size: int | None = None,
        val_func: Callable[["DeflateInstanceSet"], bool] | None = None,
        max_retry: int = 10,
        rng: Random | None = None,
    ) -> "DeflateInstanceSet | None":
        """Derive from the current DEFLATE instance set a larger instance set
        with `k=target_k` by repeatedly appending at least `min_expand` random
        bytes to each of the byte strings in the instance set, such that the
        total length of the strings in the expanded instance set either divides
        `max_match` or is a multiple of `max_match`, and, in the latter case,
        the instance set can be split into multiple instance sets, each with a
        total length of `max_match`. The total number of random bytes added to
        derive the new instance set is guaranteed not to exceed `max_pad_size`
        bytes in total.

        Unfortunately the method is not very intellegent; if that's not ideal
        for you, you should try to expand the instance set manually yourself
        (or ask an LLM?): Trust me, it's much easier to do it by hand :)

        A brief note on how the method works: First, we expand the current
        instance set by a fixed size of `expand_size`. In the expanded instance
        set, if any row has a total length of more than `max_match`, then we're
        done for; otherwise, we heuristically combine the rows together, which
        is essentially a bin packing problem (the number of "bins" in our case
        determines to the size of the padding). Here we're being lazy and only
        implement the First-Fit-Decreasing (FFD) algorithm, which has a worst
        approximation ratio of 11/9. Hopefully, we'll be able to find a case
        where only a small amount of padding is necessary. Implementation-wise,
        this method first determines the mapping from old collisions to new
        ones as well as the sizes of the random padding, and then calls the
        `expand_by_random_padding` method to obtain the final result.

        See the documentation of the `expand_by_random_padding` method for more
        information.
        """

        # Compute the total length of each row
        orig_row_sizes = [sum(len(s) for s in row) for row in self.colls]
        # Determine the maximum possible expand size
        max_expand = (max_match - max(orig_row_sizes)) // self.m

        best_new_inst: DeflateInstanceSet | None = None
        best_pad_size: int | None = None

        # Right now we favour the smallest expand size. For (possibly) better
        # stability, one can modify the logic to favour larger expand sizes.
        for expand_size in range(min_expand, max_expand + 1):
            tot_pad_size = expand_size * self.m * target_k
            if max_pad_size is not None and max_pad_size < tot_pad_size:
                break
            if best_pad_size is not None and best_pad_size <= tot_pad_size:
                break
            row_sizes = [row_size + expand_size * self.m for row_size in orig_row_sizes]
            # Repeat the rows until we reach `target_k`; if you want you can
            # modify this to use a different way of expanding the collisions
            if self.k > target_k:
                row_sizes = row_sizes[:target_k]
            else:
                for i in range(self.k, target_k):
                    row_sizes.append(row_sizes[i % self.k])
            new_rows = [(row_sizes[i], i % self.k) for i in range(target_k)]

            # Run the First-Fit-Decreasing (FFD) algorithm; see
            # https://en.wikipedia.org/wiki/First-fit-decreasing_bin_packing
            new_rows.sort(key=lambda tup: -tup[0])
            bins: list[list[int]] = []
            bin_sizes: list[int] = []
            for row_size, row_idx in new_rows:
                found = False
                for i, bin in enumerate(bins):  # cram into the first good bin
                    if bin_sizes[i] + row_size <= max_match:
                        bin.append(row_idx)
                        bin_sizes[i] = bin_sizes[i] + row_size
                        found = True
                        break
                if not found:  # open up a new bin for the row
                    bins.append([row_idx])
                    bin_sizes.append(row_size)

            row_mapping = [-1] * target_k

            # Compute the mapping from old to new row indices
            for i, row_idx in enumerate(itertools.chain(*bins)):
                row_mapping[i] = row_idx

            # Distribute padding to the rows in each bin; we try to do it
            # evenly and assign the extra bytes from back to front (heuristics)
            num_bins = len(bins)
            pad_lens: list[list[int]] = []
            for i, bin in enumerate(bins):
                num_padding = max_match - bin_sizes[i]
                if num_bins == 1:  # only one bin, can try the divisors
                    # we're being lazy and just try all possible padding sizes
                    for target_size in range(bin_sizes[i], max_match + 1):
                        if max_match % target_size == 0:
                            num_padding = target_size - bin_sizes[i]
                            break
                tot_pad_size += num_padding
                num_rows = len(bin)
                min_pad_len = num_padding // (num_rows * self.m)
                extra_padding = num_padding % (num_rows * self.m)
                pad_lens_bin = [[min_pad_len] * self.m for _ in range(num_rows)]

                for pad_lens_row in reversed(pad_lens_bin):
                    if extra_padding <= 0:
                        break
                    for i in range(self.m):
                        pad_lens_row[i] += 1
                        extra_padding -= 1
                        if extra_padding <= 0:
                            break

                pad_lens.extend(pad_lens_bin)

            if max_pad_size is not None and max_pad_size < tot_pad_size:
                continue
            if best_pad_size is not None and best_pad_size <= tot_pad_size:
                continue

            new_inst = self.expand_by_random_padding(
                charset=charset,
                target_k=target_k,
                cand_func=lambda _, i, j: (
                    row_mapping[i],
                    pad_lens[i][j] + expand_size,
                ),
                allow_repeats=False,
                max_retry=max_retry,
                val_func=val_func,
                rng=rng,
            )

            if new_inst is None:
                continue
            # print(new_inst.colls)
            # print(new_inst.total_length(), tot_pad_size)

            if best_pad_size is None or best_pad_size > tot_pad_size:
                best_new_inst = new_inst
                best_pad_size = tot_pad_size

        return best_new_inst
