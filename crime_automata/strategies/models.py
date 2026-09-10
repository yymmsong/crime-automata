from random import Random
from typing import Sequence

from .matchbuilder import MatchBuilder
from .oracle import CompressionLengthOracle

from ..automata import CRIMEAutomaton
from ..gadgets import Gadget

from ..utils import EPS, dedup


class AutomatonModel:
    """A model for a CRIME automaton."""

    def __init__(
        self,
        machine: CRIMEAutomaton,
        gadgets: Sequence[Gadget] | None,
        placeholders: Sequence[int],
        match_builder: MatchBuilder,
        max_num_updates: int | None,
        test_oracle: CompressionLengthOracle | None,
        do_sanity_check: bool,
        do_validity_check: bool,
        max_retry: int | None,
        strict: bool,
    ):
        """Initialize a CRIME automaton model, which can be instantiated as a
        CRIME automaton by providing match targets ("updates").

        Args:
            machine: A CRIME automaton.
            gadgets: A sequence of the gadgets needed, except that the match
                gadgets can be placeholders. Alternatively, one can choose to
                use the gadgets in the CRIME automaton for this purpose by
                setting `gadgets` to `None`.
            placeholders: The positions of the match gadgets to be placed.
            match_builder: A callable that takes the match target and the index
                of the match and returns a match gadget for the target.
            max_num_updates: The maximum number of match targets that can be
                inserted into the position of a single placeholder, or `None`.
            test_oracle: A compression length oracle, only required for
                performing validity checks.
            do_sanity_check: Whether to perform sanity checks.
            do_validity_check: Whether to perform validity checks.
            max_retry: The maximum number of retries before giving up on
                recompiling, or `None`. The reason for retries is that the
                compilation may fail or the query may fail the validity check.
            strict: If `strict=False`, then the model will still return the
                last compiled query even if validation checks all failed after
                `max_query` attempts.
        """
        if do_validity_check and test_oracle is None:
            raise ValueError("test oracle not specified")

        if gadgets is None:
            gadgets = machine.gadgets[:]

        self.machine = machine
        self.gadgets = gadgets
        self.placeholders = placeholders
        self.match_builder = match_builder
        self.max_num_updates = max_num_updates
        self.test_oracle = test_oracle
        self.do_sanity_check = do_sanity_check
        self.do_validity_check = do_validity_check
        self.max_retry = max_retry
        self.strict = strict

    def set_test_oracle(self, test_oracle: CompressionLengthOracle) -> None:
        self.test_oracle = test_oracle

    def flush(self) -> None:
        self.machine.flush()

    def __call__(
        self,
        updates: bytes | list[bytes] | list[list[bytes]],
        rng: Random | None,
        recompile: bool,
    ) -> bytes | None:
        """Instantiate a CRIME automaton model.

        Args:
            updates: The match targets. Internally, the updates are viewed as
                a 2D matrix, where each row contains the match targets to be
                inserted at the position of the placeholder corresponding
                to that row. If `updates` is a list of bytes, then each entry
                is treated as a single row of the matrix. If `updates` is a
                `bytes` object,then it represents a matrix with only one entry.
            rng: The RNG used for compiling the automaton. Note that the RNG
                for the test oracle is specified separately on initialization.
            recompile: Whether to force the automaton to recompile. Note if
                validity checks are enabled, then the model will recompile
                the automaton on a retry anyway.

        Returns:
            The query obtained by compiling the instantiated automaton, or
            `None` if the compilation or checks fail.
        """
        if isinstance(updates, bytes):
            updates = [updates]

        if len(self.placeholders) != len(updates):
            print(self.placeholders, updates)
            raise ValueError("incorrect model instantiation")

        updates_mat: list[list[bytes]] = [
            [row] if isinstance(row, bytes) else row for row in updates
        ]  # use a different variable to appease type checker

        if self.max_num_updates is not None:
            for row in updates_mat:
                if len(row) > self.max_num_updates:
                    raise ValueError("too many updates")

        ph_update_map = {ph: idx for idx, ph in enumerate(self.placeholders)}

        self.machine.fast_reset()
        for i, gadget in enumerate(self.gadgets):
            if i in ph_update_map.keys():
                row_id = ph_update_map[i]
                update = updates_mat[row_id]
                for col_id, target in enumerate(update):
                    self.machine.add(self.match_builder(target, row_id, col_id))
            else:
                self.machine.add(gadget, should_flush=False)

        query = None
        try:
            if self.do_sanity_check and not self.machine.sanity_check():
                return None

            num_retries = 0
            while self.max_retry is None or num_retries < self.max_retry:
                num_retries += 1
                query = self.machine.compile(rng=rng, force_recompile=recompile)
                if query is None:
                    continue
                if not self.do_validity_check:
                    return query
                elif self.check_validity(updates_mat, query):
                    return query
                else:
                    self.machine.flush()
        except Exception:
            pass
        return None if self.strict else query

    def check_validity(self, updates: list[list[bytes]], query: bytes) -> bool:
        raise NotImplementedError()


def exceeds_threshold(diff: int | float, threshold: int | float) -> bool:
    """Check whether the difference exceeds the threshold. More specifically,
    check whether `diff >= threshold > 0` or `diff <= threshold < 0`,
    tolerating small rounding errors."""

    if threshold > 0 and diff + EPS > threshold:
        return True
    if threshold < 0 and diff - EPS < threshold:
        return True

    return False


def update_best(best: int | None, cur: int, direction: bool) -> int:
    if best is None:
        return cur
    if (best < cur) == direction:
        return best
    return cur


class CRIMEChainModel(AutomatonModel):
    """A model for a CRIME chain."""

    def __init__(
        self,
        machine: CRIMEAutomaton,
        gadgets: Sequence[Gadget],
        placeholder: int | Sequence[int],
        match_builder: MatchBuilder,
        test_oracle: CompressionLengthOracle | None = None,
        do_sanity_check: bool = True,
        do_validity_check: bool = False,
        max_retry: int | None = None,
        threshold: int | float | None = None,
        strict: bool = False,
    ):
        if isinstance(placeholder, int):
            placeholder = [placeholder]
        assert len(placeholder) == 1, len(placeholder)

        if do_validity_check and threshold is None:
            raise ValueError("threshold not specified")

        super().__init__(
            machine=machine,
            gadgets=gadgets,
            placeholders=placeholder,
            match_builder=match_builder,
            max_num_updates=1,
            test_oracle=test_oracle,
            do_sanity_check=do_sanity_check,
            do_validity_check=do_validity_check,
            max_retry=max_retry,
            strict=strict,
        )

        self.threshold = threshold

    def check_validity(self, updates: list[list[bytes]], query: bytes) -> bool:
        assert len(updates) == 1 and len(updates[0]) == 1
        assert self.test_oracle is not None
        assert self.threshold is not None
        update = updates[0][0]

        self.test_oracle.set_secret(update[:-1])  # prefix
        len_incorrect = self.test_oracle(query)

        self.test_oracle.set_secret(update)
        len_correct = self.test_oracle(query)

        return exceeds_threshold(len_incorrect - len_correct, self.threshold)


class CRIMESlideModel(AutomatonModel):
    """A model for a CRIME slide."""

    def __init__(
        self,
        machine: CRIMEAutomaton,
        gadgets: Sequence[Gadget],
        placeholder: int | Sequence[int],
        match_builder: MatchBuilder,
        max_num_updates: int | None = None,
        test_oracle: CompressionLengthOracle | None = None,
        do_sanity_check: bool = True,
        do_validity_check: bool = False,
        max_retry: int | None = None,
        threshold: int | float | None = None,
        strict: bool = False,
    ):
        """Initialize a CRIME slide model."""
        if isinstance(placeholder, int):
            placeholder = [placeholder]
        assert len(placeholder) == 1, len(placeholder)

        if do_validity_check and threshold is None:
            raise ValueError("thresholds not specified")

        super().__init__(
            machine=machine,
            gadgets=gadgets,
            placeholders=placeholder,
            match_builder=match_builder,
            test_oracle=test_oracle,
            max_num_updates=max_num_updates,
            do_sanity_check=do_sanity_check,
            do_validity_check=do_validity_check,
            max_retry=max_retry,
            strict=strict,
        )

        self.threshold = threshold

    def check_validity(self, updates: list[list[bytes]], query: bytes) -> bool:
        assert len(updates) == 1
        assert self.test_oracle is not None, "test oracle not specified"
        assert self.threshold is not None, "threshold not specified"

        direction = self.threshold > 0

        worst_len_correct: int | None = None
        best_len_incorrect: int | None = None

        prefixes: list[bytes] = dedup([update[:-1] for update in updates[0]])
        for prefix in prefixes:
            if prefix in updates[0]:
                continue
            self.test_oracle.set_secret(prefix)  # prefix
            len_incorrect = self.test_oracle(query)
            best_len_incorrect = update_best(
                best_len_incorrect, len_incorrect, direction
            )

        for update in updates[0]:
            self.test_oracle.set_secret(update)
            len_correct = self.test_oracle(query)
            worst_len_correct = update_best(
                worst_len_correct, len_correct, not direction
            )

        assert best_len_incorrect is not None and worst_len_correct is not None
        if not exceeds_threshold(
            best_len_incorrect - worst_len_correct, self.threshold
        ):
            print(best_len_incorrect, worst_len_correct)
        return exceeds_threshold(best_len_incorrect - worst_len_correct, self.threshold)


class CRIMECascadeModel(AutomatonModel):
    """A model for a CRIME cascade."""

    def __init__(
        self,
        machine: CRIMEAutomaton,
        gadgets: Sequence[Gadget],
        placeholder: Sequence[int],
        match_builder: MatchBuilder,
        max_num_updates: int | None = None,
        test_oracle: CompressionLengthOracle | None = None,
        do_sanity_check: bool = True,
        do_validity_check: bool = False,
        max_retry: int | None = None,
        thresholds: list[int | float] | None = None,
        strict: bool = False,
        collect_stats: bool = False,
    ):
        """Initialize a CRIME cascade model."""

        super().__init__(
            machine=machine,
            gadgets=gadgets,
            placeholders=placeholder,
            match_builder=match_builder,
            test_oracle=test_oracle,
            max_num_updates=max_num_updates,
            do_sanity_check=do_sanity_check,
            do_validity_check=do_validity_check,
            max_retry=max_retry,
            strict=strict,
        )

        self.thresholds = thresholds
        self.collect_stats = collect_stats
        self.stats: list[list[int]] | None = None

    def check_validity(self, updates: list[list[bytes]], query: bytes) -> bool:
        assert self.test_oracle is not None

        n = len(self.placeholders)
        if self.thresholds is None:
            assert self.collect_stats, "thresholds not specified"
            direction = True
        else:
            assert n == len(self.thresholds)
            direction = self.thresholds[0] > 0
            assert all([(thres > 0) == direction for thres in self.thresholds])

        if self.collect_stats and self.stats is None:
            self.stats = [[] for _ in range(n)]

        best_len_incorrect: int | None = None
        worst_len_incorrect: int | None = None

        prefixes: list[bytes] = dedup(
            [update[:-1] for row in updates for update in row]
        )
        for prefix in prefixes:
            if prefix in updates[0]:
                continue
            self.test_oracle.set_secret(prefix)  # prefix
            len_incorrect = self.test_oracle(query)
            best_len_incorrect = update_best(
                best_len_incorrect, len_incorrect, direction
            )
            worst_len_incorrect = update_best(
                worst_len_incorrect, len_incorrect, not direction
            )
        assert best_len_incorrect is not None and worst_len_incorrect is not None

        flag = True
        for i, row in enumerate(updates):
            best_len_correct: int | None = None
            worst_len_correct: int | None = None
            for update in row:
                self.test_oracle.set_secret(update)
                len_correct = self.test_oracle(query)
                best_len_correct = update_best(best_len_correct, len_correct, direction)
                worst_len_correct = update_best(
                    worst_len_correct, len_correct, not direction
                )
                if self.collect_stats:
                    assert self.stats is not None
                    self.stats[i].append(best_len_incorrect - len_correct)
                    self.stats[i].append(worst_len_incorrect - len_correct)

            if self.thresholds is None:
                continue
            if worst_len_correct is not None:
                flag = flag and exceeds_threshold(
                    best_len_incorrect - worst_len_correct, self.thresholds[i]
                )
            if best_len_correct is not None:
                flag = flag and (
                    i > 0
                    or not exceeds_threshold(
                        worst_len_incorrect - best_len_correct, self.thresholds[i - 1]
                    )
                )
            if not flag and not self.collect_stats:
                break
        return True
