# type: ignore
"""
The MIT License (MIT)

Copyright (c) 2016 Dimitris Karakostas <dimit.karakostas@gmail.com>, Dionysis Zindros <dionyziz@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""

# This python file contains code from Rupture, a framework for compression
# side-channel attacks (https://github.com/decrypto-org/rupture). We adapted
# the backend code of Rupture to abstract out the compression side-channel
# attack strategies, so as to enable a simpler and more consistent comparison
# with our techniques. Basically we removed all depdencies on Django and
# networking details, bumped the code to Python 3, and added an interface to
# our evaluation script.

import operator
import collections
import logging
import string

from random import Random

logger = logging.getLogger(__name__)


class ValidationError(Exception):
    pass


# ---------- target.py ----------


class Target:
    """
    A particular static target endpoint that the attack can apply to
    e.g. gmail csrf, facebook message
    """

    SERIAL = 1
    DIVIDE_CONQUER = 2
    BACKTRACKING = 3
    METHOD_CHOICES = (
        (SERIAL, "serial"),
        (DIVIDE_CONQUER, "divide&conquer"),
        (BACKTRACKING, "backtracking"),
    )

    def __init__(
        self,
        prefix,
        alphabet,
        secretlength,
        name="",
        maxreflectionlength=0,
        alignmentalphabet="",
        sentinel="^",
        method=SERIAL,
        block_align=False,
        huffman_pool=True,
        samplesize=64,
        confidence_threshold=1.0,
        compression_function_factor=1.05,
        amplification_factor=1.05,
    ):
        self.prefix = prefix
        self.alphabet = alphabet
        self.secretlength = secretlength
        self.name = name
        self.maxreflectionlength = maxreflectionlength
        self.alignmentalphabet = alignmentalphabet
        self.sentinel = sentinel
        self.method = method
        self.block_align = block_align
        self.huffman_pool = huffman_pool
        self.samplesize = samplesize
        self.confidence_threshold = confidence_threshold
        self.compression_function_factor = compression_function_factor
        self.amplification_factor = amplification_factor


# ---------- round.py ----------


class Round:
    def __init__(
        self,
        victim,
        index=1,
        batch=0,
        maxroundcardinality=1,
        minroundcardinality=1,
        amount=1,
        knownsecret="",
        knownalphabet="",
        accumulated_probability=1.0,
        method=Target.SERIAL,
        block_align=False,
        huffman_pool=True,
        completed=False,
    ):
        self.victim = victim
        self.index = index
        self.batch = batch
        self.maxroundcardinality = maxroundcardinality
        self.minroundcardinality = minroundcardinality
        self.amount = amount
        self.knownsecret = knownsecret
        self.knownalphabet = knownalphabet
        self.accumulated_probability = accumulated_probability
        self.method = method
        self.block_align = block_align
        self.huffman_pool = huffman_pool
        self.completed = completed

    def clean(self):
        if not self.knownsecret.startswith(self.victim.target.prefix):
            raise ValidationError("Knownsecret must start with known target prefix")

        if not set(self.knownalphabet) <= set(self.victim.target.alphabet):
            raise ValidationError("Knownalphabet must be a subset of target's alphabet")

    def get_method(self):
        return self.method


# ---------- sampleset.py ----------


class SampleSet:
    """
    A set of samples collected for a particular victim pertaining to an
    alphabet vector used to extend a known secret.
    """

    def __init__(
        self, round, candidatealphabet, batch=0, alignmentalphabet="", datalength=0
    ):
        self.round = round
        self.candidatealphabet = candidatealphabet
        self.alignmentalphabet = alignmentalphabet
        self.batch = batch
        self.datalength = datalength
        self.clean()

    def clean(self):
        if self.round.maxroundcardinality < len(self.candidatealphabet):
            raise ValidationError(
                "Sampleset alphabet should be at most maxroundcardinality sized."
            )
        if self.round.minroundcardinality > len(self.candidatealphabet):
            raise ValidationError(
                "Sampleset alphabet should be at least minroundcardinality sized."
            )
        if set(self.candidatealphabet) > set(self.round.knownalphabet):
            raise ValidationError(
                "Candidate alphabet must be a subset of round's known alphabet"
            )
        if set(self.alignmentalphabet) != set(
            self.round.victim.target.alignmentalphabet
        ):
            raise ValidationError(
                "Alignment alphabet must be a permutation of target's alignmentalphabet"
            )


# ---------- victim.py ----------


class Victim:
    """
    A particular instance of a target for a particular user-victim
    e.g. dionyziz@gmail.com
    """

    def __init__(self, target):
        self.target = target


# ---------- analyzer.py ----------


def decide_optimal_candidate(candidate_lengths, samples_per_sampleset):
    """Take a dictionary of candidate alphabets and their associated
    accumulative lengths and decide which candidate alphabet is the best
    (minimum) with what confidence.

    Returns a pair with the decision. The first element of the pair is which
    candidate alphabet is best; the second element is the confidence level for
    the decision.
    """

    assert len(candidate_lengths) > 1

    samplesets_per_candidate = len(next(iter(candidate_lengths.items()))[1])
    accumulated_candidate_lengths = []

    for candidate_alphabet, list_of_lengths in candidate_lengths.items():
        accumulated_candidate_lengths.append(
            {"candidate_alphabet": candidate_alphabet, "length": sum(list_of_lengths)}
        )

    # Sort sampleset groups by length.
    sorted_candidate_lengths = sorted(
        accumulated_candidate_lengths, key=operator.itemgetter("length")
    )

    logger.info(75 * "#")
    logger.info("Candidate scoreboard:")
    for cand in sorted_candidate_lengths:
        logger.info("\t{}: {}".format(cand["candidate_alphabet"], cand["length"]))
    logger.info(75 * "#")

    # Extract candidate with minimum length and the next best competitor
    # candidate. In case of binary search, these will be the only two
    # candidates.
    min_candidate = sorted_candidate_lengths[0]
    next_best_candidate = sorted_candidate_lengths[1]

    samples_per_candidate = samplesets_per_candidate * samples_per_sampleset

    # Extract a confidence value, in bytes, for our decision based on the second-best candidate.
    confidence = (
        float(next_best_candidate["length"] - min_candidate["length"])
        / samples_per_candidate
    )

    return min_candidate["candidate_alphabet"], confidence


def decide_next_world_state(samplesets):
    """Take a list of samplesets and extract a decision for a state transition
    with some confidence.

    Argument:
    samplesets -- a list of samplesets.

    This list must must contain at least two elements so that we have some basis
    for comparison. Each of the list's elements must share the same world state
    (knownsecret and knownalphabet) so that we are comparing on the same basis.
    The samplesets must contain at least two different candidate alphabets so
    that a decision can be made. It can contain multiple samplesets collected
    over the same candidate alphabet.

    Returns a pair with the decision. The first element of the pair is the new
    state of the world; the second element of the pair is the confidence with
    which the analyzer is suggesting the state transition.
    """
    # Ensure we have enough sample sets to compare.
    assert len(samplesets) > 1

    # Ensure all samplesets are extending the same known state
    knownsecret = samplesets[0].round.knownsecret
    round = samplesets[0].round
    amount = round.amount
    victim = round.victim
    target = victim.target
    for sampleset in samplesets:
        assert sampleset.round == round

    # Split samplesets based on alphabetvector under consideration
    # and collect data lengths for each candidate.
    candidate_lengths = collections.defaultdict(lambda: [])
    candidate_count_samplesets = collections.defaultdict(lambda: 0)
    for sampleset in samplesets:
        candidate_lengths[sampleset.candidatealphabet].append(sampleset.datalength)
        candidate_count_samplesets[sampleset.candidatealphabet] += 1

    candidate_count_samplesets = list(candidate_count_samplesets.items())

    samplesets_per_candidate = candidate_count_samplesets[0][1]

    for alphabet, count in candidate_count_samplesets:
        assert count == samplesets_per_candidate

    # Ensure we have a decision to make
    assert len(candidate_lengths) > 1

    min_vector, confidence = decide_optimal_candidate(
        candidate_lengths, samples_per_sampleset=amount
    )

    # use minimum group's alphabet vector
    decision_knownalphabet = min_vector
    # known secret remains the same as in all current samplesets
    decision_knownsecret = knownsecret

    if len(decision_knownalphabet) == 1:
        # decision vector was one character, so we can extend the known secret
        decision_knownsecret += decision_knownalphabet
        decision_knownalphabet = target.alphabet

    state = {
        "knownsecret": decision_knownsecret,
        "knownalphabet": decision_knownalphabet,
    }

    return {"state": state, "confidence": confidence}


# ---------- backtracking_analyzer.py ----------


def get_accumulated_probabilities(
    sorted_candidate_lengths,
    current_round_acc_probability,
    compression_function_factor,
    amplification_factor,
):
    """Take a dictionary of sorted candidate alphabets  and calculate the
    relative probability of each candidate being in the target secret based on
    their associated accumulative lengths. Then associate the relative values
    with the probability of the parent Round and calculate the final accumulated
    probability.

    Returns a dictionary containing every possible candidate alphabet and its
    accumulated probability value.
    """
    relative_probability_sum = 0.0
    min_candidate_value = sorted_candidate_lengths[0]["length"]

    # Calculate relative probability sum based on each candidate's length.
    for candidate in sorted_candidate_lengths:
        relative_probability_sum += compression_function_factor ** (
            -abs(candidate["length"] - min_candidate_value)
        )

    accumulated_probabilities = []

    # Calculate every candidate's accumulated probability by multiplying its
    # parent's probability with the relative value of this round and an
    # amplification factor.

    for candidate in sorted_candidate_lengths:
        relative_prob = (
            compression_function_factor
            ** (-abs(candidate["length"] - min_candidate_value))
            / relative_probability_sum
        )

        accumulated_value = (
            amplification_factor * current_round_acc_probability * relative_prob
        )

        accumulated_probabilities.append(
            {
                "candidate": candidate["candidate_alphabet"],
                "probability": accumulated_value,
            }
        )

    return accumulated_probabilities


def get_candidates(
    candidate_lengths,
    accumulated_prob,
    compression_function_factor,
    amplification_factor,
):
    """Take a dictionary of candidate alphabets and their associated
    accumulative lengths.

    Returns a list with each candidate and its accumulated probability.
    """
    assert len(candidate_lengths) > 1

    accumulated_candidate_lengths = []

    for candidate_alphabet, list_of_lengths in candidate_lengths.items():
        accumulated_candidate_lengths.append(
            {"candidate_alphabet": candidate_alphabet, "length": sum(list_of_lengths)}
        )

    # Sort sampleset groups by length.
    sorted_candidate_lengths = sorted(
        accumulated_candidate_lengths, key=operator.itemgetter("length")
    )

    candidates_probabilities = get_accumulated_probabilities(
        sorted_candidate_lengths,
        accumulated_prob,
        compression_function_factor,
        amplification_factor,
    )

    logger.info(75 * "#")
    logger.info("Candidate scoreboard:")
    for cand in sorted_candidate_lengths:
        logger.info("\t{}: {}".format(cand["candidate_alphabet"], cand["length"]))
    logger.info(75 * "#")

    return candidates_probabilities


def decide_next_backtracking_world_state(samplesets, accumulated_prob):
    """Take a list of samplesets and the accumulated probability of current
    round and extract a decision for a state transition with a certain
    probability for each candidate.

    Arguments:
    samplesets -- a list of samplesets.
    accumulated_prob -- the accumulated probability of current knownalpahbet.

    This list must must contain at least two elements so that we have some basis
    for comparison. Each of the list's elements must share the same world state
    (knownsecret and knownalphabet) so that we are comparing on the same basis.
    The samplesets must contain at least two different candidate alphabets so
    that a decision can be made. It can contain multiple samplesets collected
    over the same candidate alphabet.

    Returns an array of dictionary pairs. The first element of the pair is the new
    state of every candidate; the second element of the pair is the
    confidence with which the analyzer is suggesting the state transition.
    """
    # Ensure we have enough sample sets to compare.
    assert len(samplesets) > 1

    # Ensure all samplesets are extending the same known state
    knownsecret = samplesets[0].round.knownsecret
    round = samplesets[0].round
    victim = round.victim
    target = victim.target
    for sampleset in samplesets:
        assert sampleset.round == round

    # Split samplesets based on alphabetvector under consideration
    # and collect data lengths for each candidate.
    candidate_lengths = collections.defaultdict(lambda: [])
    candidate_count_samplesets = collections.defaultdict(lambda: 0)
    for sampleset in samplesets:
        candidate_lengths[sampleset.candidatealphabet].append(sampleset.datalength)
        candidate_count_samplesets[sampleset.candidatealphabet] += 1

    candidate_count_samplesets = list(candidate_count_samplesets.items())

    samplesets_per_candidate = candidate_count_samplesets[0][1]

    for alphabet, count in candidate_count_samplesets:
        assert count == samplesets_per_candidate

    # Ensure we have a decision to make
    assert len(candidate_lengths) > 1

    compression_function_factor = samplesets[
        0
    ].round.victim.target.compression_function_factor
    amplification_factor = samplesets[0].round.victim.target.amplification_factor

    candidates = get_candidates(
        candidate_lengths,
        accumulated_prob,
        compression_function_factor,
        amplification_factor,
    )

    state = []
    # All candidates are returned in order to create new rounds.
    for i in candidates:
        state.append(
            {
                "knownsecret": knownsecret + i["candidate"],
                "probability": i["probability"],
                "knownalphabet": target.alphabet,
            }
        )

    return state


# ---------- strategy.py ----------


# CALIBRATION_STEP = 0.1
# CALIBRATION_SAMPLESET_WINDOW_CHECK = 3
# for our purpose there is no need to calibrate, because calibration only takes
# place when the number of TLS records do not match, but we are working
# on a higher level of abstraction


class MaxReflectionLengthError(Exception):
    """Custom exception to handle cases when maxreflectionlength
    is not sufficient for the attack to continue."""

    pass


class RuptureSearcher:
    def __init__(self, method, samplesize, confidence_threshold=1.0, huffman_pool=True):
        self._method = method
        self._samplesize = samplesize
        self._confidence_threshold = confidence_threshold
        self._huffman_pool = huffman_pool

        self.max_queries = None
        self.num_queries = 0
        self.max_query_len = 0

    def set_oracle(self, oracle):
        self._oracle = oracle

    def set_max_queries(self, max_queries):
        self.max_queries = max_queries

    def flush(self):
        # solely here to comply with the evaluation framework
        pass

    def should_stop(self) -> bool:
        return self.max_queries is not None and self.num_queries >= self.max_queries

    def reset_stats(self):
        self.num_queries = 0
        self.max_query_len = 0

    def recover(
        self,
        prefix: bytes,
        alphabet: bytes,
        length: int,
        rng: Random | None,
    ) -> bytes | None:
        """Interface to the CRIME automata evaluation framework.

        We do not use `block_align` because the attacker always gets the exact
        compressed length.
        """
        self.rng = rng

        target = Target(
            prefix=prefix.decode(),
            alphabet=alphabet.decode(),
            secretlength=length + len(prefix),
            method=self._method,
            samplesize=self._samplesize,
            confidence_threshold=self._confidence_threshold,
            block_align=False,
            huffman_pool=self._huffman_pool,
        )
        self._victim = Victim(target=target)
        self._rounds = []
        self._max_index = 0
        self._samplesets = collections.defaultdict(list)

        try:
            self._begin_attack()
        except MaxReflectionLengthError:
            # If the initial round or samplesets cannot be created, end the analysis
            return

        self._choose_next_round(self._victim.target.method, self._max_index)

        while not self._attack_is_completed():
            while not self.work_completed():
                if self.should_stop():
                    break
            # print(self._decision)
            self._choose_next_round(self._victim.target.method, self._max_index)
            if self.should_stop():
                break

        self._choose_next_round(self._victim.target.method, self._max_index)
        return self._round.knownsecret[len(prefix) :].encode()

    def _choose_next_round(self, method, current_round_index):
        # Choose next round to analyze, based on the execution method.
        if method == Target.BACKTRACKING:
            best_rd = None
            for rd in self._rounds:
                if rd.completed:
                    continue
                if (
                    best_rd is None
                    or rd.accumulated_probability > best_rd.accumulated_probability
                ):
                    best_rd = rd
            self._round = best_rd
        else:
            self._round = next(
                filter(lambda rd: rd.index == current_round_index, self._rounds)
            )

    def get_decrypted_secret(self):
        return self._round.knownsecret

    def _build_candidates_divide_conquer(self, state):
        candidate_alphabet_cardinality = len(state["knownalphabet"]) // 2

        bottom_half = state["knownalphabet"][:candidate_alphabet_cardinality]
        top_half = state["knownalphabet"][candidate_alphabet_cardinality:]

        return [bottom_half, top_half]

    def _build_candidates_serial(self, state):
        return state["knownalphabet"]

    def _build_candidates(self, state):
        """Given a state of the world, produce a list of candidate alphabets."""
        methods = {
            Target.SERIAL: self._build_candidates_serial,
            Target.DIVIDE_CONQUER: self._build_candidates_divide_conquer,
            Target.BACKTRACKING: self._build_candidates_serial,
        }
        return methods[self._round.get_method()](state)

    def _get_first_round_state(self):
        return {
            "knownsecret": self._victim.target.prefix,
            "candidatealphabet": self._victim.target.alphabet,
            "knownalphabet": self._victim.target.alphabet,
            "probability": 1.0,
        }

    def _reflection(self, alphabet):
        # We use sentinel as a separator symbol and we assume it is not part of the
        # secret. We also assume it will not be in the content.

        # Added symbols are the total amount of dummy symbols that need to be added,
        # either in candidate alphabet or huffman complement set in order
        # to avoid huffman tree imbalance between samplesets of the same batch.

        added_symbols = (
            self._round.maxroundcardinality - self._round.minroundcardinality
        )

        sentinel = self._victim.target.sentinel

        assert sentinel not in self._round.knownalphabet
        knownalphabet_complement = list(
            set(string.ascii_letters + string.digits) - set(self._round.knownalphabet)
        )

        candidate_secrets = set()
        for letter in alphabet:
            candidate_secret = self._round.knownsecret + letter
            candidate_secrets.add(candidate_secret)

        # Candidate balance indicates the amount of dummy symbols that will be included with the
        # candidate alphabet's part of the reflection.
        candidate_balance = self._round.maxroundcardinality - len(candidate_secrets)
        if len(knownalphabet_complement) <= candidate_balance:
            knownalphabet_complement += [c for c in string.punctuation if c != sentinel]
        assert len(knownalphabet_complement) > candidate_balance
        candidate_balance = [
            self._round.knownsecret + c
            for c in knownalphabet_complement[0:candidate_balance]
        ]

        reflected_data = [
            "",
            sentinel.join(list(candidate_secrets) + candidate_balance),
            "",
        ]

        if self._round.huffman_pool:
            # Huffman complement indicates the knownalphabet symbols that are not currently being tested
            huffman_complement = set(self._round.knownalphabet) - set(alphabet)

            huffman_balance = added_symbols - len(candidate_balance)

            assert (
                len(knownalphabet_complement) > len(candidate_balance) + huffman_balance
            )

            huffman_balance = knownalphabet_complement[
                len(candidate_balance) : huffman_balance
            ]
            reflected_data.insert(
                1, sentinel.join(list(huffman_complement) + huffman_balance)
            )

        reflection = sentinel.join(reflected_data)

        return reflection

    def query_sampleset(self, sampleset):
        query = self._reflection(sampleset.candidatealphabet).encode()
        self.max_query_len = max(len(query), self.max_query_len)
        datalength = 0
        for _ in range(self._victim.target.samplesize):
            if self.should_stop():
                return
            datalength += self._oracle(query)
            self.num_queries += 1
        sampleset.datalength = datalength

    def query_samplesets(self):
        for sampleset in self._samplesets[self._round.index]:
            if sampleset.batch != self._round.batch:
                continue
            self.query_sampleset(sampleset)
            if self.should_stop():
                return

    def _analyze_current_round(self):
        """Analyzes the current round samplesets to extract a decision."""

        current_round_samplesets = self._samplesets[self._round.index]

        if self._round.get_method() == Target.BACKTRACKING:
            self._decision = decide_next_backtracking_world_state(
                current_round_samplesets, self._round.accumulated_probability
            )
        else:
            self._decision = decide_next_world_state(current_round_samplesets)

    def _round_is_completed(self):
        """Checks if current round is completed."""

        # Do we need to collect more samplesets to build up confidence?
        if self._round.get_method() != Target.BACKTRACKING:
            return (
                self._decision["confidence"] >= self._victim.target.confidence_threshold
            )
        else:
            # If backtracking is enabled we don't have to build extra confidence.
            return True

    def _create_next_round(self):
        assert self._round_is_completed()

        self._create_round(self._decision["state"])

    def _create_new_rounds(self):
        assert self._round_is_completed()

        # Create round for every optimal candidate.
        for candidate in self._decision:
            self._create_round(candidate)
            self._create_round_samplesets()

    def _set_round_cardinalities(self, candidate_alphabets):
        self._round.maxroundcardinality = max(map(len, candidate_alphabets))
        self._round.minroundcardinality = min(map(len, candidate_alphabets))

    def _create_round(self, state):
        """Creates a new round based on the analysis of the current round."""

        # If backtracking is enabled, we need to pass the accumulated
        # probability of the given candidate. Else we pass the default value.
        #
        # Next round index is calculated by incrementing current round index.
        # However backtracking does not always analyzes the round with maximum
        # index so each time we need to extract that value for the rounds to
        # come.
        prob = 1.0
        max_index = self._max_index + 1
        if self._victim.target.method == Target.BACKTRACKING:
            prob = state["probability"]

        # This next round could potentially be the final round.
        # A final round has the complete secret stored in knownsecret.
        next_round = Round(
            victim=self._victim,
            index=max_index,
            amount=self._victim.target.samplesize,
            knownalphabet=state["knownalphabet"],
            knownsecret=state["knownsecret"],
            accumulated_probability=prob,
            huffman_pool=self._victim.target.huffman_pool,
            block_align=self._victim.target.block_align,
            method=self._victim.target.method,
        )
        self._rounds.append(next_round)
        assert len(self._rounds) == max_index
        self._round = next_round
        self._max_index = max(self._max_index, max_index)

        try:
            next_round.clean()
        except ValidationError as err:
            logger.error(err)
            raise err

        self._set_round_cardinalities(self._build_candidates(state))

    def _create_round_samplesets(self):
        state = {
            "knownalphabet": self._round.knownalphabet,
            "knownsecret": self._round.knownsecret,
        }

        self._round.batch += 1

        candidate_alphabets = self._build_candidates(state)

        alignmentalphabet = ""
        if self._round.block_align:
            alignmentalphabet = list(self._round.victim.target.alignmentalphabet)
            self.rng.shuffle(alignmentalphabet)
            alignmentalphabet = "".join(alignmentalphabet)

        for candidate in candidate_alphabets:
            self._samplesets[self._round.index].append(
                SampleSet(
                    round=self._round,
                    candidatealphabet=candidate,
                    alignmentalphabet=alignmentalphabet,
                    batch=self._round.batch,
                )
            )

    def _attack_is_completed(self):
        return len(self._round.knownsecret) == self._victim.target.secretlength

    def _check_branch_length(self):
        # CRIME automata: fix typo?
        return len(self._round.knownsecret) == self._victim.target.secretlength

    def work_completed(self, success=True):
        """Receives and consumes work completed from the victim, analyzes
        the work, and returns True if the attack is complete (victory),
        otherwise returns False if more work is needed.

        It also creates the new work that is needed.

        Post-condition: Either the attack is completed, or there is work to
        do (there are unstarted samplesets in the database)."""

        self.query_samplesets()
        if self.should_stop():
            return

        # All batches are completed.
        self._analyze_current_round()

        # Serial and divide and conquer methods require a certain confidence to
        # complete current round, whereas backtracking only checks if final
        # secret is recovered.
        if self._victim.target.method == Target.BACKTRACKING:
            return self._complete_backtracking_round()
        else:
            return self._complete_round()

    def _complete_round(self):
        logger.info(75 * "$")
        logger.info("Decision:")
        for i in self._decision:
            logger.info("\t{}: {}".format(i, self._decision[i]))
        logger.info(75 * "$")

        if self._round_is_completed():
            # Advance to the next round.
            try:
                self._create_next_round()
            except MaxReflectionLengthError:
                # If a new round cannot be created, end the attack
                return True

            if self._attack_is_completed():
                return True

        # Not enough confidence, we need to create more samplesets to be
        # collected for this round.
        self._create_round_samplesets()

        return False

    def _complete_backtracking_round(self):
        self._round.completed = True

        if not self._check_branch_length():
            try:
                self._create_new_rounds()
                return False
            except MaxReflectionLengthError:
                # If a new round cannot be created, end the attack.
                return True

        # If current branch is completed, then we already matched the
        # secretlength.
        return True

    def _begin_attack(self):
        self._create_round(self._get_first_round_state())
        self._create_round_samplesets()
