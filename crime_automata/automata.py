from random import Random, SystemRandom

from .dictionary import Dictionary
from .filler import Filler
from .gadgets import Gadget


class CRIMEAutomaton:
    def __init__(self, charset: bytes, gadgets: list[Gadget] | None):
        """Initialize a CRIME automaton.

        Args:
            charset: The character set of the CRIME automaton, which is the
                default character set for its compilable components. Note that
                `charset` is only used for generating random characters and the
                parts specified by users can take bytes outside of `charset`.
            gadgets: The initial list of gadgets, or `None`.
        """
        self.charset: bytes = charset
        self.gadgets: list[Gadget] = []
        self.output: bytes | None = None

        if gadgets is not None:
            self.extend(*gadgets)

    def __getitem__(self, index: int) -> Gadget:
        return self.gadgets[index]

    def last_gadget(self) -> Gadget | None:
        """Return the last gadget in `gadgets`, or `None` if it's empty."""
        if len(self.gadgets) == 0:
            return None
        return self.gadgets[-1]

    def num_gadgets(self) -> int:
        """Return the number of gadgets."""
        return len(self.gadgets)

    def add(self, gadget: Gadget, should_flush: bool = True):
        """Add `gadget` to the list of gadgets.

        This method binds `gadget` to the CRIME automaton, appends `gadget` to
        the list of gadgets, and updates `prev_gadget` appropriately.

        Args:
            gadget: The gadget to be added to the CRIME automaton.
            should_flush: Whether to flush `gadget`; default `True`.

        Returns:
            The automaton itself.
        """
        gadget.bind(self, should_flush=should_flush)
        gadget.set_prev_gadget(self.last_gadget())  # update prev_gadget
        self.gadgets.append(gadget)

        self.output = None  # invalidate automaton output
        return self

    def extend(self, *gadgets: Gadget, should_flush: bool = True):
        """Extend `gadgets` to the list of gadgets.

        This method calls `add()` for each `gadget` in `gadgets` sequentially.

        Args:
            gadgets: The gadgets to be added to the CRIME automaton.
            should_flush: Whether to flush `gadgets`; default `True`.

        Returns:
            The automaton itself.
        """
        for gadget in gadgets:
            self.add(gadget, should_flush=should_flush)

        # automaton output already invalidated
        return self

    def insert(self, index: int, gadget: Gadget, should_flush: bool = True):
        """Insert `gadget` to the list of gadgets before position `index`.

        This method binds `gadget` to the CRIME automaton, inserts `gadget` to
        the list of gadgets before position `index`, and updates the
        `prev_gadget` attribute appropriately for `gadget` and (if any) its
        subsequent gadget.

        Args:
            index: The index before which the gadget is to be inserted.
            gadget: The gadget to be inserted to the CRIME automaton.
            should_flush: Whether to flush `gadget`; default `True`.

        Returns:
            The automaton itself.
        """
        # degenerate to add_gadget for insertions to the end of the list
        if not self.gadgets or index >= len(self.gadgets):
            return self.add(gadget=gadget)

        gadget.bind(self, should_flush=should_flush)
        next_gadget = self.gadgets[max(index, -len(self.gadgets))]
        self.gadgets.insert(index, gadget)

        # update prev_gadget
        gadget.set_prev_gadget(next_gadget.prev_gadget)
        next_gadget.set_prev_gadget(gadget)

        self.output = None  # invalidate automaton output
        return self

    def replace(self, index: int, new_gadget: Gadget, should_flush: bool = True):
        """Replace the gadget at position `index` with `new_gadget`.

        This method un-binds `old_gadget` at position `index` of the list of
        gadgets, binds `new_gadget` to the CRIME automaton, and replaces
        `old_gadget` with `new_gadget` in the list of gadgets, updating the
        `prev_gadget` attribute appropriately.

        Args:
            index: The index of the old gadget to be replaced.
            gadget: The replacement gadget.
            should_flush: Whether to flush the old gadget to be replaced and
              `new_gadget`; default `True`.

        Returns:
            The automaton itself.
        """
        old_gadget = self.gadgets[index]
        old_gadget.bind(machine=None, should_flush=should_flush)
        new_gadget.bind(self, should_flush=should_flush)
        self.gadgets[index] = new_gadget

        # update prev_gadget (take care when `new_gadget is old_gadget`)
        prev_gadget = old_gadget.prev_gadget
        old_gadget.set_prev_gadget(None)
        new_gadget.set_prev_gadget(prev_gadget)
        next_index = (index + 1) % len(self.gadgets)
        if next_index != 0:
            self.gadgets[next_index].set_prev_gadget(new_gadget)

        self.output = None  # invalidate automaton output
        return self

    def pop(self, index: int = -1, should_flush: bool = True) -> Gadget:
        """Pop the gadget at position `index` from the list of gadgets.

        The method unbinds the gadget at position `index` from the CRIME
        automaton, removes it from the list of gadgets, updates the
        `prev_gadget` attribute appropriately for this gadget and its
        subsequent gadget, and returns the gadget.

        Args:
            index: The index of the old gadget to be replaced; default `-1`.
            should_flush: Whether to flush the popped gadget; default `True`.

        Returns:
            The popped gadget.
        """
        if not -len(self.gadgets) <= index < len(self.gadgets):
            raise IndexError("Pop index out of range")
        next_index = (index + 1) % len(self.gadgets)
        next_gadget = self.gadgets[next_index] if next_index != 0 else None

        popped_gadget = self.gadgets.pop(index)
        popped_gadget.bind(machine=None, should_flush=should_flush)

        # update prev_gadget
        if next_gadget:
            next_gadget.set_prev_gadget(popped_gadget.prev_gadget)
        popped_gadget.set_prev_gadget(None)

        self.output = None  # invalidate automaton output
        return popped_gadget

    def flush(self) -> None:
        """Flush the CRIME automaton."""
        for gadget in self.gadgets:
            gadget.flush()
        self.output = None

    def compile(self, rng: Random | None, force_recompile: bool) -> bytes | None:
        """Compile the CRIME automaton.

        This method compiles each gadget from the list of gadgets sequentially,
        executing its associated actions simultaneously. If any of the gadget
        fails to compile, the compilation stops and the method returns `None`;
        otherwise, the method sets `self.output` to be concatenation of the
        compiled outputs of the gadgets and returns this value.

        Args:
            rng: a random number generator used for compilation, or `None`.
            force_recompile: Whether to force each gadget to recompile.

        Returns:
            The compiled output in bytes, or `None` if the compilation failed.
        """
        if force_recompile:
            self.flush()

        self.output = b""
        for gadget in self.gadgets:
            result = gadget.compile(rng, force_recompile, execute_actions=True)
            if result is None:
                # compilation failed; clean up and exit
                self.output = None
                break
            self.output += result
        return self.output

    def reset(self, should_flush=True) -> None:
        """Pop all gadgets in the CRIME automaton and clear cached output."""
        for _ in range(len(self.gadgets)):
            self.pop(-1, should_flush=should_flush)
        self.output = None

    def fast_reset(self) -> None:
        """Clear the list of gadgets and cached output."""
        self.gadgets = []
        self.output = None

    def sanity_check(self) -> bool:
        """Perform sanity check on the CRIME automaton."""
        for gadget in self.gadgets:
            if not gadget.sanity_check():
                return False
        return True


class DoubleDictAutomaton(CRIMEAutomaton):

    def __init__(
        self,
        charset: bytes,
        dict_1: Dictionary,
        filler: Filler,
        dict_2: Dictionary,
        gadgets: list[Gadget] | None = None,
    ):
        """Initialize a CRIME automaton with two dictionaries.

        The automaton has the structure `dict_1, filler, dict_2, gadgets`.

        Args:
            charset: See `CRIMEAutomaton`.
            dict_1: The first dictionary.
            filler: The filler between the two dictionaries.
            dict_2: The second dictionary.
            gadgets: See `CRIMEAutomaton`.
        """
        super().__init__(charset, gadgets)

        self.dict_1: Dictionary = dict_1
        self.filler: Filler = filler
        self.dict_2: Dictionary = dict_2
        self.bind_non_gadget_components(should_flush=True)

    def flush(self) -> None:
        self.dict_1.flush()
        self.filler.flush()
        self.dict_2.flush()
        super().flush()

    def bind_non_gadget_components(self, should_flush: bool = True) -> None:
        self.dict_1.bind(self, should_flush=should_flush)
        self.filler.bind(self, should_flush=should_flush)
        self.dict_2.bind(self, should_flush=should_flush)

    def compile(
        self,
        rng: Random | None = None,
        force_recompile: bool = False,
    ) -> bytes | None:
        self.compile_split(rng=rng, force_recompile=force_recompile)
        return self.output

    def compile_split(
        self,
        rng: Random | None = None,
        force_recompile: bool = False,
    ) -> tuple[bytes, bytes, bytes, bytes] | None:
        """Same as `compile()`, but returns each compiled part separately."""
        if rng is None:
            rng = SystemRandom()  # default to high-quality randomness

        # I don't understand python that well, so just to be completely safe,
        # I let the automaton flush itself here, not in the overriden method
        if force_recompile:
            self.flush()
        else:
            self.dict_1.flush()
            self.dict_2.flush()

        comp_gadgets = super().compile(
            rng, force_recompile=False
        )  # already flushed, no need to set force_recompile
        if comp_gadgets is None:
            return None

        # compile the other parts of the automaton
        comp_dict_1 = self.dict_1.compile(rng, force_recompile, True)
        comp_filler = self.filler.compile(rng, force_recompile, True)
        comp_dict_2 = self.dict_2.compile(rng, force_recompile, True)

        if comp_dict_1 is None or comp_filler is None or comp_dict_2 is None:
            self.output = None
            return None
        self.output = comp_dict_1 + comp_filler + comp_dict_2 + comp_gadgets
        return comp_dict_1, comp_filler, comp_dict_2, comp_gadgets
