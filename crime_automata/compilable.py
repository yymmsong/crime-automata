from collections.abc import Callable
from random import Random
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .automata import CRIMEAutomaton


class Compilable:
    """A compilable object as a component of the CRIME automaton."""

    def __init__(self, machine: "CRIMEAutomaton | None"):
        """Initialize the compilable object.

        Args:
            machine: The CRIME automaton to which the compilable object
                belongs, or `None`.
        """
        self.machine: "CRIMEAutomaton | None" = machine
        self.actions: list[Callable[[Compilable], None] | None] = []
        self.output: bytes | None = None
        self.frozen: bool = False

    def flush(self) -> None:
        """Remove `actions` and `output` cached in the compilable object."""
        if self.frozen:
            return
        self.actions = []
        self.output = None

    def bind(self, machine: "CRIMEAutomaton | None", should_flush: bool = True) -> None:
        """Bind the compilable object to `machine`; if `should_flush` is set
        to `True`, then the `flush()` method of the object is called."""
        self.machine = machine
        if should_flush:
            self.flush()

    def freeze(self) -> None:
        """Set the attribute `frozen` of the compilable object to `True`,
        which guarantees that no public method of this object will modify
        `actions` and `output`, with the exception of `__call__`."""
        self.frozen = True

    def unfreeze(self, should_flush: bool = False) -> None:
        """Set the attribute `frozen` of the compilable object to `False`; if
        `should_flush` is `True`, then this method calls the `flush()` method
        of the object."""
        self.frozen = False
        if should_flush:
            self.flush()

    def __bytes__(self) -> bytes:
        """Return the representation of the compilable object in bytes.

        A derived class that intends to produce a fixed output and perform no
        actions can simply override this method but not `__call__`, but in
        other cases it is not necessary to override this method.
        """
        raise NotImplementedError()

    def __call__(self, rng: Random | None) -> bytes | None:
        """Compile the compilable object internally and return the output.

        The `__call__` method always recompiles the compilable object, sets
        the actions (if any) of the compilable object to the desired actions,
        and returns the output or `None` in case of a compilation failure.
        This method is not expected to modify `self.output`.

        A derived class that tries to do more than vanilla stuff generally
        needs to override this method. Unfortunately the `rng` parameter must
        be kept in the signature even for non-random compilable objects, but
        it can be set to `None` by default.

        Note that this method may raise an error if the
        compilation failure is independent of the randomness used, e.g., caused
        by unwise parameter choices that make no sense at all.

        Args:
            rng: a random number generator used for compilation, or `None`.

        Returns:
            The compiled output in bytes, or `None` if the compilation failed.
            Note that a compilable object that produces no output (why?)
            should output an empty byte string `b""` rather than `None` in case
            of a successful compilation.
        """
        return bytes(self)

    def compile(
        self, rng: Random | None, force_recompile: bool, execute_actions: bool
    ) -> bytes | None:
        """Compile the compilable object under the options provided.

        Compile the compilable object by running the internal `__call__` method
        (should be overriden in derived classes) if necessary, and return its
        result. The method also saves the actions and output of the compilation
        in cache.

        Args:
            rng: a random number generator used for compilation, or `None`.
            force_recompile: disregard the cache if set to be `True`.
            execute_actions: execute the compiled actions if set to be `True`.

        Returns:
            The compiled output, or `None` if the compilation failed. Note that
            a caller of `compile` may wish to either set execute_actions to be
            `True` or execute the actions by themselves (but not both) in order
            to ensure the correctness of the CRIME automaton.
        """

        if (not self.frozen) and (force_recompile or self.output is None):
            self.actions = []  # clear cached actions
            self.output = self(rng)
        if self.output is None:  # compilation failed
            return None

        if execute_actions and self.actions:
            for action in self.actions:
                if action:
                    action(self)
        return self.output


class CustomCompilable(Compilable):
    """A custom compilable part, with its behavior defined in `_procedure`.

    Might be useful if you want to try new stuff but can't be bothered to
    create a new class every time.
    """

    def __init__(
        self,
        procedure: Callable[[Compilable, Random | None], bytes | None],
    ):
        super().__init__(machine=None)
        self._procedure: Callable[[Compilable, Random | None], bytes | None] = procedure

    def __call__(self, rng: Random | None) -> bytes | None:
        return self._procedure(self, rng)
