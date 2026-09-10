from collections.abc import Callable

from ..gadgets import Gadget, GenericMatch


class MatchBuilder:
    """A match builder for our CRIME models."""

    def __init__(self):
        pass

    def __call__(self, target: bytes, i: int, j: int) -> Gadget:
        raise NotImplementedError()


class DefaultMatchBuilder(MatchBuilder):
    """The default match builder, where we render the first target as a match
    gadget, and the rest as or-match gadgets."""

    def __init__(
        self,
        match_class: type,
        or_match_class: type | None,  # good luck with type hints :)
        match_kwargs: dict | None = None,
        or_match_kwargs: dict | None = None,
    ):
        """Initialize a default match builder.

        Args:
            match_class: The type of the match gadget.
            or_match_class: The type of the or-match gadget, or `None` if it
                is not needed, in which case all targets will be built using
                the gadget indicated by `match_class`.
            match_kwargs: Keyword arguments for initializing `match_class`, or
                `None` (by default).
            or_match_kwargs: Keyword arguments for initializing
                `or_match_class`, or `None` (by default).
        """
        self.match_class = match_class
        if match_kwargs is None:
            match_kwargs = dict()
        self.match_kwargs = match_kwargs
        self.or_match_class = or_match_class
        if or_match_kwargs is None:
            or_match_kwargs = dict()
        self.or_match_kwargs = or_match_kwargs

    def __call__(self, target: bytes, i: int, j: int) -> Gadget:
        match_gadget = self.match_class(target, **self.match_kwargs)
        if (i == 0 and j == 0) or self.or_match_class is None:
            return match_gadget
        else:
            return self.or_match_class(match_gadget, **self.or_match_kwargs)


class CustomMatchBuilder:
    """A custom match builder."""

    def __init__(self, procedure: Callable[[bytes, int, int], Gadget]):
        self.procedure = procedure

    def __call__(self, target: bytes, i: int, j: int) -> Gadget:
        return self.procedure(target, i, j)


basic_match_builder = DefaultMatchBuilder(match_class=GenericMatch, or_match_class=None)
