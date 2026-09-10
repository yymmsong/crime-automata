from ..automata import DoubleDictAutomaton
from ..dictionary import Dictionary, SimpleDictionary
from .params import DeflateParams, ZLIB_DEFAULT_PARAMS
from ..filler import Filler, NullFiller
from ..gadgets import Gadget


class DeflateAutomaton(DoubleDictAutomaton):

    def __init__(
        self,
        charset: bytes,
        params: DeflateParams | None = None,
        dict_1: Dictionary | None = None,
        filler: Filler | None = None,
        dict_2: Dictionary | None = None,
        gadgets: list[Gadget] | None = None,
    ):
        """Initialize a DEFLATE automaton.

        Args:
            charset: See parent.
            params: DEFLATE parameters. If `None` is provided, then the
              automaton will use the default parameters in zlib/Gzip.
            dict_1: The first dictionary. If `None` is provided, then the
                automaton will use a `SimpleDictionary` for `dict_1`.
            filler: The filler between the two dictionaries. If `None` is
                provided, then the automaton will use a `NullFiller`.
            dict_2: The second dictionary. If `None` is provided, then the
                automaton will use a `SimpleDictionary` for `dict_2`.
            gadgets: See parent.
        """

        if params is None:
            params = ZLIB_DEFAULT_PARAMS
        self.params: DeflateParams = params

        if dict_1 is None:
            dict_1 = SimpleDictionary()

        if filler is None:
            filler = NullFiller()

        if dict_2 is None:
            dict_2 = SimpleDictionary()

        super().__init__(charset, dict_1, filler, dict_2, gadgets)

    def set_params(self, params: DeflateParams) -> "DeflateAutomaton":
        self.params = params
        return self
