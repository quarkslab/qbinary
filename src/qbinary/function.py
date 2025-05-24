# Copyright 2025 Quarkslab
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Interface over a Function

Contains the abstraction layer to a Function"""

from __future__ import annotations

from abc import abstractmethod
from collections.abc import Mapping
from typing import TYPE_CHECKING
from qbinary.abc import ABCMetaAttributes
from qbinary.types import FunctionType


if TYPE_CHECKING:
    import networkx
    from networkx.classes.reportviews import OutEdgeView
    from collections.abc import Iterator, ItemsView
    from qbinary.basic_block import BasicBlock
    from qbinary.types import Addr


class Function(Mapping, metaclass=ABCMetaAttributes):
    """
    Representation of a function of a Program.
    This is an abstract class and should not be used as is.

    This class is a non-mutable mapping between basic block's address and the basic block itself.

    It lazily loads all the basic blocks when iterating through them or even accessing
    one of them and it unloads all of them after the iteration has ended.

    To keep a reference to the basic blocks the **with** statement can be used, for example:

    .. code-block:: python
        :linenos:

        # func: Function
        with func:  # Loading all the basic blocks
            for bb_addr, bb in func.items():  # Blocks are already loaded
                pass
            # The blocks are still loaded
            for bb_addr, bb in func.items():
                pass
        # here the blocks have been unloaded

    Otherwise the _preload() and _unload() methods can be used:

    .. code-block:: python
        :linenos:

        # func: Function
        func._preload()
        # Basic blocks are loaded
        for bb_addr, bb in func.items():
            pass
        # Blocks still loaded
        for bb_addr, bb in func.items():
            pass
        func._unload()  # Unload the basic blocks
    """

    __slots__ = ("addr", "name", "flowgraph", "parents", "children", "type", "mangled_name")

    addr: Addr  # Address of the beginning of the function
    name: str  # Name of the function
    flowgraph: networkx.DiGraph  # The Control Flow Graph of the function as a networkx DiGraph
    parents: set[Addr]  # Set of parents in the call graph. Aka functions that call this function
    children: set[Addr]  # Set of functions called by this function in the call graph
    type: FunctionType  # Function type
    mangled_name: str  # Mangled name of the function

    def __repr__(self) -> str:
        return f"<{type(self).__name__}: {self.addr:#x} - {self.name}>"

    def __hash__(self):
        return hash(self.addr)

    @abstractmethod
    def __enter__(self) -> None:
        """
        Preload basic blocks and don't deallocate them until __exit__ is called
        """
        raise NotImplementedError()

    @abstractmethod
    def __exit__(self, exc_type, exc_value, traceback) -> None:
        """
        Deallocate all the basic blocks
        """
        raise NotImplementedError()

    @abstractmethod
    def __getitem__(self, key: Addr) -> BasicBlock:
        raise NotImplementedError()

    @abstractmethod
    def __iter__(self) -> Iterator[Addr]:
        """
        Iterate over basic block addresses
        """
        raise NotImplementedError()

    @abstractmethod
    def preload(self) -> None:
        """Load in memory all the basic blocks"""
        raise NotImplementedError()

    @abstractmethod
    def unload(self) -> None:
        """Unload from memory all the basic blocks"""
        raise NotImplementedError()

    @abstractmethod
    def items(self) -> ItemsView[Addr, BasicBlock]:
        """
        Returns a set-like object providing a view on the basic blocks

        :returns: A view over the basic blocks. Each element is a pair (addr, basicblock)
        """
        raise NotImplementedError()

    @property
    def edges(self) -> OutEdgeView[tuple[Addr, Addr]]:
        """
        View over the edges of the function Control Flow Graph.
        An edge is a pair (addr_a, addr_b)

        :returns: An :py:class:`OutEdgeView` over the edges.
        """

        return self.flowgraph.edges

    def is_library(self) -> bool:
        """
        Returns whether or not this function is a library function.

        A library function is embedded in the Program (aka it was statically compiled)
        but has been identified as part of a third party library.

        .. note:: It is not an imported function.

        :return: bool
        """

        return self.type == FunctionType.library

    def is_import(self) -> bool:
        """
        Returns whether this function is an imported function.
        Imported functions belongs to a shared library (.so, .dll, ...) and have no content.

        :return: bool
        """

        return self.type == FunctionType.imported

    def is_thunk(self) -> bool:
        """
        Returns whether this function is a thunk function.

        :return: bool
        """

        return self.type == FunctionType.thunk

    def is_alone(self) -> bool:
        """
        Returns whether the function have neither caller nor callee.

        :return: bool
        """

        return not (self.children or self.parents)
