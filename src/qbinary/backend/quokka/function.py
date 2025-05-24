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

"""Quokka backend

Contains the FunctionQuokka implementation"""

from __future__ import annotations
import quokka  # type: ignore[import-untyped]
from functools import cache
from typing import TYPE_CHECKING, cast
from qbinary.function import Function
from qbinary.backend.quokka.basic_block import BasicBlockQuokka
from qbinary.types import FunctionType, Addr


if TYPE_CHECKING:
    from collections.abc import Iterator, ItemsView


class FunctionQuokka(Function):
    __slots__ = ("_qk_func", "__enable_unloading", "_blocks")

    @classmethod
    @cache
    def _convert_function_type(cls, qk_type: quokka.types.FunctionType) -> FunctionType:
        if qk_type == quokka.types.FunctionType.NORMAL:
            return FunctionType.normal
        elif (
            qk_type == quokka.types.FunctionType.IMPORTED
            or qk_type == quokka.types.FunctionType.EXTERN
        ):
            return FunctionType.imported
        elif qk_type == quokka.types.FunctionType.LIBRARY:
            return FunctionType.library
        elif qk_type == quokka.types.FunctionType.THUNK:
            return FunctionType.thunk
        elif qk_type == quokka.types.FunctionType.INVALID:
            return FunctionType.invalid
        else:
            raise NotImplementedError(f"Function type {qk_type} not implemented")

    def __init__(self, qk_func: quokka.function.Function):
        super().__init__()

        # Class private attributes
        self.__enable_unloading = True

        # Private attributes
        self._qk_func = qk_func
        # The basic blocks are lazily loaded
        self._blocks: dict[Addr, BasicBlockQuokka] | None = None

        # Public attributes
        self.addr = self._qk_func.start
        self.name = self._qk_func.name
        self.mangled_name = self._qk_func.mangled_name
        self.flowgraph = self._qk_func.graph
        self.type = self._convert_function_type(self._qk_func.type)
        self.parents = set()
        for chunk in self._qk_func.callers:
            try:
                for func in self._qk_func.program.get_function_by_chunk(chunk):
                    self.parents.add(func.start)
            except IndexError:
                pass  # Sometimes there can be a chunk that is not part of any function
        self.children = set()
        for chunk in self._qk_func.calls:
            try:
                for func in self._qk_func.program.get_function_by_chunk(chunk):
                    self.children.add(func.start)
            except IndexError:
                pass  # Sometimes there can be a chunk that is not part of any function

    def __enter__(self) -> None:
        """
        Preload basic blocks and don't deallocate them until __exit__ is called
        """

        self.__enable_unloading = False
        self.preload()

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        """
        Deallocate all the basic blocks
        """

        self.__enable_unloading = True
        self.unload()

    def __getitem__(self, key: Addr) -> BasicBlockQuokka:
        if self._blocks is not None:
            return self._blocks[key]

        self.preload()
        bb = self._blocks[key]  # type: ignore
        self.unload()
        return bb

    def __iter__(self) -> Iterator[Addr]:
        """
        Iterate over basic block addresses
        """

        if self._blocks is not None:
            yield from self._blocks.keys()
        else:
            self.preload()
            yield from self._blocks.keys()  # type: ignore
            self.unload()

    def __len__(self) -> int:
        if self._blocks is not None:
            return len(self._blocks)

        self.preload()
        size = len(self._blocks)  # type: ignore
        self.unload()
        return size

    def items(self) -> ItemsView[Addr, BasicBlockQuokka]:
        """
        Returns a set-like object providing a view on the basic blocks

        :returns: A view over the basic blocks. Each element is a pair (addr, basicblock)
        """

        if self._blocks is not None:
            return self._blocks.items()
        else:
            self.preload()
            # Store the basic blocks in a temporary variable
            blocks = cast(dict[Addr, BasicBlockQuokka], self._blocks)
            self.unload()
            return blocks.items()

    def preload(self) -> None:
        """Load in memory all the basic blocks"""
        self._blocks = {}

        # Stop the exploration if it's an imported function
        if self.is_import():
            return

        for addr in self._qk_func.graph.nodes:
            self._blocks[addr] = BasicBlockQuokka(self._qk_func.get_block(addr))

    def unload(self) -> None:
        """Unload from memory all the basic blocks"""

        if self.__enable_unloading:
            self._blocks = None
