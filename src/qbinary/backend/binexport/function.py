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

"""BinExport backend

Contains the FunctionBinExport implementation"""

from __future__ import annotations
import weakref
import binexport  # type: ignore[import-untyped]
from functools import cache
from typing import TYPE_CHECKING, cast
from qbinary.function import Function
from qbinary.backend.binexport.basic_block import BasicBlockBinExport
from qbinary.types import FunctionType, Addr


if TYPE_CHECKING:
    from collections.abc import Iterator, ItemsView
    from qbinary.backend.binexport.program import ProgramBinExport


class FunctionBinExport(Function):
    __slots__ = ("_be_func", "_program", "__enable_unloading", "_blocks")

    @classmethod
    @cache
    def _convert_function_type(cls, be_type: binexport.FunctionType) -> FunctionType:
        if be_type == binexport.types.FunctionType.NORMAL:
            return FunctionType.normal
        elif be_type == binexport.types.FunctionType.LIBRARY:
            return FunctionType.library
        elif be_type == binexport.types.FunctionType.IMPORTED:
            return FunctionType.imported
        elif be_type == binexport.types.FunctionType.THUNK:
            return FunctionType.thunk
        elif be_type == binexport.types.FunctionType.INVALID:
            return FunctionType.invalid
        else:
            raise NotImplementedError(f"Function type {be_type} not implemented")

    def __init__(
        self, program: weakref.ref[ProgramBinExport], be_func: binexport.function.FunctionBinExport
    ):
        super().__init__()

        # Class private attributes
        self.__enable_unloading = True

        # Private attributes
        self._be_func = be_func
        self._program = program
        # The basic blocks are lazily loaded
        self._blocks: dict[Addr, BasicBlockBinExport] | None = None

        # Public attributes
        self.addr = self._be_func.addr
        self.name = self._be_func.name
        self.mangled_name = self.name  # BinExport doesn't mangled name
        self.flowgraph = self._be_func.graph
        self.parents = {func.addr for func in self._be_func.parents}
        self.children = {func.addr for func in self._be_func.children}
        self.type = self._convert_function_type(self._be_func.type)

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

    def __getitem__(self, key: Addr) -> BasicBlockBinExport:
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

    def items(self) -> ItemsView[Addr, BasicBlockBinExport]:
        """
        Returns a set-like object providing a view on the basic blocks

        :returns: A view over the basic blocks. Each element is a pair (addr, basicblock)
        """

        if self._blocks is not None:
            return self._blocks.items()
        else:
            self.preload()
            # Store the basic blocks in a temporary variable
            blocks = cast(dict[Addr, BasicBlockBinExport], self._blocks)
            self.unload()
            return blocks.items()

    def preload(self) -> None:
        """Load in memory all the basic blocks"""
        self._blocks = {}
        for addr, bb in self._be_func.blocks.items():
            self._blocks[addr] = BasicBlockBinExport(self._program, bb)

    def unload(self) -> None:
        """Unload from memory all the basic blocks"""

        if self.__enable_unloading:
            self._blocks = None
