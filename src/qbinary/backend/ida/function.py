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

"""IDA backend

Contains the FunctionIDA implementation"""

from __future__ import annotations
import weakref, networkx
import ida_funcs, ida_gdl, ida_ida, ida_name  # type: ignore[import-not-found]
from typing import TYPE_CHECKING, cast
from qbinary.function import Function
from qbinary.backend.ida.basic_block import BasicBlockIDA
from qbinary.types import FunctionType, Addr


if TYPE_CHECKING:
    from collections.abc import Iterator, ItemsView
    from qbinary.backend.ida.program import ProgramIDA, ImportManager


class FunctionIDA(Function):
    __slots__ = ("_blocks", "__enable_unloading", "_ida_fun")

    def _convert_function_type(self, import_manager: ImportManager) -> FunctionType:
        if self._ida_fun.flags & ida_funcs.FUNC_THUNK:
            return FunctionType.thunk
        elif self._ida_fun.flags & ida_funcs.FUNC_LIB:
            return FunctionType.library
        elif import_manager.is_import(self.addr):
            return FunctionType.imported
        else:
            return FunctionType.normal

    def __init__(self, program: weakref.ref[ProgramIDA], addr: Addr):
        super().__init__()

        # Class private attributes
        self.__enable_unloading = True

        # Private attributes
        self._ida_fun = ida_funcs.get_func(addr)
        # The basic blocks are lazily loaded
        self._blocks: dict[Addr, BasicBlockIDA] | None = None

        # Public attributes
        self.addr = addr
        self.name = ida_name.get_demangled_name(self.addr, ida_ida.get_demnames(), 0)
        self.mangled_name = ida_funcs.get_func_name(self.addr)
        self.flowgraph = networkx.DiGraph()
        self.parents = set(program().callgraph.predecessors(self.addr))  # type: ignore[union-attr]
        self.children = set(program().callgraph.successors(self.addr))  # type: ignore[union-attr]
        self.type = self._convert_function_type(program().import_manager)  # type: ignore[union-attr]

        self._load_cfg()

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

    def __getitem__(self, key: Addr) -> BasicBlockIDA:
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

    def items(self) -> ItemsView[Addr, BasicBlockIDA]:
        """
        Returns a set-like object providing a view on the basic blocks

        :returns: A view over the basic blocks. Each element is a pair (addr, basicblock)
        """

        if self._blocks is not None:
            return self._blocks.items()
        else:
            self.preload()
            # Store the basic blocks in a temporary variable
            blocks = cast(dict[Addr, BasicBlockIDA], self._blocks)
            self.unload()
            return blocks.items()

    def _load_cfg(self) -> None:
        """Load the CFG in memory"""

        for block in ida_gdl.FlowChart(self._ida_fun, flags=ida_gdl.FC_NOEXT):
            self.flowgraph.add_node(block.start_ea)
            for parent in block.preds():
                self.flowgraph.add_edge(parent.start_ea, block.start_ea)
            for child in block.succs():
                self.flowgraph.add_edge(block.start_ea, child.start_ea)

    def preload(self) -> None:
        """Load in memory all the basic blocks"""
        self._blocks = {}
        if self.is_import():
            return

        for block in ida_gdl.FlowChart(self._ida_fun, flags=ida_gdl.FC_NOEXT):
            self._blocks[block.start_ea] = BasicBlockIDA(block.start_ea, block.end_ea)

    def unload(self) -> None:
        """Unload from memory all the basic blocks"""

        if self.__enable_unloading:
            self._blocks = None
