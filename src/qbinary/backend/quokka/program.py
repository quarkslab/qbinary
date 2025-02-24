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

Contains the ProgramQuokka implementation"""

from __future__ import annotations
import networkx, logging
import quokka  # type: ignore[import-untyped]
from typing import TYPE_CHECKING

from qbinary.program import Program
from qbinary.backend.quokka.function import FunctionQuokka
from qbinary.types import ProgramCapability

if TYPE_CHECKING:
    from collections.abc import Iterator, ItemsView
    from qbinary.types import Addr


class ProgramQuokka(Program):
    """
    Program specialization that uses the Quokka backend.

    :param export_path: The path to the .quokka exported file
    :param exec_path: The raw binary file path
    """

    __slots__ = ("_qk_prog", "_functions")

    def __init__(self, export_path: str, exec_path: str):
        super().__init__()

        # Private attributes
        self._qk_prog = quokka.Program(export_path, exec_path)
        self._functions: dict[Addr, FunctionQuokka] = {}  # dictionary containing the functions

        # Public attributes
        self.name = self._qk_prog.executable.exec_file.name
        self.exec_path = exec_path
        self.export_path = str(self._qk_prog.export_file)
        self.func_names = {}
        self.callgraph = networkx.DiGraph()  # type: ignore[var-annotated]
        self.capabilities = ProgramCapability.INSTR_GROUP | ProgramCapability.PCODE

        self._load_functions()

    def __iter__(self) -> Iterator[Addr]:
        """
        Iterate over all functions located in the program.

        :return: Iterator over the functions' address
        """

        yield from self._functions.keys()

    def __len__(self) -> int:
        return len(self._functions)

    @Program.__getitem__.register
    def __getitem__(self, key: int) -> FunctionQuokka:
        return self._functions.__getitem__(key)

    def items(self) -> ItemsView[Addr, FunctionQuokka]:
        """
        Returns a set-like object providing a view on the functions

        :returns: A view over the functions. Each element is a
            pair (function_addr, function_obj)
        """

        return self._functions.items()

    def _load_functions(self) -> None:
        for addr, func in self._qk_prog.items():
            if addr in self._functions:
                logging.error(f"Address collision for {addr:#x}")

            f = FunctionQuokka(func)
            self._functions[addr] = f
            self.func_names[f.name] = addr

            # Load the callgraph
            self.callgraph.add_node(addr)
            for c_addr in f.children:
                self.callgraph.add_edge(addr, c_addr)
            for p_addr in f.parents:
                self.callgraph.add_edge(p_addr, addr)

    # @property
    # def structures(self) -> list[Structure]:
    #     """
    #     Returns the list of structures defined in program.
    #     WARNING: Not supported by BinExport
    #     """

    #     return []  # Not supported
