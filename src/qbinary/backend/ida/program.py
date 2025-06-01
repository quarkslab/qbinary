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

Contains the ProgramIDA implementation"""

from __future__ import annotations
import weakref, networkx
import idautils, ida_nalt, ida_funcs, ida_name, ida_bytes  # type: ignore[import-not-found]
from pathlib import Path
from typing import TYPE_CHECKING

from qbinary.program import Program
from qbinary.backend.ida.function import FunctionIDA
from qbinary.types import ProgramCapability

if TYPE_CHECKING:
    from collections.abc import Iterator, ItemsView
    from qbinary.types import Addr


class ImportManager:
    """
    Class responsible for identifying imported functions.
    This is needed as there is no direct IDA API to know if a function is external or not
    """

    def __init__(self):
        # { address : (name, ordinal) }
        self.imports: dict[Addr, tuple(str, int)] = {}

        for i in range(ida_nalt.get_import_module_qty()):
            ida_nalt.enum_import_names(i, lambda ea, name, ord: self.handle_import(ea, name, ord))

    def handle_import(self, ea: Addr, name: str, ord: int) -> int:
        """Handle the imported function by adding it to the collection"""

        if name == "":
            # IDA might know the name even though it is not reporting it now
            flags = ida_bytes.get_flags(ea)
            if ida_bytes.has_user_name(flags):
                name = ida_name.get_short_name(ea)

        self.imports[ea] = (name, ord)
        return 1

    def is_import(self, addr: Addr) -> bool:
        """Returns True if the address specified refers to an imported function"""

        return addr in self.imports


class ProgramIDA(Program):
    """
    Program specialization that uses the idapython API.
    """

    __slots__ = ("_functions", "import_manager")

    def __init__(self):
        super().__init__()

        # Private attributes
        self._functions: dict[Addr, FunctionIDA] = {}  # dictionary containing the functions

        # Public attributes
        self.name = ida_nalt.get_root_filename()
        self.exec_path = Path(ida_nalt.get_input_file_path())
        self.export_path = None
        self.func_names = {}
        self.callgraph = networkx.DiGraph()
        self.capabilities = ProgramCapability(0)
        self.import_manager = ImportManager()

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
    def __getitem__(self, key: int) -> FunctionIDA:
        return self._functions.__getitem__(key)

    def items(self) -> ItemsView[Addr, FunctionIDA]:
        """
        Returns a set-like object providing a view on the functions

        :returns: A view over the functions. Each element is a
            pair (function_addr, function_obj)
        """

        return self._functions.items()

    def _load_functions(self) -> None:
        for fun_addr in idautils.Functions():
            f = FunctionIDA(weakref.ref(self), fun_addr)
            self._functions[fun_addr] = f
            self.func_names[ida_funcs.get_func_name(fun_addr)] = fun_addr

            # Load the callgraph
            self.callgraph.add_node(fun_addr)
            for xref_addr in idautils.CodeRefsTo(fun_addr, 1):
                fun_parent = ida_funcs.get_func(xref_addr)
                if fun_parent:
                    self.callgraph.add_edge(fun_parent.start_ea, fun_addr)

    # @property
    # def structures(self) -> list[Structure]:
    #     """
    #     Returns the list of structures defined in program.
    #     WARNING: Not supported by BinExport
    #     """

    #     return []  # Not supported
