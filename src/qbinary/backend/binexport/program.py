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

Contains the ProgramBinExport implementation"""

from __future__ import annotations
import weakref, networkx, binexport, logging, capstone
from typing import TypeAlias, TYPE_CHECKING
from functools import cached_property
from multimethod import multimethod

from qbinary.program import Program
from qbinary.backend.binexport.function import FunctionBinExport
from qbinary.types import ProgramCapability

if TYPE_CHECKING:
    from collections.abc import Iterator
    from typing import Any
    from qbinary.function import Function
    from qbinary.types import Addr


def _parse_architecture_flag(arch_mode_str: str) -> capstone.Cs | None:
    """
    Return the capstone architecture corresponding to the string passed as parameter.
    The format should be something like 'CS_ARCH_any:[CS_MODE_any, ...]

    :param arch_mode_str: the architecture mode (as in capstone)
    :returns: The capstone disassembler context or None if an error occurred
    """

    separator = ":"
    # Replace trailing spaces
    split = arch_mode_str.replace(" ", "").split(separator)
    # Check for only one separator
    if len(split) != 2:
        return None

    # Unpack arch and mode
    arch_str, mode_str = split
    arch = capstone.__dict__.get(arch_str)
    if arch == None:
        return None

    mode = 0
    # Look for one or more modes
    for m in mode_str.split(","):
        mode_attr = capstone.__dict__.get(m)
        if mode_attr == None:
            return None
        # Capstone mode is a bitwise enum
        mode |= mode_attr

    # Arch and Mode are valid capstone attributes, instantiate Cs object
    cs = capstone.Cs(arch, mode)
    if cs:
        # Enable details for operand
        cs.detail = True
    return cs


class ProgramBinExport(Program):
    """
    Program specialization that uses the BinExport backend.

    :param file: The path to the .BinExport exported file
    :param arch: The architecture details (as in capstone) of the binary
    :param exec_path: The raw binary file path
    """

    __slots__ = ("_be_prog", "architecture_name", "cs", "_functions")

    def __init__(self, file: str, *, arch: str | None = None, exec_path: str | None = None):
        super().__init__()

        # Private attributes
        self._be_prog = binexport.ProgramBinExport(file)
        self._functions: dict[Addr, FunctionBinExport] = {}  # dictionary containing the functions

        # Public attributes
        self.name = self._be_prog.name
        if exec_path:
            self.exec_path = exec_path
        else:  # Try to guess it as best effort by removing the final .BinExport suffix
            self.exec_path = self.name.replace(".BinExport", "")
        self.export_path = str(self._be_prog.path)
        self.func_names = {}
        self.callgraph = self._be_prog.callgraph
        self.capabilities = ProgramCapability.INSTR_GROUP
        self.cs = None  #: Capstone disassembler context
        self.architecture_name = self._be_prog.architecture  #: BinExport architecture name

        # Check if the architecture is set by the user
        if arch:
            # Parse the architecture
            self.cs = _parse_architecture_flag(arch)
            if not self.cs:
                raise Exception(f"Unable to instantiate capstone context from given arch: {arch}")
        else:
            logging.info(
                "No architecture set but BinExport backend is used. If invalid instructions"
                " are found consider setting manually the architecture"
            )
            # self.cs will be set at basic block level
            # self.cs = _get_capstone_disassembler(self.be_prog.architecture)

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
    def __getitem__(self, key: int) -> FunctionBinExport:
        return self._functions.__getitem__(key)

    def items(self) -> Iterator[tuple[Addr, FunctionBinExport]]:
        """
        Iterate over the items. Each item is {address: :py:class:`FunctionBinExport`}

        :returns: A :py:class:`Iterator` over the functions. Each element
                  is a tuple (function_addr, function_obj)
        """

        return self._functions.items()

    def _load_functions(self) -> None:
        for addr, func in self._be_prog.items():
            f = FunctionBinExport(weakref.ref(self), func)
            self._functions[f.addr] = f
            self.func_names[f.name] = f.addr

    # @property
    # def structures(self) -> list[Structure]:
    #     """
    #     Returns the list of structures defined in program.
    #     WARNING: Not supported by BinExport
    #     """

    #     return []  # Not supported
