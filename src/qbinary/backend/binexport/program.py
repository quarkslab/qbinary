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
import weakref, networkx, logging
import binexport, capstone  # type: ignore[import-untyped]
from typing import TypeAlias, TYPE_CHECKING
from functools import cached_property
from multimethod import multimethod
from pathlib import Path

from qbinary.program import Program
from qbinary.backend.binexport.function import FunctionBinExport
from qbinary.utils import cached_property
from qbinary.types import ProgramCapability

if TYPE_CHECKING:
    from collections.abc import Iterator, ItemsView
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


def _get_capstone_disassembler(binexport_arch: str, mode: int = 0):
    # Lazy import
    import capstone  # type: ignore[import-untyped]

    def capstone_context(arch, mode):
        context = capstone.Cs(arch, mode)
        context.detail = True
        return context

    if binexport_arch == "x86-32" or binexport_arch == "x86":
        return capstone_context(capstone.CS_ARCH_X86, capstone.CS_MODE_32 | mode)
    elif binexport_arch == "x86-64":
        return capstone_context(capstone.CS_ARCH_X86, capstone.CS_MODE_64 | mode)
    elif binexport_arch == "ARM-32":
        return capstone_context(capstone.CS_ARCH_ARM, mode)
    elif binexport_arch == "ARM-64":
        return capstone_context(capstone.CS_ARCH_ARM64, mode)
    elif binexport_arch == "MIPS-32":
        return capstone_context(capstone.CS_ARCH_MIPS, capstone.CS_MODE_32 | mode)
    elif binexport_arch == "MIPS-64":
        return capstone_context(capstone.CS_ARCH_MIPS, capstone.CS_MODE_64 | mode)

    raise NotImplementedError(
        f"Cannot instantiate a capstone disassembler from architecture {binexport_arch}"
    )


class ProgramBinExport(Program):
    """
    Program specialization that uses the BinExport backend.

    :param file: The path to the .BinExport exported file
    :param arch: The architecture details (as in capstone) of the binary.
        Only meaningful if capstone is used
    :param exec_path: The raw binary file path
    """

    __slots__ = ("_be_prog", "architecture_name", "_functions", "_cached_properties", "_cs_arch")

    def __init__(
        self, file: str | Path, exec_path: str | Path | None = None, *, arch: str | None = None
    ):
        super().__init__()

        # Private attributes
        self._be_prog = binexport.ProgramBinExport(file)
        self._functions: dict[Addr, FunctionBinExport] = {}  # dictionary containing the functions
        self._cached_properties: dict = {}
        self._cs_arch = arch

        # Public attributes
        self.name = self._be_prog.name
        if exec_path:
            self.exec_path = Path(exec_path)
        else:  # Try to guess it as best effort by removing the final .BinExport suffix
            self.exec_path = Path(file).with_suffix("")
        self.export_path = Path(self._be_prog.path)
        self.func_names = {}
        self.callgraph = self._be_prog.callgraph
        self.capabilities = ProgramCapability(0)
        self.architecture_name = self._be_prog.architecture  #: BinExport architecture name

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

    def items(self) -> ItemsView[Addr, FunctionBinExport]:
        """
        Returns a set-like object providing a view on the functions

        :returns: A view over the functions. Each element is a
            pair (function_addr, function_obj)
        """

        return self._functions.items()

    def _load_functions(self) -> None:
        for addr, func in self._be_prog.items():
            f = FunctionBinExport(weakref.ref(self), func)
            self._functions[f.addr] = f
            self.func_names[f.name] = f.addr

    @cached_property
    def cs(self) -> capstone.Cs:
        """
        Returns the capstone disassembler context object
        """

        if self._cs_arch:  # Check if the architecture is set by the user
            # Parse the architecture
            cs = _parse_architecture_flag(self._cs_arch)
            if not cs:
                raise Exception(
                    f"Unable to instantiate capstone context from given arch: {self._cs_arch}"
                )
            return cs
        else:  # Continue with the old method
            # No need to guess the context for these arch
            if self._be_prog.architecture not in (
                "x86",
                "x86-32",
                "x86-64",
                "MIPS-32",
                "MIPS-64",
                "ARM-64",
            ):
                raise ValueError(
                    "Cannot instantiate the capstone disassembler context by deriving the "
                    f"architecture and mode from BinExport ({self._be_prog.architecture}). "
                    "Consider setting manually the configuration by passing the 'arch' attribute "
                    "in the ProgramBinExport constructor"
                )
            return _get_capstone_disassembler(self._be_prog.architecture)
