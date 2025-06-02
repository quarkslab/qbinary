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

"""Interface over a Program

Contains the abstraction layer to a Program"""

from __future__ import annotations
import logging
from multimethod import multimethod
from abc import abstractmethod
from collections.abc import Mapping
from typing import TYPE_CHECKING
from pathlib import Path

from qbinary.abc import ABCMetaAttributes
from qbinary.types import (
    BackendType,
    Disassembler,
    ExportFormat,
    ExportException,
    DisassExportNotImplemented,
    QbinaryException,
)
from qbinary.function import Function
from qbinary.disassembler import (
    IDADisassembler,
    BNDisassembler,
    GhidraDisassembler,
    DisassemblyEngine,
)

if TYPE_CHECKING:
    import networkx
    from networkx.classes.reportviews import OutEdgeView
    from collections.abc import Iterator, ItemsView
    from qbinary.types import Addr, ProgramCapability


class Program(Mapping, metaclass=ABCMetaAttributes):
    """
    Program class that offers a uniform interface over a binary Program.
    This is an abstract class and should not be used as is.

    It is a :py:class:`Mapping`, where keys are function addresses and
    values are :py:class:`Function` objects.
    """

    __slots__ = (
        "name",
        "exec_path",
        "export_path",
        "callgraph",
        "capabilities",
        "func_names",
        "__weakref__",
    )

    name: str  # The name of the program
    exec_path: Path | None  # The executable path if it has been specified, None otherwise
    export_path: Path | None  # The exported file path if it has been specified, None otherwise
    callgraph: networkx.DiGraph  # The program Call Graph as a Networkx DiGraph
    capabilities: ProgramCapability  # Capabilities offered by the underlying backend
    func_names: dict[str, Addr]  # Mapping between function names and addresses

    @abstractmethod
    def __iter__(self) -> Iterator[Addr]:
        """
        Iterate over all functions located in the program

        :return: Iterator over the functions' address
        """
        raise NotImplementedError()

    @multimethod
    def __getitem__(self, key: int) -> Function:
        raise NotImplementedError()

    @__getitem__.register
    def _(self, key: str) -> Function:
        return self[self.func_names[key]]

    def __repr__(self) -> str:
        return f"<{type(self).__name__}:{self.name}>"

    @abstractmethod
    def items(self) -> ItemsView[Addr, Function]:
        """
        Returns a set-like object providing a view on the functions

        :returns: A view over the functions. Each element is a
            pair (function_addr, function_obj)
        """
        raise NotImplementedError()

    @property
    def edges(self) -> OutEdgeView[tuple[Addr, Addr]]:
        """
        Iterate over the edges. An edge is a pair (addr_a, addr_b)

        :returns: An :py:class:`OutEdgeView` over the edges.
        """

        return self.callgraph.edges

    #
    ### Only static methods from here below, they are part of the Factory pattern
    #

    @staticmethod
    def open(
        export_file: Path | str = "",
        exec_file: Path | str = "",
        backend: BackendType | None = None,
        **kwargs,
    ) -> Program:
        """
        Opens a program by calling the right backend.
        :param export_file: The path to the exported file. If empty, use IDAPython backend
        :param exec_file: The path to the raw executable binary file.
        :param backend: The backend type. If not provided, the backend is inferred from the export_file
        :param kwargs: extra parameters forwarded to the backend constructor
        """
        # Try to infer it the correct backend
        if backend is None:
            if not export_file and not exec_file:
                # If no export file and no exec file, use IDAPython backend
                backend = BackendType.idapython
            else:
                if str(export_file).endswith(ExportFormat.QUOKKA.extension):
                    backend = BackendType.quokka
                elif str(export_file).endswith(ExportFormat.BINEXPORT.extension):
                    backend = BackendType.binexport
                else:
                    logging.error(
                        f"Could not infer the backend from the provided path {export_file}"
                    )

        # Match the resulting backend
        if backend == BackendType.idapython:
            from qbinary.backend.ida import ProgramIDA

            return ProgramIDA()

        elif backend == BackendType.binexport:
            from qbinary.backend.binexport import ProgramBinExport

            return ProgramBinExport(export_file, exec_path=exec_file, **kwargs)

        elif backend == BackendType.quokka:
            from qbinary.backend.quokka import ProgramQuokka

            return ProgramQuokka(export_file, exec_file)

        else:
            raise QbinaryException(f"Backend {backend} not implemented")

    @staticmethod
    def from_binexport(
        file_path: str, arch: str | None = None, exec_file: str | None = None
    ) -> Program:
        """
        Load the Program using the binexport backend

        :param file_path: File path to the binexport file
        :param arch: Architecture to pass to the capstone disassembler. This is
                     useful when the binexport'ed architecture is not enough to
                     correctly disassemble the binary (for example with arm
                     thumb2 or some mips modes).
        :param exec_file: Optional path to raw executable binary
        :return: Program instance
        """

        return Program.open(
            file_path, arch=arch, exec_file=exec_file, backend=BackendType.binexport
        )

    @staticmethod
    def from_quokka(file_path: str, exec_file: str) -> Program:
        """
        Load the Program using the Quokka backend.

        :param file_path: File path to the binexport file
        :param exec_file: Path of the raw binary
        :return: Program instance
        """

        return Program.open(file_path, exec_file=exec_file, backend=BackendType.quokka)

    @staticmethod
    def from_idapython() -> Program:
        """
        Load the program using the IDAPython backend

        :return: Program instance
        """

        return Program.open(backend=BackendType.idapython)

    @staticmethod
    def from_binary(
        file_path: str,
        export_format: ExportFormat = ExportFormat.AUTO,
        disassembler: Disassembler = Disassembler.AUTO,
        timeout: int = 0,
        override: bool = True,
    ) -> Program:
        """
        Loads the executable @file_path into a Program object.
        If override is set to false, will first try to open an
        existing exported file. Otherwise it will try to generate
        the exported file using the disassembler and the export format.
        If the export format or the disassembler is set to AUTO,
        a heuristic-based selection is used in the following order of preference.

        :param file_path: File path to the binary
        :param export_format: The binary exporter format to use for loading the program.
        :param disassembler: The disassembler to invoke.
        :param output_path: The path where the exported file should be saved.
                            If empty, the default path is used.
        :param database_path: The path to the database file for the disassembler.
                              If empty, the default path is used.
        :param timeout: The timeout in seconds for the disassembler to complete. 0 means no timeout.
        :param override: Whether to override the existing exported file if it exists.
        :return: Program instance.

        :raises DisassExportNotImplemented: If the disassembler and export format tuple is not implemented.
        :raises ExportException: If the couple disass+exporter failed at producing the
                                 excepted export file.
        """

        export_file = Program.generate(
            file_path,
            export_format=export_format,
            disassembler=disassembler,
            timeout=timeout,
            override=override,
        )

        # If reach this location no exception was raised , so we have a valid export file
        return Program.open(export_file, file_path)

    @staticmethod
    def generate(
        file_path: str,
        export_format: ExportFormat = ExportFormat.AUTO,
        disassembler: Disassembler = Disassembler.AUTO,
        timeout: int = 0,
        override: bool = True,
    ) -> Path:
        """
        Generates the exported file by invoking the third-party disassembler on the
        provides @p file_path and imports the resulting exported program.
        If the backend or the disassembler is set to AUTO, a heuristic-based selection
        is used in the following order of preference, until a succesful match is found:

        **format selection priority:**

          1. Quokka
          2. BinExport

        **Disassembler selection priority:**

          1. IDA
          2. Binary Ninja
          3. Ghidra

        When both parameters are unspecified, the function attempts combinations
        of all disassemblers with each backend in the above order until a successful
        result is obtained.

        :param file_path: File path to the binary
        :param export_format: The binary exporter format to use for loading the program.
        :param disassembler: The disassembler to invoke.
        :param timeout: The timeout in seconds for the disassembler to complete.
        :param override: Whether to override the existing exported file if it exists.
        :return: Path to the exported file. Otherwise exception is raised

        :raises DisassExportNotImplemented: If the disassembler and export format tuple is not implemented.
        :raises ExportException: If the couple disass+exporter failed at producing the
                                 excepted export file.
        """
        # select the export format
        if export_format == ExportFormat.AUTO:
            format_constraints = [ExportFormat.QUOKKA, ExportFormat.BINEXPORT]
        else:
            format_constraints = [export_format]  # use the one provided

        # select the disassembler
        if disassembler == Disassembler.AUTO:  # predefined order
            tupl_combinations = [
                (d, fmt) for fmt in format_constraints for d in fmt.supported_disassemblers
            ]
        else:
            tupl_combinations = [
                (d, fmt)
                for fmt in format_constraints
                for d in fmt.supported_disassemblers
                if d == disassembler
            ]

        # if list is empty it means that no valid tuple match given disass/exporter criteria
        if not tupl_combinations:
            raise DisassExportNotImplemented(
                f"{disassembler.name} and {export_format.name} " "combination is not supported"
            )

        for disass_ty, format in tupl_combinations:
            # Check if the disassembler is available
            disass = DisassemblyEngine.from_enum(disass_ty)  # will
            if not disass.exist():
                logging.warning(f"Disassembler {disass_ty.name} is not available, skipping")
                if len(tupl_combinations) == 1:  # if single entry directly raise exception
                    raise DisassExportNotImplemented(
                        f"{disass_ty.name} is not available, "
                        f"cannot generate export file for {file_path}"
                    )

            # Generate the export file using the disassembler
            try:
                export_path = disass.generate(file_path, format, timeout=timeout, override=override)
                if export_path is not None:
                    return export_path
                else:
                    continue  # try other ones if any
            except ExportException as e:
                logging.error(f"Failed to generate export file with {disass_ty.name}: {e}")
                raise e

        # If reach this point no valid disass/export managed to generate
        # an exported file
        raise ExportException(
            f"Failed to generate export file for {file_path} "
            f"using disassembler {disassembler.name} "
            f"and format {export_format.name}"
        )


class ComplexTypesCapability(metaclass=ABCMetaAttributes):
    """
    Defines the interface when offering the COMPLEX_TYPES capability.
    Complex types are struct, union an enums.
    This is an abstract class and should not be used as is.

    .. warning::
        Provides ProgramCapability.COMPLEX_TYPES capability (see :py:class:`ProgramCapability`)
    """

    __slots__ = ()

    structures: list[Structure]  # The list of structures defined in the program
    unions: list[qbinary.types.Union]  # The list of unions defined in the program
    enums: list[Enums]  # The list of enums defined in the program
