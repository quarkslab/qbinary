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

from qbinary.abc import ABCMetaAttributes
from qbinary.types import BackendType
from qbinary.function import Function

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
    exec_path: str | None  # The executable path if it has been specified, None otherwise
    export_path: str | None  # The exported file path if it has been specified, None otherwise
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

    @staticmethod
    def open(*args, backend: BackendType | None = None, **kwargs) -> Program:
        """
        Opens a program by calling the right backend.

        :param backend: The backend type. If not provided, the backend is inferred from the path
        :param args: extra parameters passed to the backend constructor
        :param kwargs: extra parameters forwarded to the backend constructor
        """
        # Try to infer it the correct backend
        if backend is None and len(args) > 0:
            path = args[0].casefold()  # Assume that path is the first non-keyword argument
            if path.endswith(".Quokka".casefold()):
                backend = BackendType.quokka
            elif path.endswith(".BinExport".casefold()):
                backend = BackendType.binexport
            else:
                logging.error(f"Could not infer the backend from the provided path {path}")

        # Match the resulting backend
        match backend:
            case BackendType.ida:
                from qbinary.backend.ida import ProgramIDA

                return ProgramIDA(*args, **kwargs)

            case BackendType.binexport:
                from qbinary.backend.binexport import ProgramBinExport

                return ProgramBinExport(*args, **kwargs)

            case BackendType.quokka:
                from qbinary.backend.quokka import ProgramQuokka

                return ProgramQuokka(*args, **kwargs)

            case _:
                raise NotImplementedError(f"Backend {backend} not implemented")

    @staticmethod
    def from_binexport(
        file_path: str, arch: str | None = None, exec_path: str | None = None
    ) -> Program:
        """
        Load the Program using the binexport backend

        :param file_path: File path to the binexport file
        :param arch: Architecture to pass to the capstone disassembler. This is
                     useful when the binexport'ed architecture is not enough to
                     correctly disassemble the binary (for example with arm
                     thumb2 or some mips modes).
        :param exec_path: Optional path to raw executable binary
        :return: Program instance
        """

        return Program.open(
            file_path, arch=arch, exec_path=exec_path, backend=BackendType.binexport
        )

    @staticmethod
    def from_quokka(file_path: str, exec_path: str) -> Program:
        """
        Load the Program using the Quokka backend.

        :param file_path: File path to the binexport file
        :param exec_path: Path of the raw binary
        :return: Program instance
        """

        return Program.open(file_path, exec_path=exec_path, backend=BackendType.quokka)

    @staticmethod
    def from_ida() -> Program:
        """
        Load the program using the IDA backend

        :return: Program instance
        """

        return Program.open(backend=BackendType.ida)
