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
from functools import cache
from typing import TYPE_CHECKING
from pathlib import Path

import qbinary
from qbinary.program import Program, ComplexTypesCapability
from qbinary.backend.quokka.function import FunctionQuokka
from qbinary.types import ProgramCapability, Structure, StructureMember, DataType, UnionMember

if TYPE_CHECKING:
    from collections.abc import Iterator, ItemsView
    from qbinary.types import Addr, Structure


@cache
def _data_type_mapping() -> dict[quokka.types.DataType, DataType]:
    return {
        quokka.types.DataType.UNKNOWN: DataType.UNKNOWN,
        quokka.types.DataType.POINTER: DataType.UNKNOWN,
        quokka.types.DataType.STRUCT: DataType.UNKNOWN,
        quokka.types.DataType.ALIGN: DataType.UNKNOWN,
        quokka.types.DataType.ASCII: DataType.UNKNOWN,
        quokka.types.DataType.BYTE: DataType.BYTE,
        quokka.types.DataType.WORD: DataType.WORD,
        quokka.types.DataType.DOUBLE_WORD: DataType.DOUBLE_WORD,
        quokka.types.DataType.QUAD_WORD: DataType.QUAD_WORD,
        quokka.types.DataType.OCTO_WORD: DataType.OCTO_WORD,
        quokka.types.DataType.FLOAT: DataType.FLOAT,
        quokka.types.DataType.DOUBLE: DataType.DOUBLE,
    }


def convert_to_qbinary(
    qk_struct: quokka.Structure,
) -> Structure | qbinary.types.Union | qbinary.types.Enum:
    """Convert a quokka structure into its corresponding qbinary object"""
    if qk_struct.type == quokka.types.StructureType.STRUCT:
        return Structure(
            name=qk_struct.name,
            size=qk_struct.size,
            members=[
                StructureMember(
                    offset=off,
                    name=member.name,
                    type=_data_type_mapping()[member.type],
                    size=member.size,
                )
                for off, member in qk_struct.items()
            ],
        )
    elif qk_struct.type == quokka.types.StructureType.UNION:
        return qbinary.types.Union(
            name=qk_struct.name,
            size=qk_struct.size,
            members=[
                UnionMember(
                    name=member.name, type=_data_type_mapping()[member.type], size=member.size
                )
                for member in qk_struct.values()
            ],
        )
    elif qk_struct.type == quokka.types.StructureType.ENUM:
        return qbinary.types.Enum(
            name=qk_struct.name,
            size=qk_struct.size,
            members=[(member.name, member.value) for member in qk_struct.values()],
        )
    else:
        raise ValueError(f"Unsupported type of quokka structure {qk_struct.type}")


class ProgramQuokka(Program, ComplexTypesCapability):
    """
    Program specialization that uses the Quokka backend.

    :param export_path: The path to the .quokka exported file
    :param exec_path: The raw binary file path
    """

    __slots__ = ("structures", "unions", "enums", "_qk_prog", "_functions")

    capabilities = (
        ProgramCapability.INSTR_GROUP
        | ProgramCapability.PCODE
        | ProgramCapability.CAPSTONE
        | ProgramCapability.COMPLEX_TYPES
    )

    def __init__(self, export_path: str | Path, exec_path: str | Path):
        super().__init__()

        # exec_path make sure its valid
        if exec_path == "":  # empty string
            self.exec_path = Path(export_path).with_suffix("")
        else:
            self.exec_path = Path(exec_path)

        # Private attributes
        self._qk_prog = quokka.Program(export_path, self.exec_path)
        self._functions: dict[Addr, FunctionQuokka] = {}  # dictionary containing the functions

        # Public attributes
        self.name = self._qk_prog.executable.exec_file.name
        self.export_path = Path(self._qk_prog.export_file)
        self.func_names = {}
        self.callgraph = networkx.DiGraph()  # type: ignore[var-annotated]
        self.structures = []
        self.unions = []
        self.enums = []
        for s in self._qk_prog.structures:
            if s.type == quokka.types.StructureType.STRUCT:
                self.structures.append(convert_to_qbinary(s))
            elif s.type == quokka.types.StructureType.UNION:
                self.unions.append(convert_to_qbinary(s))
            elif s.type == quokka.types.StructureType.ENUM:
                self.enums.append(convert_to_qbinary(s))
            else:
                raise ValueError(f"Unknown type of a quokka structure {s.type}")

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
