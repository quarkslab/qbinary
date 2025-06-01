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

"""Contains all the type alias/definitions used by the module

This module contains all definitions of the type aliases and the generic enums
used by qbinary.
"""

from __future__ import annotations
import enum, weakref
import enum_tools.documentation, logging
from dataclasses import dataclass, field
from functools import cache
from typing import TYPE_CHECKING
from qbinary.utils import log_once

if TYPE_CHECKING:
    from typing import TypeAlias

Addr: TypeAlias = int
"""
An integer representing an address within a program
"""


class QbinaryException(Exception):
    """
    Base exception of all Qbinary's exception. Enables catching
    all possible exceptions raised by Qbinary API.
    """

    pass


class ExportException(QbinaryException):
    """
    Exception raised when an error occurs during export.
    """

    pass


class DisassExportNotImplemented(QbinaryException):
    """
    The combination disassembler and exporter provided does not exists.
    """

    pass


class Disassembler(enum.Enum):
    """
    Enum of the different disassemblers supported by qbinary
    """

    AUTO = enum.auto()
    IDA = enum.auto()
    GHIDRA = enum.auto()
    BINARY_NINJA = enum.auto()
    # TODO choose whether to add it # IDAPYTHON = enum.auto()    # from within IDAPython


class ExportFormat(enum.Enum):
    """
    Enum of the different export formats supported by qbinary.
    Enum meant to be exposed and manipulated by users.
    """

    AUTO = enum.auto()
    BINEXPORT = enum.auto()
    QUOKKA = enum.auto()

    @property
    def extension(self) -> str:
        """
        Get the file extension for the export format
        """
        match self:
            case ExportFormat.BINEXPORT:
                return ".BinExport"
            case ExportFormat.QUOKKA:
                return ".quokka"
            case _:
                raise ".noext"

    @property
    def supported_disassemblers(self) -> list[Disassembler]:
        """
        Get the list of disassemblers that support this export format.
        """
        match self:
            case ExportFormat.BINEXPORT:
                # FIXME: Re-enable binary ninja and ghidra when supported
                return [Disassembler.IDA]  # , Disassembler.BINARY_NINJA, Disassembler.GHIDRA]
            case ExportFormat.QUOKKA:
                return [Disassembler.IDA]
            case _:
                return []  # Irrelevant for AUTO


class DataType(enum.Enum):
    """Data Type"""

    # TODO expand with the following:
    # - composite types (union/structs)
    # - enums
    # - pointers
    # - array
    # - void
    UNKNOWN = enum.auto()
    BYTE = enum.auto()
    WORD = enum.auto()
    DOUBLE_WORD = enum.auto()
    QUAD_WORD = enum.auto()
    OCTO_WORD = enum.auto()
    FLOAT = enum.auto()
    DOUBLE = enum.auto()


@dataclass(slots=True)
class Enum:
    """
    Abstract representation of a C union type member field
    """

    name: str  # Name of the enum
    size: int  # Base size in bytes for the enum
    members: list[tuple[str, int]]  # The members of the enum, as a list of pairs (name, value)


@dataclass(slots=True)
class UnionMember:
    """
    Abstract representation of a C union type member field
    """

    name: str  # Name of the union member
    type: DataType  # Type of the field
    size: int  # Size in bits of the member
    _parent_ref: weakref.ref[Union] = field(init=False, repr=False)

    @property
    def parent(self) -> Union:
        return self._parent_ref()


@dataclass(slots=True, weakref_slot=True)
class Union:
    """
    Abstract representation of a C union type
    """

    name: str  # Name of the union
    size: int  # The overall size in bytes of the whole union type
    members: list[UnionMember]  # The union members, aka the fields of the union type

    def __post_init__(self) -> None:
        for member in self.members:
            member._parent_ref = weakref.ref(self)


@dataclass(slots=True)
class StructureMember:
    """
    Abstract representation of a C struct type member field
    """

    offset: int  # The offset at which the member is placed within the parent struct
    name: str  # Name of the member
    type: DataType  # Type of the member
    size: int  # The size in bits of the member
    _parent_ref: weakref.ref[Structure] = field(init=False, repr=False)

    @property
    def parent(self) -> Structure:
        return self._parent_ref()


@dataclass(slots=True, weakref_slot=True)
class Structure:
    """
    Abstract representation of a C struct type
    """

    name: str  # Name of the struct
    size: int  # The overall size in bytes of the whole struct
    members: list[StructureMember]  # The structure members, aka the fields of the struct type
    _offset_map: dict[int, StructureMember] = field(init=False, repr=False, hash=False)

    def __post_init__(self) -> None:
        self._offset_map = {}
        for member in self.members:
            self._offset_map[member.offset] = member
            member._parent_ref = weakref.ref(self)

    def get_member_by_offset(self, offset: int) -> StructureMember | None:
        return self._offset_map.get(offset)


@enum_tools.documentation.document_enum
class BackendType(enum.IntEnum):
    """
    Enum of different backends (supported or not)
    """

    binexport = 0  # doc: binexport backend
    diaphora = 1  # doc: diaphora backend (not supported)
    idapython = 2  # doc: IDAPython backend
    quokka = 3  # doc: Quokka backend


@enum_tools.documentation.document_enum
class FunctionType(enum.IntEnum):
    """
    Function types
    """

    normal = 0  # doc: Normal function
    library = 1  # doc: Library function embedded in the program (statically compiled)
    imported = 2  # doc: Imported function e.g: function in PLT
    thunk = 3  # doc: Function identified as thunk (trampoline to another one)
    invalid = 4  # doc: Invalid function type (contains errors)


@enum_tools.documentation.document_enum
class ProgramCapability(enum.IntFlag):
    """
    Defines the capabilities that are supported by a Program backed
    by a specific backend loader
    """

    PCODE = enum.auto()
    INSTR_GROUP = enum.auto()
    COMPLEX_TYPES = enum.auto()
    CAPSTONE = enum.auto()


@enum_tools.documentation.document_enum
class OperandType(enum.IntEnum):
    """
    All the operand types as defined by IDA
    """

    unknown = 0  # doc: type is unknown
    register = 1  # doc: register (GPR)
    memory = 2  # doc: Direct memory reference
    immediate = 3  # doc: Immediate value
    float_point = 4  # doc: Floating point operand
    coprocessor = 5  # doc: Coprocessor operand

    # Below are arch specific
    arm_setend = 6  # doc: operand for SETEND instruction ('BE'/'LE')
    arm_sme = 7  # doc: operand for SME instruction (matrix operation)
    arm_memory_management = 8  # doc: Memory management operand like prefetch, SYS and barrier


@enum_tools.documentation.document_enum
class InstructionGroup(enum.IntFlag, boundary=enum.STRICT):
    """
    Categorize instructions into semantic groups, for now it relies on capstone ones.
    """

    INVALID = enum.auto()  # doc: Uninitialized/invalid group
    JUMP = enum.auto()  # doc: Jump instructions (conditional+direct+indirect jumps)
    CALL = enum.auto()  # doc: Call instructions
    RET = enum.auto()  # doc: Return group
    INT = enum.auto()  # doc: Interrupt instructions (int+syscall)
    IRET = enum.auto()  # doc: Interrupt return instructions
    PRIVILEGE = enum.auto()  # doc: Privileged instructions
    BRANCH_RELATIVE = enum.auto()  # doc: Relative branching instructions
    AES = enum.auto()  # doc: AES related instructions
    MODE64 = enum.auto()
    """
    doc: Instructions working on 64 bits operands/addresses/values
    (but they have counterparts for different bitnesses).
    For example: `pop rsp` or `pop esp`.
    """
    COMPARE_MOV = enum.auto()  # doc: Perform a move operation depending on some flags
    SSE1 = enum.auto()  # doc: Instructions part of the SSE (first version) instruction set
    SSE2 = enum.auto()  # doc: Instructions part of the SSE2 instruction set
    FPU = enum.auto()  # doc: Instructions that handle Floating Point operands/data

    @classmethod
    @cache
    def from_capstone(cls, capstone_arch: int, capstone_group: int):
        """Cast a capstone group to InstructionGroup type"""
        # Capstone architectures
        CS_ARCH_X86 = 3

        # Huge mapping from capstone groups to our custom type
        match (capstone_arch, capstone_group):
            case _, 0:
                return InstructionGroup.INVALID
            case _, 1:
                return InstructionGroup.JUMP
            case _, 2:
                return InstructionGroup.CALL
            case _, 3:
                return InstructionGroup.RET
            case _, 4:
                return InstructionGroup.INT
            case _, 5:
                return InstructionGroup.IRET
            case _, 6:
                return InstructionGroup.PRIVILEGE
            case _, 7:
                return InstructionGroup.BRANCH_RELATIVE
            case CS_ARCH_X86, 130:  # X86_GRP_AES
                return InstructionGroup.AES
            case CS_ARCH_X86, 145:  # X86_GRP_MODE64
                return InstructionGroup.MODE64
            case CS_ARCH_X86, 137:  # X86_GRP_CMOV
                return InstructionGroup.COMPARE_MOV
            case CS_ARCH_X86, 148:  # X86_GRP_SSE1
                return InstructionGroup.SSE1
            case CS_ARCH_X86, 149:  # X86_GRP_SSE2
                return InstructionGroup.SSE2
            case CS_ARCH_X86, 169:  # X86_GRP_FPU
                return InstructionGroup.FPU
            case _:
                # Log once the unsupported
                log_once(
                    logging.WARN,
                    f"Misalignment between capstone group {capstone_group} ({capstone_arch=}) "
                    "and InstructionGroup",
                )
                return InstructionGroup.INVALID
