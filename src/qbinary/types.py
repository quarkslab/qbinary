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
import enum
import enum_tools.documentation, logging
from typing import TYPE_CHECKING
from qbinary.utils import log_once

if TYPE_CHECKING:
    from typing import TypeAlias

Addr: TypeAlias = int
"""
An integer representing an address within a program
"""


@enum_tools.documentation.document_enum
class BackendType(enum.IntEnum):
    """
    Enum of different backends (supported or not)
    """

    binexport = 0  # doc: binexport backend
    diaphora = 1  # doc: diaphora backend (not supported)
    ida = 2  # doc: IDA backend
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

    @classmethod
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
            case _:
                # Log once the unsupported
                log_once(
                    logging.WARN,
                    f"Misalignment between capstone group {capstone_group} ({capstone_arch=}) "
                    "and InstructionGroup",
                )
                return InstructionGroup.GRP_INVALID
