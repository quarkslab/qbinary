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
import enum_tools.documentation, logging
from enum import IntEnum, IntFlag, auto
from typing import TYPE_CHECKING
from qbinary.utils import log_once

if TYPE_CHECKING:
    from typing import TypeAlias

Addr: TypeAlias = int
"""
An integer representing an address within a program
"""


@enum_tools.documentation.document_enum
class LoaderType(IntEnum):
    """
    Enum of different loaders (supported or not)
    """

    binexport = 0  # doc: binexport loader
    diaphora = 1  # doc: diaphora loader (not supported)
    ida = 2  # doc: IDA loader
    quokka = 3  # doc: Quokka loader


@enum_tools.documentation.document_enum
class FunctionType(IntEnum):
    """
    Function types
    """

    normal = 0  # doc: Normal function
    library = 1  # doc: Library function embedded in the program (statically compiled)
    imported = 2  # doc: Imported function e.g: function in PLT
    thunk = 3  # doc: Function identified as thunk (trampoline to another one)
    invalid = 4  # doc: Invalid function type (contains errors)


@enum_tools.documentation.document_enum
class ProgramCapability(IntFlag):
    """
    Defines the capabilities that are supported by a Program backed
    by a specific backend loader
    """

    PCODE = auto()
    INSTR_GROUP = auto()


@enum_tools.documentation.document_enum
class OperandType(IntEnum):
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
class InstructionGroup(IntEnum):
    """
    Abstraction for the instruction group, for now rely on capstone ones.
    """

    GRP_INVALID = 0  # doc: Uninitialized/invalid group
    GRP_JUMP = 1  # doc: Jump instructions (conditional+direct+indirect jumps)
    GRP_CALL = 2  # doc: Call instructions
    GRP_RET = 3  # doc: Return group
    GRP_INT = 4  # doc: Interrupt instructions (int+syscall)
    GRP_IRET = 5  # doc: Interrupt return instructions
    GRP_PRIVILEGE = 6  # doc: Privileged instructions
    GRP_BRANCH_RELATIVE = 7  # doc: Relative branching instructions

    @classmethod
    def fromint(cls, value: int):
        """Cast an integer to InstructionGroup type"""
        # Return an invalid group if cast is not possible
        try:
            return InstructionGroup(value)
        except ValueError:
            return InstructionGroup.GRP_INVALID

    @classmethod
    def from_capstone(cls, capstone_group: int):
        """Cast a capstone group to InstructionGroup type"""
        # Wrap capstone group using our custom type
        # Note: This only works because the mappings between the enums are the same
        try:
            return InstructionGroup(capstone_group)
        except ValueError:
            # Log once the unsupported
            log_once(
                logging.WARN,
                f"Misalignment between capstone group {capstone_group} and InstructionGroup",
            )
            return InstructionGroup.GRP_INVALID
