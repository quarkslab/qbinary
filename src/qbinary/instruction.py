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

"""Interface over a Instruction

Contains the abstraction layer to a Instruction"""

from __future__ import annotations
from abc import abstractmethod
from typing import TYPE_CHECKING
from qbinary.abc import ABCMetaAttributes

if TYPE_CHECKING:
    from pypcode import PcodeOp  # type: ignore[import-untyped]
    from qbinary.operand import Operand
    from qbinary.types import Addr, InstructionGroup


class Instruction(metaclass=ABCMetaAttributes):
    """
    Representation of an assembly Instruction.
    This is an abstract class and should not be used as is.
    """

    __slots__ = ("addr", "mnemonic", "extra", "comment", "bytes", "disasm")

    addr: Addr  # The address of the instruction
    mnemonic: str  # The instruction mnemonic as a string
    disasm: str  # The disassembly string representation
    extra: Any | None  # Backend specific extra information. Interface not uniform across backends
    comment: str  # The comment tied to the instruction
    bytes: bytes  # The bytes representation of the Instruction

    def __repr__(self) -> str:
        return f"<{type(self).__name__}: {self}>"

    def __str__(self) -> str:
        return f"{self.disasm}"

    # @cached_property
    # def references(self) -> dict[ReferenceType, list[ReferenceTarget]]:
    #     """
    #     Returns all the references towards the instruction
    #     """

    #     return self._backend.references

    # @property
    # def data_references(self) -> list[Data]:
    #     """
    #     Returns the list of data that are referenced by the instruction

    #     .. warning::
    #        The BinExport backend tends to return empty references and so are data references

    #     """
    #     if ReferenceType.DATA in self.references:
    #         return self.references[ReferenceType.DATA]  # type: ignore[return-value]
    #     else:
    #         return []

    @property
    @abstractmethod
    def operands(self) -> list[Operand]:
        """
        Returns the list of operands as Operand object.
        """
        raise NotImplementedError()


class PcodeCapability(metaclass=ABCMetaAttributes):
    """
    Defines the interface when offering the PCODE capability.
    This is an abstract class and should not be used as is.

    .. warning::
        Provides ProgramCapability.PCODE capability
    """

    __slots__ = ()

    @property
    @abstractmethod
    def pcode_ops(self) -> list[PcodeOp]:
        """
        List of pcode instructions associated with the current assembly instruction
        """
        raise NotImplementedError()


class CapstoneCapability(metaclass=ABCMetaAttributes):
    """
    Defines the interface when offering the CAPSTONE capability.
    This is an abstract class and should not be used as is.

    .. warning::
        Provides ProgramCapability.CAPSTONE capability
    """

    __slots__ = ()

    capstone_instr: capstone.CsInsn | None
    """
    The capstone instruction associated with the current instruction.
    If it is None it means that capstone was not able to decode the current instruction.

    .. warning::
        There can be a mismatch between the capstone representation and the chosen
        backend representation for the same instruction.
    """


class GroupCapability(metaclass=ABCMetaAttributes):
    """
    Defines the interface when offering the INSTR_GROUP capability.
    This is an abstract class and should not be used as is.

    .. warning::
        Provides ProgramCapability.INSTR_GROUP capability (see :py:class:`ProgramCapability`)
    """

    __slots__ = ()

    groups: InstructionGroup  # The semantic groups this instruction belongs to
