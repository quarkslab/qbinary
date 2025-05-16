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

"""Capstone backend

Contains the InstructionCapstone implementation"""

from __future__ import annotations
from functools import reduce
from typing import TYPE_CHECKING
from qbinary.instruction import Instruction, GroupCapability, CapstoneCapability
from qbinary.backend.capstone.operand import OperandCapstone

from qbinary.utils import cached_property
from qbinary.types import InstructionGroup


if TYPE_CHECKING:
    import capstone  # type: ignore[import-untyped]


class InstructionCapstone(Instruction, GroupCapability, CapstoneCapability):
    __slots__ = ("groups", "capstone_instr", "_cached_properties", "_cs")

    def __init__(self, cs: capstone.Cs, cs_instruction: capstone.CsInsn):
        super().__init__()

        # Private attributes
        self._cs = cs
        self._cached_properties: dict = {}

        # Public attributes
        self.capstone_instr = cs_instruction
        self.comment = ""  # Not supported
        self.mnemonic = self.capstone_instr.mnemonic
        self.disasm = f"{self.mnemonic} {self.capstone_instr.op_str}"
        self.groups = reduce(
            lambda x, y: x | y,
            map(
                lambda g: InstructionGroup.from_capstone(self._cs.arch, g),
                self.capstone_instr.groups,
            ),
            InstructionGroup(0),
        )
        self.addr = self.capstone_instr.address
        self.bytes = bytes(self.capstone_instr.bytes)
        self.extra = None

    @cached_property
    def operands(self) -> list[OperandCapstone]:  # type: ignore[override]
        """Returns the list of operands as Operand object."""
        return [OperandCapstone(self._cs, o) for o in self.capstone_instr.operands]
