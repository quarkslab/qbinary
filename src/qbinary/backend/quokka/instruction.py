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

Contains the InstructionQuokka implementation"""

from __future__ import annotations
import logging
from functools import reduce
from typing import TYPE_CHECKING
from qbinary.instruction import Instruction, PcodeCapability, GroupCapability
from qbinary.backend.quokka.operand import OperandQuokka

from qbinary.utils import cached_property
from qbinary.types import InstructionGroup


if TYPE_CHECKING:
    import quokka  # type: ignore[import-untyped]
    from pypcode import PcodeOp  # type: ignore[import-untyped]


class InstructionQuokka(Instruction, PcodeCapability, GroupCapability):
    __slots__ = ("_cached_properties", "_qk_instr")

    def __init__(self, qk_instruction: quokka.instruction.Instruction):
        super().__init__()

        # Private attributes
        self._cached_properties: dict = {}
        self._qk_instr = qk_instruction

        # Public attributes
        self.comment = ""  # Not supported
        self.mnemonic = self._qk_instr.mnemonic
        if self._qk_instr.cs_inst is None:
            logging.error(
                f"Capstone could not disassemble instruction at {self._qk_instr.address:#x} {self._qk_instr}"
            )
            self.disasm = f"{self.mnemonic}"
            self.groups = InstructionGroup(0)
            self.id = 0  # TODO what to put here? Only god knows
        else:
            self.disasm = f"{self.mnemonic} {self._qk_instr.cs_inst.op_str}"
            convert_group = lambda g: InstructionGroup.from_capstone(
                self._qk_instr.cs_inst._cs.arch, g
            )  # type: ignore[union-attr]
            self.groups = reduce(
                lambda x, y: x | y,
                map(convert_group, self._qk_instr.cs_inst.groups),
                InstructionGroup(0),
            )
            self.id = self._qk_instr.cs_inst.id
        self.addr = self._qk_instr.address
        self.bytes = self._qk_instr.bytes

    @cached_property
    def operands(self) -> list[OperandQuokka]:  # type: ignore[override]
        """Returns the list of operands as Operand object."""
        return [OperandQuokka(op) for op in self._qk_instr.operands]

    @cached_property
    def pcode_ops(self) -> list[PcodeOp]:
        """
        List of pcode instructions associated with the current assembly instruction
        """
        return list(self._qk_instr.pcode_insts)
