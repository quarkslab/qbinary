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

Contains the InstructionBinExport implementation"""

from __future__ import annotations
from typing import TYPE_CHECKING
from qbinary.instruction import Instruction
from qbinary.backend.binexport.operand import OperandBinExport

from qbinary.utils import cached_property


if TYPE_CHECKING:
    import binexport  # type: ignore[import-untyped]


class InstructionBinExport(Instruction):
    __slots__ = ("_cached_properties", "_be_instr")

    def __init__(self, be_instr: binexport.InstructionBinExport):
        super().__init__()

        # Private attributes
        self._be_instr = be_instr
        self._cached_properties: dict = {}

        # Public attributes
        self.comment = ""  # Not supported
        self.mnemonic = self._be_instr.mnemonic
        self.disasm = self._be_instr.disasm
        self.addr = self._be_instr.addr
        self.bytes = self._be_instr.bytes
        self.extra = None

    @cached_property
    def operands(self) -> list[OperandBinExport]:  # type: ignore[override]
        """Returns the list of operands as Operand object."""
        return [OperandBinExport(op) for op in self._be_instr.operands]
