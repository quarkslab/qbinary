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

Contains the BasicBlockBinExport implementation"""

from __future__ import annotations
import weakref
import binexport  # type: ignore[import-untyped]
from typing import TYPE_CHECKING

from qbinary.basic_block import BasicBlock
from qbinary.backend.binexport.instruction import InstructionBinExport
from qbinary.utils import cached_property

if TYPE_CHECKING:
    from qbinary.backend.binexport.program import ProgramBinExport
    from qbinary.backend.capstone.instruction import InstructionCapstone


class BasicBlockBinExport(BasicBlock):
    __slots__ = ("_program", "_be_block", "_cached_properties")

    def __init__(
        self,
        program: weakref.ref[ProgramBinExport],
        be_block: binexport.basic_block.BasicBlockBinExport,
    ):
        super().__init__()

        # Private attributes
        self._program = program
        self._be_block = be_block
        self._cached_properties: dict = {}

        # Public attributes
        self.addr = self._be_block.addr
        self.bytes = self._be_block.bytes

    @property
    def program(self) -> ProgramBinExport:
        """Wrapper on weak reference on ProgramBinExport"""
        if (program := self._program()) is None:
            raise RuntimeError(
                "Trying to access an already expired weak reference on ProgramBinExport"
            )
        return program

    @cached_property
    def instructions(self) -> list[InstructionBinExport]:  # type: ignore[override]
        """
        List of Instruction objects of the basic block
        """
        return [InstructionBinExport(instr) for instr in self._be_block.instructions.values()]

    @cached_property
    def capstone_instructions(self) -> list[InstructionCapstone]:
        """
        List of Instruction objects of the basic block, using the capstone backend.

        .. warning:: There might be a misalignment between BinExport and capstone disassembly
        """
        # Lazy import to avoid enforcing capstone dependency. It should come with a small overhead
        # that will hopefully be overcome by the instruction generation step
        from qbinary.backend.capstone.instruction import InstructionCapstone

        return [
            InstructionCapstone(self.program.cs, instr)
            for rng_addr, rng_bytes in self._be_block.contiguous_ranges
            for instr in self.program.cs.disasm(rng_bytes, rng_addr)
        ]
