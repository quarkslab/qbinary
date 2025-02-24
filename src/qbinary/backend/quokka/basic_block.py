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

Contains the BasicBlockQuokka implementation"""

from __future__ import annotations
import logging
from typing import TYPE_CHECKING

from qbinary.basic_block import BasicBlock
from qbinary.backend.quokka.instruction import InstructionQuokka
from qbinary.utils import cached_property

if TYPE_CHECKING:
    import quokka  # type: ignore[import-untyped]


class BasicBlockQuokka(BasicBlock):
    __slots__ = ("_qk_block", "_cached_properties")

    def __init__(self, qk_block: quokka.block.Block):
        super().__init__()

        # Private attributes
        self._qk_block = qk_block
        self._cached_properties: dict = {}

        # Public attributes
        self.addr = self._qk_block.start
        self.bytes = self._qk_block.bytes

    def __del__(self) -> None:
        """
        Clean quokka internal state by unloading from memory the Block object
        """

        chunk = self._qk_block.parent
        chunk._raw_dict[self._qk_block.start] = self._qk_block.proto_index

    @cached_property
    def instructions(self) -> list[InstructionQuokka]:  # type: ignore[override]
        """
        List of Instruction objects of the basic block
        """

        return [InstructionQuokka(instr) for instr in self._qk_block.instructions]
