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

"""IDA backend

Contains the BasicBlockIDA implementation"""

from __future__ import annotations
import ida_bytes, idautils  # type: ignore[import-not-found]
from typing import TYPE_CHECKING

from qbinary.basic_block import BasicBlock
from qbinary.backend.ida.instruction import InstructionIDA
from qbinary.utils import cached_property

if TYPE_CHECKING:
    from qbinary.types import Addr


class BasicBlockIDA(BasicBlock):
    __slots__ = ("_cached_properties", "_end_addr")

    def __init__(self, start_addr: Addr, end_addr: Addr):
        super().__init__()

        # Private attributes
        self._end_addr: Addr = end_addr
        self._cached_properties: dict = {}

        # Public attributes
        self.addr = start_addr
        self.bytes = ida_bytes.get_bytes(self.addr, end_addr - self.addr)

    @cached_property
    def instructions(self) -> list[InstructionIDA]:  # type: ignore[override]
        """
        List of Instruction objects of the basic block
        """
        return [InstructionIDA(addr) for addr in idautils.Heads(self.addr, self._end_addr)]
