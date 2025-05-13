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

Contains the InstructionIDA implementation"""

from __future__ import annotations
from dataclasses import dataclass
from functools import cached_property
import idc, ida_bytes, ida_ua  # type: ignore[import-not-found]
from typing import TYPE_CHECKING

from qbinary.instruction import Instruction
from qbinary.backend.ida.operand import OperandIDA
from qbinary.utils import cached_property


if TYPE_CHECKING:
    from qbinary.types import Addr


@dataclass
class InstructionIDAExtra:
    """
    Provide extra information, specific to the IDA backend.

    .. warning::
        This interface is specific to the IDA backend and is not uniform
        across backends.
        The interface is NOT guaranteed to be backwards compatible.
    """

    ida_instr: ida_ua.insn_t  # IDA instruction

    @cached_property
    def id(self):
        """IDA instruction ID"""
        return self.ida_instr.ityped


class InstructionIDA(Instruction):
    __slots__ = ("_cached_properties", "_ida_instr")

    def __init__(self, addr: Addr):
        super().__init__()

        # Private attributes
        self._ida_instr = ida_ua.insn_t()
        ida_ua.decode_insn(self._ida_instr, addr)
        self._cached_properties: dict = {}

        # Public attributes
        self.comment = ida_bytes.get_cmt(addr, True) or ""  # return repeatable ones
        self.mnemonic = ida_ua.ua_mnem(addr)
        self.disasm = idc.GetDisasm(addr)
        self.addr = addr
        self.bytes = ida_bytes.get_bytes(addr, self._ida_instr.size)
        self.extra = InstructionIDAExtra(ida_instr=self._ida_instr)

    @cached_property
    def operands(self) -> list[OperandIDA]:  # type: ignore[override]
        """Returns the list of operands as Operand object."""
        return [
            OperandIDA(op, self.addr)
            for op in self._ida_instr.ops
            if op.type != ida_ua.o_void and op.shown()
        ]
