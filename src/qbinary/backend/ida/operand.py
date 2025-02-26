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

Contains the OperandIDA implementation"""

from __future__ import annotations
import ida_ua, ida_lines  # type: ignore[import-not-found]
from functools import cache
from typing import TYPE_CHECKING
from qbinary.operand import Operand
from qbinary.types import OperandType


if TYPE_CHECKING:
    from qbinary.types import Addr


class OperandIDA(Operand):
    __slots__ = ("_str_repr",)

    @classmethod
    @cache
    def _convert_operand_type(cls, ida_type: int) -> OperandType:
        if ida_type == ida_ua.o_reg:
            return OperandType.register
        elif ida_type == ida_ua.o_mem:
            return OperandType.memory
        elif ida_type == ida_ua.o_phrase:
            return OperandType.memory
        elif ida_type == ida_ua.o_displ:
            return OperandType.memory
        elif ida_type == ida_ua.o_imm:
            return OperandType.immediate
        elif ida_type == ida_ua.o_far:
            return OperandType.memory
        elif ida_type == ida_ua.o_near:
            return OperandType.memory
        else:
            return OperandType.unknown

    def __init__(self, ida_operand: ida_ua.op_t, inst_addr: Addr):
        super().__init__()

        # Private attributes
        self._str_repr = ida_lines.tag_remove(ida_ua.print_operand(inst_addr, ida_operand.n))

        # Public attributes
        self.type = self._convert_operand_type(ida_operand.type)
        self.value = ida_operand.value if self.type == OperandType.immediate else None

    def __str__(self) -> str:
        return self._str_repr
