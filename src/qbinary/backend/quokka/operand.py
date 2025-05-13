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

Contains the OperandQuokka implementation"""

from __future__ import annotations
from functools import cache
from dataclasses import dataclass
from typing import TYPE_CHECKING
from qbinary.operand import Operand
from qbinary.types import OperandType

if TYPE_CHECKING:
    import quokka  # type: ignore[import-untyped]


@dataclass
class OperandQuokkaExtra:
    """
    Provide extra information, specific to the Quokka backend.

    .. warning::
        This interface is specific to Quokka and is not uniform across backends.
        The interface is NOT guaranteed to be backwards compatible.
    """

    quokka_operand: quokka.Operand  # The Quokka operand


class OperandQuokka(Operand):
    __slots__ = ("_str_repr",)

    @classmethod
    @cache
    def _convert_operand_type(cls, qk_type: int) -> OperandType:
        return OperandType.unknown  # TODO from ida

    def __init__(self, qk_operand: quokka.instruction.Operand):
        super().__init__()

        # Private attributes
        # TODO implement a real string representation of the operand
        self._str_repr = "Operand"

        # Public attributes
        self.type = self._convert_operand_type(qk_operand.type)
        self.value = qk_operand.value if self.type == OperandType.immediate else None
        self.extra = OperandQuokkaExtra(quokka_operand=qk_operand)

    def __str__(self) -> str:
        return self._str_repr
