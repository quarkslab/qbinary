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

Contains the OperandBinExport implementation"""

from __future__ import annotations
from dataclasses import dataclass
from typing import TYPE_CHECKING
from qbinary.operand import Operand
from qbinary.types import OperandType


if TYPE_CHECKING:
    import binexport  # type: ignore[import-untyped]


@dataclass
class OperandBinExportExtra:
    """
    Provide extra information, specific to the BinExport backend.

    .. warning::
        This interface is specific to BinExport and is not uniform across backends.
        The interface is NOT guaranteed to be backwards compatible.
    """

    binexport_operand: binexport.OperandBinExport  # The binexport operand


class OperandBinExport(Operand):
    __slots__ = ("_str_repr",)

    def __init__(self, be_operand: binexport.OperandBinExport):
        super().__init__()

        # Private attributes
        self._str_repr = str(be_operand)

        # Public attributes
        self.type = OperandType.unknown  # TODO Maybe parse the expressions to get it?
        self.value = None  # TODO maybe just put the string?
        self.extra = OperandBinExportExtra(binexport_operand=be_operand)

    def __str__(self) -> str:
        return self._str_repr
