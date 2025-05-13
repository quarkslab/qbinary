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

"""Interface over a Operand

Contains the abstraction layer to a Operand"""

from __future__ import annotations
from typing import TYPE_CHECKING
from qbinary.abc import ABCMetaAttributes


if TYPE_CHECKING:
    from qbinary.types import OperandType


class Operand(metaclass=ABCMetaAttributes):
    """
    Representation of an operand of an assembly instruction.
    This is an abstract class and should not be used as is.

    .. warning::
        The operand interface is mostly specific to the backend used.
    """

    __slots__ = ("type", "value", "extra")

    type: OperandType  # The operand type
    value: int | None  # The immediate value used by the operand. None if there isn't one
    extra: Any | None  # Backend specific extra information. Interface not uniform across backends

    def __repr__(self) -> str:
        return f"<{type(self).__name__}:{self}>"

    def __str__(self) -> str:
        return f"{self.type}"
