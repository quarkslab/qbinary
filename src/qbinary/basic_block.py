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

"""Interface over a Basic Block

Contains the abstraction layer to a Basic Block"""

from __future__ import annotations
from abc import abstractmethod
from collections.abc import Iterable
from typing import TYPE_CHECKING

from qbinary.instruction import Instruction
from qbinary.abc import ABCMetaAttributes

if TYPE_CHECKING:
    from qbinary.types import Addr


class BasicBlock(metaclass=ABCMetaAttributes):
    """
    Representation of a basic block of a Function. A basic block is defined as a
    contiguous region of memory containing instructions that do not modify the function control flow
    (such as jumps and branches). It has a single entry point and a single exit point.
    This is an abstract class and should not be used as is.
    """

    __slots__ = ("addr", "bytes")

    addr: Addr  # Address of the basic block
    bytes: bytes  # Raw bytes of basic block instructions.

    def __repr__(self) -> str:
        return f"<{type(self).__name__}: size {len(self.bytes)}>"

    @property
    @abstractmethod
    def instructions(self) -> list[Instruction]:
        """
        List of Instruction objects of the basic block
        """
        raise NotImplementedError()
