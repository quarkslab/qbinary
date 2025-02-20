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

"""BinExport backend loader"""

# builtin imports
from __future__ import annotations
import logging
import weakref
from typing import Any, TypeAlias, TYPE_CHECKING
from collections.abc import Iterator
from functools import cached_property

# third-party imports
import capstone  # type: ignore[import-untyped]
import binexport  # type: ignore[import-untyped]
import binexport.types  # type: ignore[import-untyped]
import networkx

# local imports
from qbindiff.loader.backend import (
    AbstractProgramBackend,
    AbstractFunctionBackend,
    AbstractBasicBlockBackend,
    AbstractInstructionBackend,
    AbstractOperandBackend,
)
from qbindiff.loader.backend.utils import convert_operand_type
from qbindiff.loader import Structure
from qbindiff.utils import log_once
from qbindiff.loader.types import (
    FunctionType,
    ReferenceType,
    ReferenceTarget,
    OperandType,
    InstructionGroup,
    ProgramCapability,
)

if TYPE_CHECKING:
    from qbindiff.types import Addr

# Type aliases
beFunction: TypeAlias = binexport.function.FunctionBinExport
beBasicBlock: TypeAlias = binexport.basic_block.BasicBlockBinExport
capstoneOperand: TypeAlias = Any  # Relaxed typing


# === General purpose utils functions ===


def is_same_mnemonic(mnemonic1: str, mnemonic2: str) -> bool:
    """Check whether two mnemonics are the same"""

    def normalize(mnemonic: str) -> str:
        if mnemonic == "ldmia":
            return "ldm"
        return mnemonic.replace("lo", "cc")

    mnemonic1 = normalize(mnemonic1)
    mnemonic2 = normalize(mnemonic2)

    if mnemonic1 == mnemonic2:
        return True

    if len(mnemonic1) > len(mnemonic2):
        mnemonic1, mnemonic2 = mnemonic2, mnemonic1
    if mnemonic1 + ".w" == mnemonic2:
        return True

    return False
