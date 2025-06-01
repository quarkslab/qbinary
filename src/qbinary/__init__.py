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

"""QBinary

QBinary is a framework meant to offer a stable universal API over binaries.
"""

from qbinary.__version__ import __version__
from qbinary.program import Program
from qbinary.function import Function
from qbinary.basic_block import BasicBlock
from qbinary.instruction import Instruction
from qbinary.operand import Operand
from qbinary.types import (
    ProgramCapability,
    OperandType,
    FunctionType,
    InstructionGroup,
    BackendType,
    Disassembler,
    ExportFormat,
    QbinaryException,
    DisassExportNotImplemented,
    ExportException,
)

__all__ = [
    "Program",
    "Function",
    "BasicBlock",
    "Instruction",
    "Operand",
    "ProgramCapability",
    "OperandType",
    "FunctionType",
    "InstructionGroup",
    "BackendType",
    "Disassembler",
    "ExportFormat",
    "QbinaryException",
    "DisassExportNotImplemented",
    "ExportException",
]
