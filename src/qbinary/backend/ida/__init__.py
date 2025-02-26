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

"""IDA Backend

The implementation of the IDA backend"""

from qbinary.backend.ida.program import ProgramIDA
from qbinary.backend.ida.function import FunctionIDA
from qbinary.backend.ida.basic_block import BasicBlockIDA
from qbinary.backend.ida.instruction import InstructionIDA
from qbinary.backend.ida.operand import OperandIDA
