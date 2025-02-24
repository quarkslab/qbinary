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

"""Testing the BinExport backend

Contains the tests for the BinExport backend"""

from qbinary import Program


class TestBinExport:
    """Regression tests for BinExport backend"""

    def test_x86_binary(self):
        prog = Program.from_binexport("tests/data/test-bin.BinExport")
        assert len(prog) == len(prog.keys()) == len(prog.values()) == len(prog.items()) == 367

        for fun_addr, fun in prog.items():
            assert fun_addr == fun.addr
            assert prog.func_names[fun.name] == fun_addr

            with fun:
                for bb_addr, bb in fun.items():
                    assert bb_addr == bb.addr
                    bb_size = len(bb.bytes)

                    for instr in bb.instructions:
                        assert bb.addr <= instr.addr < bb.addr + bb_size

                        for operand in instr.operands:
                            pass
