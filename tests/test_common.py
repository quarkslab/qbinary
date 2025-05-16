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

"""Testing the common interface of qbinary

Contains the tests for the unified interface of qbinary over any backend"""

import pytest
from pathlib import Path
import qbinary
from qbinary import Program
from qbinary.backend.binexport import ProgramBinExport


@pytest.mark.binexport
@pytest.mark.quokka
class TestCommonInterface:
    """
    Test the same binary, loaded with different backends.
    The common interface exposed by Qbinary is always the same.
    """

    TEST_SET = (
        (
            Path("sample_gcc_O2_x86_s"),
            (Path("sample_gcc_O2_x86_s.BinExport"), Path("sample_gcc_O2_x86_s.quokka")),
        ),
        (
            Path("sample_gcc_O2_x86_g"),
            (Path("sample_gcc_O2_x86_g.BinExport"), Path("sample_gcc_O2_x86_g.quokka")),
        ),
        (
            Path("sample_gcc_O2_x64_s"),
            (Path("sample_gcc_O2_x64_s.BinExport"), Path("sample_gcc_O2_x64_s.quokka")),
        ),
        (
            Path("sample_gcc_O2_x64_g"),
            (Path("sample_gcc_O2_x64_g.BinExport"), Path("sample_gcc_O2_x64_g.quokka")),
        ),
        (
            Path("sample_gcc_O0_x64_s"),
            (Path("sample_gcc_O0_x64_s.BinExport"), Path("sample_gcc_O0_x64_s.quokka")),
        ),
        (
            Path("sample_gcc_O0_x64_g"),
            (Path("sample_gcc_O0_x64_g.BinExport"), Path("sample_gcc_O0_x64_g.quokka")),
        ),
        (
            Path("sample_gcc_O0_x86_s"),
            (Path("sample_gcc_O0_x86_s.BinExport"), Path("sample_gcc_O0_x86_s.quokka")),
        ),
        (
            Path("sample_gcc_O0_x86_g"),
            (Path("sample_gcc_O0_x86_g.BinExport"), Path("sample_gcc_O0_x86_g.quokka")),
        ),
        (
            Path("sample_clang_O2_x86_s"),
            (Path("sample_clang_O2_x86_s.BinExport"), Path("sample_clang_O2_x86_s.quokka")),
        ),
        (
            Path("sample_clang_O2_x86_g"),
            (Path("sample_clang_O2_x86_g.BinExport"), Path("sample_clang_O2_x86_g.quokka")),
        ),
        (
            Path("sample_clang_O2_x64_s"),
            (Path("sample_clang_O2_x64_s.BinExport"), Path("sample_clang_O2_x64_s.quokka")),
        ),
        (
            Path("sample_clang_O2_x64_g"),
            (Path("sample_clang_O2_x64_g.BinExport"), Path("sample_clang_O2_x64_g.quokka")),
        ),
        (
            Path("sample_clang_O0_x86_s"),
            (Path("sample_clang_O0_x86_s.BinExport"), Path("sample_clang_O0_x86_s.quokka")),
        ),
        (
            Path("sample_clang_O0_x86_g"),
            (Path("sample_clang_O0_x86_g.BinExport"), Path("sample_clang_O0_x86_g.quokka")),
        ),
        (
            Path("sample_clang_O0_x64_s"),
            (Path("sample_clang_O0_x64_s.BinExport"), Path("sample_clang_O0_x64_s.quokka")),
        ),
        (
            Path("sample_clang_O0_x64_g"),
            (Path("sample_clang_O0_x64_g.BinExport"), Path("sample_clang_O0_x64_g.quokka")),
        ),
    )

    def _test_common(self, program: Program) -> None:
        assert len(program) == len(program.keys()) == len(program.values()) == len(program.items())

        # Test complex types
        if program.capabilities & qbinary.ProgramCapability.COMPLEX_TYPES:
            for struct in program.structures:
                for member in struct.members:
                    pass
            for union in program.unions:
                for member in union.members:
                    pass
            for enum in program.enums:
                for member_name, member_val in enum.members:
                    pass

        for fun_addr, fun in program.items():
            assert fun_addr == fun.addr
            assert program.func_names[fun.name] == fun_addr

            with fun:
                for bb_addr, bb in fun.items():
                    assert bb_addr == bb.addr
                    bb_size = len(bb.bytes)

                    for instr in bb.instructions:
                        # In binexport the basic blocks are not necessarily a contiguous sequence
                        # of instructions. So skip the assert
                        if not isinstance(program, ProgramBinExport):
                            assert bb.addr <= instr.addr < bb.addr + bb_size

                        for operand in instr.operands:
                            pass

            # Force a preload
            for _ in fun.items():
                pass

    def test_x86_binary(self) -> None:
        for binary, (binexport_path, quokka_path) in TestCommonInterface.TEST_SET:
            prog = Program.from_binexport(str("tests/data" / binexport_path))
            self._test_common(prog)
            prog = Program.from_quokka(str("tests/data" / quokka_path), str("tests/data" / binary))
            self._test_common(prog)
