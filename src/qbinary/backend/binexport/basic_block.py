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

Contains the BasicBlockBinExport implementation"""

from __future__ import annotations
import weakref, binexport, capstone
from typing import TYPE_CHECKING

from qbinary.basic_block import BasicBlock
from qbinary.backend.binexport.instruction import InstructionBinExport
from qbinary.utils import cached_property, log_once

if TYPE_CHECKING:
    from qbinary.backend.binexport.program import ProgramBinExport


def _get_capstone_disassembler(binexport_arch: str, mode: int = 0):
    def capstone_context(arch, mode):
        context = capstone.Cs(arch, mode)
        context.detail = True
        return context

    if binexport_arch == "x86-32" or binexport_arch == "x86":
        return capstone_context(capstone.CS_ARCH_X86, capstone.CS_MODE_32 | mode)
    elif binexport_arch == "x86-64":
        return capstone_context(capstone.CS_ARCH_X86, capstone.CS_MODE_64 | mode)
    elif binexport_arch == "ARM-32":
        return capstone_context(capstone.CS_ARCH_ARM, mode)
    elif binexport_arch == "ARM-64":
        return capstone_context(capstone.CS_ARCH_ARM64, mode)
    elif binexport_arch == "MIPS-32":
        return capstone_context(capstone.CS_ARCH_MIPS, capstone.CS_MODE_32 | mode)
    elif binexport_arch == "MIPS-64":
        return capstone_context(capstone.CS_ARCH_MIPS, capstone.CS_MODE_64 | mode)

    raise NotImplementedError(
        f"Cannot instantiate a capstone disassembler from architecture {binexport_arch}"
    )

def _is_same_mnemonic(mnemonic1: str, mnemonic2: str) -> bool:
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


class BasicBlockBinExport(BasicBlock):
    __slots__ = ("_program", "_be_block", "_cached_properties")

    def __init__(
        self,
        program: weakref.ref[ProgramBinExport],
        be_block: binexport.basic_block.BasicBlockBinExport,
    ):
        super().__init__()

        # Private attributes
        self._program = program
        self._be_block = be_block
        self._cached_properties = {}

        # Public attributes
        self.addr = self._be_block.addr
        self.bytes = self._be_block.bytes

    def _guess_thumb_context(self, instr_bytes: bytes, mnemonic: str) -> int:
        """Guess wether the instruction is thumb or not"""

        if len(instr_bytes) < 2:  # Must be an error
            raise ValueError(f"Instruction malformed of size {len(instr_bytes)} bytes.")

        if len(instr_bytes) == 2:  # Must be thumb
            return capstone.CS_MODE_THUMB

        # Might be either thumb or normal arm.
        # There is no easy way of knowing whether a 4/8 bytes instruction is thumb or not
        # and IDA sometimes likes to merge two instructions together (so two 4bytes thumb
        # instructions might become a single 8bytes thumb instruction from IDA perspective).
        # The only way of checking if the context is correct is by comparing the mnemonic
        # of the capstone instruction with the one in BinExport.
        # Of course we have to rely on heuristics to know whether the two mnemonics are the
        # same or not.
        log_once(
            logging.WARNING,
            f"Relying on heuristics to guess the context mode of the binary (thumb or not)",
        )

        # Save the original mode
        arch = self.program.architecture_name

        # Bruteforce-guessing the context
        for capstone_mode in [capstone.CS_MODE_ARM, capstone.CS_MODE_THUMB]:  # try both modes
            # Disassemble the instruction and check the mnemonic
            disassembler = _get_capstone_disassembler(arch, capstone_mode)
            disasm = disassembler.disasm(instr_bytes, self.addr)
            try:
                instr = next(disasm)
                # Check if the mnemonic is the same
                if _is_same_mnemonic(instr.mnemonic, mnemonic):
                    return capstone_mode
            except StopIteration:
                pass

        # We have not being lucky
        raise TypeError(
            f"Cannot guess {self.program.name} ISA for the instruction at address {self.addr:#x} "
            f"(consider setting it manually through the `arch` parameter)"
        )

    def _disassemble(
        self, bb_asm: bytes, correct_mnemonic: str, correct_size: int
    ) -> list[capstone.CsInsn]:
        """
        Disassemble the basic block using capstone trying to guess the instruction set
        when unable to determine it from binexport.

        :param bb_asm: basic block raw bytes
        :param correct_mnemonic: The correct mnemonic of the first instruction of the
                                 basic block
        :param correct_size: The right size of the first instruction of the basic block
        """

        # Check if we already have a capstone context, if so use it
        if self.program.cs:
            return list(self.program.cs.disasm(bb_asm, self.addr))

        # Continue with the old method
        arch = self.program.architecture_name
        capstone_mode = 0

        # No need to guess the context for these arch
        if arch in ("x86", "x86-32", "x86-64", "MIPS-32", "MIPS-64", "ARM-64"):
            pass

        # For arm thumb use appropriate context guessing heuristics
        elif arch == "ARM-32":
            capstone_mode = self._guess_thumb_context(bb_asm[:correct_size], correct_mnemonic)

        # Everything else not yet supported
        else:
            raise NotImplementedError(
                f"Cannot automatically derive the capstone architecture from {arch}. "
                "Consider specifying one manually via the `arch` parameter."
            )

        # Set the program wide disassembler
        self.program.cs = _get_capstone_disassembler(arch, capstone_mode)
        return list(self.program.cs.disasm(bb_asm, self.addr))

    @property
    def program(self) -> ProgramBinExport:
        """Wrapper on weak reference on ProgramBinExport"""
        if (program := self._program()) is None:
            raise RuntimeError(
                "Trying to access an already expired weak reference on ProgramBinExport"
            )
        return program

    @cached_property
    def instructions(self) -> list[InstructionBinExport]:
        """
        List of Instruction objects of the basic block
        """

        # Generates the first instruction and use it to guess the context for capstone
        first_instr = next(iter(self._be_block.instructions.values()))
        capstone_instructions = self._disassemble(
            self._be_block.bytes, first_instr.mnemonic, len(first_instr.bytes)
        )

        # Then iterate over the instructions
        return [InstructionBinExport(self.program.cs, instr) for instr in capstone_instructions]
