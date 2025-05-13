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

"""Capstone backend

Contains the OperandCapstone implementation"""

from __future__ import annotations
from dataclasses import dataclass
import capstone  # type: ignore[import-untyped]
from typing import TYPE_CHECKING
from qbinary.operand import Operand
from qbinary.types import OperandType


if TYPE_CHECKING:
    from typing import Any, TypeAlias

    capstoneArch: TypeAlias = int  # Relaxed typing
    capstoneOperand: TypeAlias = Any  # Relaxed typing


_OPERAND_TYPE_MAPPING = {
    capstone.CS_ARCH_ARM: {
        capstone.arm_const.ARM_OP_INVALID: OperandType.unknown,
        capstone.arm_const.ARM_OP_REG: OperandType.register,
        capstone.arm_const.ARM_OP_IMM: OperandType.immediate,
        capstone.arm_const.ARM_OP_MEM: OperandType.memory,
        capstone.arm_const.ARM_OP_FP: OperandType.float_point,
        capstone.arm_const.ARM_OP_CIMM: OperandType.coprocessor,
        capstone.arm_const.ARM_OP_PIMM: OperandType.coprocessor,
        capstone.arm_const.ARM_OP_SETEND: OperandType.arm_setend,
        capstone.arm_const.ARM_OP_SYSREG: OperandType.coprocessor,
    },
    capstone.CS_ARCH_ARM64: {
        capstone.arm64_const.ARM64_OP_INVALID: OperandType.unknown,
        capstone.arm64_const.ARM64_OP_REG: OperandType.register,
        capstone.arm64_const.ARM64_OP_IMM: OperandType.immediate,
        capstone.arm64_const.ARM64_OP_MEM: OperandType.memory,
        capstone.arm64_const.ARM64_OP_FP: OperandType.float_point,
        capstone.arm64_const.ARM64_OP_CIMM: OperandType.coprocessor,
        capstone.arm64_const.ARM64_OP_REG_MRS: OperandType.coprocessor,
        capstone.arm64_const.ARM64_OP_REG_MSR: OperandType.coprocessor,
        capstone.arm64_const.ARM64_OP_PSTATE: OperandType.register,
        capstone.arm64_const.ARM64_OP_SYS: OperandType.arm_memory_management,
        capstone.arm64_const.ARM64_OP_SVCR: OperandType.coprocessor,
        capstone.arm64_const.ARM64_OP_PREFETCH: OperandType.arm_memory_management,
        capstone.arm64_const.ARM64_OP_BARRIER: OperandType.arm_memory_management,
        capstone.arm64_const.ARM64_OP_SME_INDEX: OperandType.arm_sme,
    },
    capstone.CS_ARCH_MIPS: {
        capstone.mips_const.MIPS_OP_INVALID: OperandType.unknown,
        capstone.mips_const.MIPS_OP_REG: OperandType.register,
        capstone.mips_const.MIPS_OP_IMM: OperandType.immediate,
        capstone.mips_const.MIPS_OP_MEM: OperandType.memory,
    },
    capstone.CS_ARCH_X86: {
        capstone.x86_const.X86_OP_INVALID: OperandType.unknown,
        capstone.x86_const.X86_OP_REG: OperandType.register,
        capstone.x86_const.X86_OP_IMM: OperandType.immediate,
        capstone.x86_const.X86_OP_MEM: OperandType.memory,
    },
    capstone.CS_ARCH_PPC: {
        capstone.ppc_const.PPC_OP_INVALID: OperandType.unknown,
        capstone.ppc_const.PPC_OP_REG: OperandType.register,
        capstone.ppc_const.PPC_OP_IMM: OperandType.immediate,
        capstone.ppc_const.PPC_OP_MEM: OperandType.memory,
        capstone.ppc_const.PPC_OP_CRX: OperandType.register,
    },
    capstone.CS_ARCH_SPARC: {
        capstone.sparc_const.SPARC_OP_INVALID: OperandType.unknown,
        capstone.sparc_const.SPARC_OP_REG: OperandType.register,
        capstone.sparc_const.SPARC_OP_IMM: OperandType.immediate,
        capstone.sparc_const.SPARC_OP_MEM: OperandType.memory,
    },
    capstone.CS_ARCH_SYSZ: {
        capstone.sysz_const.SYSZ_OP_INVALID: OperandType.unknown,
        capstone.sysz_const.SYSZ_OP_REG: OperandType.register,
        capstone.sysz_const.SYSZ_OP_IMM: OperandType.immediate,
        capstone.sysz_const.SYSZ_OP_MEM: OperandType.memory,
        capstone.sysz_const.SYSZ_OP_ACREG: OperandType.register,
    },
    capstone.CS_ARCH_XCORE: {
        capstone.xcore_const.XCORE_OP_INVALID: OperandType.unknown,
        capstone.xcore_const.XCORE_OP_REG: OperandType.register,
        capstone.xcore_const.XCORE_OP_IMM: OperandType.immediate,
        capstone.xcore_const.XCORE_OP_MEM: OperandType.memory,
    },
    capstone.CS_ARCH_M68K: {
        capstone.m68k_const.M68K_OP_INVALID: OperandType.unknown,
        capstone.m68k_const.M68K_OP_REG: OperandType.register,
        capstone.m68k_const.M68K_OP_IMM: OperandType.immediate,
        capstone.m68k_const.M68K_OP_MEM: OperandType.memory,
        capstone.m68k_const.M68K_OP_FP_SINGLE: OperandType.float_point,
        capstone.m68k_const.M68K_OP_FP_DOUBLE: OperandType.float_point,
        capstone.m68k_const.M68K_OP_REG_BITS: OperandType.register,
        capstone.m68k_const.M68K_OP_REG_PAIR: OperandType.register,
        capstone.m68k_const.M68K_OP_BR_DISP: OperandType.memory,
    },
    capstone.CS_ARCH_TMS320C64X: {
        capstone.tms320c64x_const.TMS320C64X_OP_INVALID: OperandType.unknown,
        capstone.tms320c64x_const.TMS320C64X_OP_REG: OperandType.register,
        capstone.tms320c64x_const.TMS320C64X_OP_IMM: OperandType.immediate,
        capstone.tms320c64x_const.TMS320C64X_OP_MEM: OperandType.memory,
        capstone.tms320c64x_const.TMS320C64X_OP_REGPAIR: OperandType.register,
    },
    capstone.CS_ARCH_M680X: {
        capstone.m680x_const.M680X_OP_INVALID: OperandType.unknown,
        capstone.m680x_const.M680X_OP_REGISTER: OperandType.register,
        capstone.m680x_const.M680X_OP_IMMEDIATE: OperandType.immediate,
        capstone.m680x_const.M680X_OP_INDEXED: OperandType.memory,
        capstone.m680x_const.M680X_OP_EXTENDED: OperandType.memory,
        capstone.m680x_const.M680X_OP_DIRECT: OperandType.memory,
        capstone.m680x_const.M680X_OP_RELATIVE: OperandType.memory,
        capstone.m680x_const.M680X_OP_CONSTANT: OperandType.immediate,
    },
    capstone.CS_ARCH_MOS65XX: {
        capstone.mos65xx_const.MOS65XX_OP_INVALID: OperandType.unknown,
        capstone.mos65xx_const.MOS65XX_OP_REG: OperandType.register,
        capstone.mos65xx_const.MOS65XX_OP_IMM: OperandType.immediate,
        capstone.mos65xx_const.MOS65XX_OP_MEM: OperandType.memory,
    },
    capstone.CS_ARCH_WASM: {
        capstone.wasm_const.WASM_OP_INVALID: OperandType.unknown,
        capstone.wasm_const.WASM_OP_NONE: OperandType.unknown,
        capstone.wasm_const.WASM_OP_INT7: OperandType.unknown,
        capstone.wasm_const.WASM_OP_VARUINT32: OperandType.unknown,
        capstone.wasm_const.WASM_OP_VARUINT64: OperandType.unknown,
        capstone.wasm_const.WASM_OP_UINT32: OperandType.unknown,
        capstone.wasm_const.WASM_OP_UINT64: OperandType.unknown,
        capstone.wasm_const.WASM_OP_IMM: OperandType.immediate,
        capstone.wasm_const.WASM_OP_BRTABLE: OperandType.unknown,
    },
    capstone.CS_ARCH_BPF: {
        capstone.bpf_const.BPF_OP_INVALID: OperandType.unknown,
        capstone.bpf_const.BPF_OP_REG: OperandType.register,
        capstone.bpf_const.BPF_OP_IMM: OperandType.immediate,
        capstone.bpf_const.BPF_OP_OFF: OperandType.unknown,
        capstone.bpf_const.BPF_OP_MEM: OperandType.memory,
        capstone.bpf_const.BPF_OP_MMEM: OperandType.unknown,
        capstone.bpf_const.BPF_OP_MSH: OperandType.unknown,
        capstone.bpf_const.BPF_OP_EXT: OperandType.unknown,
    },
    capstone.CS_ARCH_RISCV: {
        capstone.riscv_const.RISCV_OP_INVALID: OperandType.unknown,
        capstone.riscv_const.RISCV_OP_REG: OperandType.register,
        capstone.riscv_const.RISCV_OP_IMM: OperandType.immediate,
        capstone.riscv_const.RISCV_OP_MEM: OperandType.memory,
    },
    capstone.CS_ARCH_SH: {
        capstone.sh_const.SH_OP_INVALID: OperandType.unknown,
        capstone.sh_const.SH_OP_REG: OperandType.register,
        capstone.sh_const.SH_OP_IMM: OperandType.immediate,
        capstone.sh_const.SH_OP_MEM: OperandType.memory,
    },
    capstone.CS_ARCH_TRICORE: {
        capstone.tricore_const.TRICORE_OP_INVALID: OperandType.unknown,
        capstone.tricore_const.TRICORE_OP_REG: OperandType.register,
        capstone.tricore_const.TRICORE_OP_IMM: OperandType.immediate,
        capstone.tricore_const.TRICORE_OP_MEM: OperandType.memory,
    },
    capstone.CS_ARCH_EVM: {
        # No operands are defined by capstone
    },
}


def _convert_operand_type(arch: capstoneArch, cs_operand: capstoneOperand) -> OperandType:
    """
    Function that convert the capstone operand type to Operand type.
    The conversion is specific to the architecture because capstone operand
    type differs from one arch to another.

    Note 1: For the BPF arch, we are yet unsure how to handle the different
            type offered by capstone.
    Note 2: For WASM there is currently no documentation on the different
            operands so it is hard to convert them.
    Note 3: There is actually no operand for the EVM arch.
    """

    arch_specific_operands = _OPERAND_TYPE_MAPPING.get(arch)
    if not arch_specific_operands:
        raise NotImplementedError(f"Unrecognized capstone arch {arch}")
    operand_type = arch_specific_operands.get(cs_operand.type)  # type: ignore[attr-defined]
    if not operand_type:
        raise Exception(f"Unrecognized capstone operand {cs_operand.type} for arch {arch}")
    return operand_type


@dataclass
class OperandCapstoneExtra:
    """
    Provide extra information, specific to the capstone backend.

    .. warning::
        This interface is specific to capstone and is not uniform across backends.
        The interface is NOT guaranteed to be backwards compatible.
    """

    capstone_operand: capstoneOperand  # The capstone operand


class OperandCapstone(Operand):
    def __init__(self, cs: capstone.Cs, cs_operand: capstoneOperand):
        super().__init__()

        # Public attributes
        # Convert the capstone operand type
        self.type = _convert_operand_type(cs.arch, cs_operand)
        self.value = cs_operand.value.imm if self.type == OperandType.immediate else None
        self.extra = OperandCapstoneExtra(cs_operand)

    def __str__(self) -> str:
        # TODO implement a real string representation of the operand
        return "Operand"
