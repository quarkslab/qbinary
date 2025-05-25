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

"""Disassembler API

Contains the abstraction layer to interact with disassemblers"""

from __future__ import annotations
import os, sys, pathlib, quokka, binexport
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from qbinary.types import ExportFormat

if TYPE_CHECKING:
    from qbinary.program import Program


class Disassembler(ABC):

    @staticmethod
    @abstractmethod
    def from_binary(
        binary_file: pathlib.Path | str, export_format: ExportFormat
    ) -> pathlib.Path | None:
        """
        Export the binary file provided using the specified format. It returns
        the exported file path or None when an error occurred
        """
        raise NotImplementedError("This method should be implemented by subclasses")

    @staticmethod
    @abstractmethod
    def decompile(binary: Program) -> None:
        """
        Decompile the program and fill the Program object in place.
        """
        raise NotImplementedError("This method should be implemented by subclasses")

    @staticmethod
    @abstractmethod
    def exist() -> bool:
        """
        Check if the disassembler can be found in the system path

        :return: True if the disassembler is found, False otherwise
        """
        raise NotImplementedError("This method should be implemented by subclasses")


class IDADisassembler(Disassembler):

    @staticmethod
    def from_binary(binary_file: pathlib.Path | str, export_format: ExportFormat) -> str | None:
        formats = [ExportFormat.QUOKKA, ExportFormat.BINEXPORT]
        if export_format != ExportFormat.AUTO:
            formats = [export_format]

        for format_try in formats:
            if format_try == ExportFormat.QUOKKA:
                prog = quokka.Program.from_binary(file_path)
                if prog:
                    return prog.export_file

            elif format_try == ExportFormat.BINEXPORT:
                prog = binexport.ProgramBinExport.from_binary_file(
                    file_path, backend=binexport.DisassemblerBackend.IDA
                )
                if prog:
                    return prog.export_file
            else:
                raise ValueError(f"Unsupported binary exporter format {format_try}")

        # Nothing worked
        return None

    @staticmethod
    def get_path() -> str | None:
        """
        Get the IDA path by using several heuristics.

        :return: the IDA path if it was found, otherwise None
        """

        # Search different names to be version independent
        names = ("idat64", "idat")
        if sys.platform == "win32":
            names = tuple(x + ".exe" for x in names)

        def find_in_dir(d: pathlib.Path) -> str:
            for bin_name in names:
                if (d / bin_name).exists():
                    return (d / bin_name).absolute().as_posix()
            return None

        # Search for a IDA_PATH environment variable
        if "IDA_PATH" in os.environ:
            return find_in_dir(pathlib.Path(os.environ["IDA_PATH"]))
        elif "PATH" in os.environ:  # Iterate PATH (linux only)
            for p in os.environ["PATH"].split(":"):
                if ida_path := find_in_dir(pathlib.Path(p)):
                    return ida_path
        return None

    @staticmethod
    def exist() -> bool:
        """
        Check if the disassembler can be found in the system path

        :return: True if the disassembler is found, False otherwise
        """
        return bool(IDADisassembler.get_path())


# TODO complete this
class BNDisassembler(Disassembler):

    @staticmethod
    def exist() -> bool:
        """
        Check if the disassembler can be found in the system path

        :return: True if the disassembler is found, False otherwise
        """
        return False


# TODO complete this
class GhidraDisassembler(Disassembler):

    @staticmethod
    def exist() -> bool:
        """
        Check if the disassembler can be found in the system path

        :return: True if the disassembler is found, False otherwise
        """
        return False
