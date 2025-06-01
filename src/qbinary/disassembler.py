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
import os, sys
from pathlib import Path
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING
import logging

# third-party imports
import quokka
import binexport

# local imports
from qbinary.types import ExportFormat, Disassembler

if TYPE_CHECKING:
    from qbinary.program import Program


class DisassemblyEngine(ABC):

    @staticmethod
    @abstractmethod
    def generate(
        binary_file: Path | str,
        export_format: ExportFormat,
        timeout: int = 0,
        override: bool = True,
    ) -> Path | None:
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

    @staticmethod
    def from_enum(disassembler: Disassembler) -> type[DisassemblyEngine]:
        """
        Get the disassembler instance from the Disassembler enum value.

        :param disassembler: The Disassembler enum value
        :return: An instance of the corresponding disassembler class
        """
        if disassembler == Disassembler.IDA:
            return IDADisassembler
        elif disassembler == Disassembler.BINARY_NINJA:
            return BNDisassembler
        elif disassembler == Disassembler.GHIDRA:
            return GhidraDisassembler
        else:
            raise ValueError(f"Unsupported disassembler {disassembler}")


class IDADisassembler(DisassemblyEngine):

    @staticmethod
    def generate(
        binary_file: Path | str,
        export_format: ExportFormat,
        timeout: int = 0,
        override: bool = True,
    ) -> Path | None:
        formats = [ExportFormat.QUOKKA, ExportFormat.BINEXPORT]
        if export_format != ExportFormat.AUTO:
            formats = [export_format]

        for format_try in formats:

            if format_try == ExportFormat.QUOKKA:
                try:
                    export_file = quokka.Program.generate(
                        binary_file, override=override, timeout=timeout
                    )
                    if export_file.exists():
                        return export_file
                except FileNotFoundError as e:  # Raise if files not found
                    logging.warning(f"FileNotFoundError after Quokka generation: {e}")
                except quokka.QuokkaError as e:
                    logging.error(f"Quokka error during generation: {e}")

            elif format_try == ExportFormat.BINEXPORT:
                export_path = Path(str(binary_file) + ".BinExport")
                try:
                    prog = binexport.ProgramBinExport.generate(
                        binary_file,
                        export_path,
                        backend=binexport.DisassemblerBackend.IDA,
                        override=override,
                        timeout=timeout,
                    )
                    if prog:
                        return export_path
                except FileNotFoundError as e:  # Raise if files not found
                    logging.warning(f"FileNotFoundError after BinExport generation: {e}")
                except Exception as e:
                    logging.error(f"Error during BinExport generation: {e}")
                    continue  # Exception raise by means of calling idascript
            else:
                logging.warning(f"Unsupported exporting combination {format_try}/IDA")

        # Nothing worked
        return None

    @staticmethod
    def decompile(binary: Program) -> None:
        """
        Decompile the program and fill the Program object in place.
        Not yet supported.
        """
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

        def find_in_dir(d: Path) -> str:
            for bin_name in names:
                if (d / bin_name).exists():
                    return (d / bin_name).absolute().as_posix()
            return ""

        # Search for a IDA_PATH environment variable
        if "IDA_PATH" in os.environ:
            return find_in_dir(Path(os.environ["IDA_PATH"]))
        elif "PATH" in os.environ:  # Iterate PATH (linux only)
            for p in os.environ["PATH"].split(":"):
                if ida_path := find_in_dir(Path(p)):
                    return ida_path
        return None

    @staticmethod
    def exist() -> bool:
        """
        Check if the disassembler can be found in the system path

        :return: True if the disassembler is found, False otherwise
        """
        return bool(IDADisassembler.get_path())


class BNDisassembler(DisassemblyEngine):
    @staticmethod
    def generate(
        binary_file: Path | str,
        export_format: ExportFormat,
        timeout: int = 0,
        override: bool = True,
    ) -> Path | None:
        """
        Export the binary file provided using the specified format. It returns
        the exported file path or None when an error occurred
        """

        formats = (ExportFormat.BINEXPORT,)
        if export_format != ExportFormat.AUTO:
            formats = (export_format,)

        for format_try in formats:
            if format_try == ExportFormat.BINEXPORT:
                export_path = Path(binary_file).with_suffix(".BinExport")
                try:
                    prog = binexport.ProgramBinExport.generate(
                        binary_file,
                        export_path,
                        backend=binexport.DisassemblerBackend.BINARY_NINJA,
                        override=override,
                        timeout=timeout,
                    )
                    if prog:
                        return export_path
                except FileNotFoundError as e:  # Raise if files not found
                    logging.warning(f"FileNotFoundError after BinExport generation: {e}")
                except Exception as e:
                    logging.error(f"Error during BinExport generation: {e}")
                    continue
            else:
                logging.warning(f"Unsupported exporting combination {format_try}/Binary Ninja")

        # Nothing worked
        return None

    @staticmethod
    def decompile(binary: Program) -> None:
        """
        Decompile the program and fill the Program object in place.
        Not yet supported.
        """
        return None

    @staticmethod
    def exist() -> bool:
        """
        Check if the binaryninja module is reachable.

        :return: True if the disassembler is found, False otherwise
        """
        try:
            import binaryninja
        except ModuleNotFoundError as e:
            logging.error(
                "Cannot find module python `binaryninja`. Try running BINARY_NINJA_PATH/scripts/install_api.py"
            )
            return False

        return True


class GhidraDisassembler(DisassemblyEngine):
    @staticmethod
    def generate(
        binary_file: Path | str,
        export_format: ExportFormat,
        timeout: int = 0,
        override: bool = True,
    ) -> Path | None:
        """
        Export the binary file provided using the specified format. It returns
        the exported file path or None when an error occurred
        """

        formats = (ExportFormat.BINEXPORT,)
        if export_format != ExportFormat.AUTO:
            formats = (export_format,)

        for format_try in formats:
            if format_try == ExportFormat.BINEXPORT:
                export_path = Path(binary_file).with_suffix(".BinExport")
                try:
                    prog = binexport.ProgramBinExport.generate(
                        binary_file,
                        export_path,
                        backend=binexport.DisassemblerBackend.GHIDRA,
                        override=override,
                        timeout=timeout,
                    )
                    if prog:
                        return export_path
                except FileNotFoundError as e:  # Raise if files not found
                    logging.warning(f"FileNotFoundError after BinExport generation: {e}")
                except Exception as e:
                    logging.error(f"Error during BinExport generation: {e}")
                    continue
            else:
                logging.warning(f"Unsupported exporting combination {format_try}/Ghidra")

        # Nothing worked
        return None

    @staticmethod
    def decompile(binary: Program) -> None:
        """
        Decompile the program and fill the Program object in place.
        Not yet supported.
        """
        return None

    @staticmethod
    def exist() -> bool:
        """
        Check if the Ghidra disassembler is reachable.

        :return: True if the disassembler is found, False otherwise
        """

        # Check if the GHIDRA_PATH environment variable is set
        ghidra_dir = os.environ.get("GHIDRA_PATH")
        if not ghidra_dir:
            logger.error(
                "The 'GHIDRA_PATH' environment variable is not set. "
                "Please set it to the root installation folder of Ghidra."
            )
            return False

        # Check if the GHIDRA_PATH dir exists
        ghidra_dir = Path(ghidra_dir)
        if not ghidra_dir.exists():
            logger.error(f"The path specified in 'GHIDRA_PATH' does not exist: {ghidra_dir}")
        elif not ghidra_dir.is_dir():
            logger.error(f"The path specified in 'GHIDRA_PATH' is not a directory: {ghidra_dir}")
        else:
            return True

        return False
