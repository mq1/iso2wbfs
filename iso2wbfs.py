#!/usr/bin/env python3
#
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "cryptography==45.0.5",
#   "tqdm==4.67.1",
# ]
# ///
#
# SPDX-FileCopyrightText: 2025 Manuel Quarneti <mq1@ik.me>
# SPDX-License-Identifier: GPL-2.0-only

import argparse
import logging
import os
import struct
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("Error: The 'cryptography' library is required. Please install it with 'pip install cryptography'", file=sys.stderr)
    sys.exit(1)

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

# --- Constants from the C source ---

# wbfs.h, wiidisc.h
WII_SECTOR_SIZE = 0x8000  # 32 KB
WBFS_MAGIC = 0x57424653  # "WBFS"

# splits.h
SPLIT_SIZE_4GB_MINUS_32KB = (4 * 1024 * 1024 * 1024) - (32 * 1024)

# wiidisc.c
WII_COMMON_KEY = bytes.fromhex("ebe42a225e8593e448d9c5457381aaf7")
INVALID_PATH_CHARS = '/\\:|<>?*"\''
SINGLE_LAYER_WII_SECTORS = 143432
MAX_WII_SECTORS = SINGLE_LAYER_WII_SECTORS * 2

# --- Setup Logging ---
log = logging.getLogger(__name__)

class SplitWbfsWriter:
    """Manages writing to split WBFS files."""
    def __init__(self, base_path: Path, split_size: int):
        self.base_path = base_path
        self.split_size = split_size
        self.file_handles = {}
        self.temp_path = self.base_path.with_suffix('.wbfs.tmp')
        self.final_path = self.base_path.with_suffix('.wbfs')

        # Ensure no old files exist
        if self.temp_path.exists() or self.final_path.exists():
            raise FileExistsError(f"Output file already exists: {self.final_path} or {self.temp_path}")

    def _get_file(self, offset: int) -> (object, int):
        """Gets the correct file handle and relative offset for a global offset."""
        file_index = offset // self.split_size
        relative_offset = offset % self.split_size

        if file_index not in self.file_handles:
            if file_index == 0:
                filepath = self.temp_path
            else:
                filepath = self.base_path.with_suffix(f'.wbf{file_index}')

            log.debug(f"Opening split file {filepath} for writing.")
            self.file_handles[file_index] = open(filepath, 'wb')

        return self.file_handles[file_index], relative_offset

    def write(self, offset: int, data: bytes):
        """Writes data at a specific global offset."""
        while data:
            fh, rel_offset = self._get_file(offset)
            fh.seek(rel_offset)

            writable_len = self.split_size - rel_offset
            chunk = data[:writable_len]
            fh.write(chunk)

            data = data[writable_len:]
            offset += len(chunk)

    def truncate(self, total_size: int):
        """Truncates all split files to their final correct sizes."""
        remaining_size = total_size
        for i in sorted(self.file_handles.keys()):
            fh = self.file_handles[i]
            fh.flush()

            chunk_size = min(remaining_size, self.split_size)
            log.debug(f"Truncating file index {i} to {chunk_size} bytes.")
            os.ftruncate(fh.fileno(), chunk_size)
            remaining_size -= chunk_size
            if remaining_size <= 0:
                break

    def close(self):
        """Closes all file handles and renames the temporary first file."""
        for fh in self.file_handles.values():
            fh.close()

        if self.temp_path.exists():
            log.info(f"Renaming {self.temp_path} to {self.final_path}")
            self.temp_path.rename(self.final_path)

class WbfsConverter:
    """
    Handles the conversion of a Wii ISO to a WBFS file, replicating the
    behavior of wbfs_file v2.9.
    """
    def __init__(self, iso_path: str, output_dir: str, verbose: bool = False):
        self.iso_path = Path(iso_path)
        self.output_dir = Path(output_dir)
        if verbose:
            logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')
        else:
            logging.basicConfig(level=logging.INFO, format='%(message)s')

        if not self.iso_path.is_file():
            raise FileNotFoundError(f"ISO file not found: {self.iso_path}")

        self.iso_file = None
        self.disc_key = None
        self.usage_table = bytearray(MAX_WII_SECTORS)

    def _aes_decrypt(self, key: bytes, iv: bytes, data: bytes) -> bytes:
        """Performs AES-128-CBC decryption."""
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()

    def _decrypt_title_key(self, ticket: bytes) -> bytes:
        """Decrypts the title key from the ticket using the Wii common key."""
        iv = ticket[0x1DC:0x1DC + 8] + b'\x00' * 8
        encrypted_key = ticket[0x1BF:0x1BF + 16]
        log.debug(f"Decrypting Title Key with IV: {iv.hex()}")
        return self._aes_decrypt(WII_COMMON_KEY, iv, encrypted_key)

    def _read_iso_data(self, offset: int, size: int) -> bytes:
        """Reads raw data from the ISO file."""
        self.iso_file.seek(offset)
        return self.iso_file.read(size)

    def _read_iso_partition_data(self, part_offset: int, offset: int, size: int) -> bytes:
        """Reads and decrypts data from a specific partition."""
        data = bytearray()
        while size > 0:
            block_index = offset // 0x7C00
            offset_in_block = offset % 0x7C00

            block_offset = part_offset + self.part_data_offset + (block_index * WII_SECTOR_SIZE)
            raw_block = self._read_iso_data(block_offset, WII_SECTOR_SIZE)

            # Mark sector as used for the usage table
            usage_index = block_offset // WII_SECTOR_SIZE
            if usage_index < len(self.usage_table):
                self.usage_table[usage_index] = 1

            iv = raw_block[0x3D0:0x3D0 + 16]
            encrypted_data = raw_block[0x400:0x400 + 0x7C00]
            decrypted_block = self._aes_decrypt(self.disc_key, iv, encrypted_data)

            read_len = min(size, 0x7C00 - offset_in_block)
            data.extend(decrypted_block[offset_in_block : offset_in_block + read_len])

            offset += read_len
            size -= read_len
        return bytes(data)

    def _traverse_fst(self, part_offset: int, fst_data: bytes):
        """Recursively traverses the File System Table to build the usage table."""
        num_entries = struct.unpack('>I', fst_data[8:12])[0]
        log.debug(f"FST has {num_entries} entries.")

        for i in range(1, num_entries):
            entry_offset = i * 12
            entry = fst_data[entry_offset : entry_offset + 12]
            is_dir = entry[0] == 1

            if not is_dir:
                file_offset = struct.unpack('>I', entry[4:8])[0]
                file_size = struct.unpack('>I', entry[8:12])[0]
                self._read_iso_partition_data(part_offset, file_offset * 4, file_size)

    def _build_disc_usage_table(self):
        """
        Parses the ISO to determine which sectors contain actual data,
        populating self.usage_table. This is the "scrubbing" process.
        """
        log.info("Building disc usage table (scrubbing)...")
        self.iso_file.seek(0)

        # Mark essential boot sectors as used
        self.usage_table[0] = 1 # Boot block
        self.usage_table[0x40000 // WII_SECTOR_SIZE] = 1 # Partition table info
        self.usage_table[0x4E000 // WII_SECTOR_SIZE] = 1 # Region info

        # Read partition table
        part_table_info = self._read_iso_data(0x40000, 0x20)
        num_partitions, part_table_offset = struct.unpack('>II', part_table_info[:8])
        part_table_offset *= 4

        log.debug(f"Found {num_partitions} partitions at offset {part_table_offset:#x}")

        part_info_data = self._read_iso_data(part_table_offset, num_partitions * 8)

        for i in range(num_partitions):
            part_offset, part_type = struct.unpack('>II', part_info_data[i*8 : i*8+8])
            part_offset *= 4

            log.info(f"Analyzing Partition {i}: type={part_type}, offset={part_offset:#x}")

            ticket = self._read_iso_data(part_offset, 0x2A4)
            self.disc_key = self._decrypt_title_key(ticket)
            log.debug(f"Decrypted Disc Key for partition {i}: {self.disc_key.hex()}")

            part_header = self._read_iso_data(part_offset + 0x2A4, 0x1C)
            self.part_data_offset = struct.unpack('>I', part_header[0x14:0x18])[0] * 4

            part_main_header = self._read_iso_partition_data(part_offset, 0, 0x480)
            fst_offset, fst_size = struct.unpack('>II', part_main_header[0x424:0x42C])
            fst_offset *= 4
            fst_size *= 4

            log.debug(f"FST located at offset {fst_offset:#x} with size {fst_size:#x}")
            fst_data = self._read_iso_partition_data(part_offset, fst_offset, fst_size)

            self._traverse_fst(part_offset, fst_data)

    def convert(self):
        """Main conversion process."""
        try:
            self.iso_file = open(self.iso_path, 'rb')

            iso_header = self._read_iso_data(0, 0x100)
            game_id = iso_header[:6].decode('ascii')

            title = iso_header[0x20:0x60].decode('ascii', errors='ignore').strip('\x00').strip()
            for char in INVALID_PATH_CHARS:
                title = title.replace(char, '_')

            output_name = f"{title} [{game_id}]"
            final_dir = self.output_dir / output_name
            final_dir.mkdir(parents=True, exist_ok=True)
            wbfs_base_path = final_dir / game_id

            log.info(f"Game: '{title}' ({game_id})")
            log.info(f"Output will be in: {final_dir}")

            self._build_disc_usage_table()

            writer = SplitWbfsWriter(wbfs_base_path, SPLIT_SIZE_4GB_MINUS_32KB)

            hd_sector_size = 512
            wbfs_block_size_shift = 6
            wii_sec_per_wbfs_sec = 1 << wbfs_block_size_shift
            wbfs_sec_sz_s = wbfs_block_size_shift + 15
            wbfs_sec_sz = 1 << wbfs_sec_sz_s

            # --- FIX: Determine accurate number of blocks to process ---
            last_used_wii_sector = -1
            for i in range(len(self.usage_table) - 1, -1, -1):
                if self.usage_table[i]:
                    last_used_wii_sector = i
                    break

            single_layer_wbfs_blocks = SINGLE_LAYER_WII_SECTORS >> wbfs_block_size_shift
            if last_used_wii_sector < SINGLE_LAYER_WII_SECTORS:
                log.debug(f"Single-layer disc detected. Processing {single_layer_wbfs_blocks} blocks.")
                total_blocks_to_process = single_layer_wbfs_blocks
            else:
                dual_layer_wbfs_blocks = MAX_WII_SECTORS >> wbfs_block_size_shift
                log.debug(f"Dual-layer disc detected. Processing {dual_layer_wbfs_blocks} blocks.")
                total_blocks_to_process = dual_layer_wbfs_blocks

            log.info("Converting ISO to WBFS format...")

            disc_info = bytearray(0x100 + (MAX_WII_SECTORS >> wbfs_block_size_shift) * 2)
            disc_info[:0x100] = iso_header
            wlba_table_offset = 0x100

            free_block_allocator = 1

            progress_bar = None
            if TQDM_AVAILABLE:
                progress_bar = tqdm(total=total_blocks_to_process, unit="block", desc="Converting")

            for i in range(total_blocks_to_process):
                if progress_bar: progress_bar.update(1)

                start_sec = i * wii_sec_per_wbfs_sec
                end_sec = start_sec + wii_sec_per_wbfs_sec

                is_used = any(self.usage_table[j] for j in range(start_sec, end_sec))

                if is_used:
                    block_addr = free_block_allocator
                    free_block_allocator += 1

                    struct.pack_into('>H', disc_info, wlba_table_offset + i * 2, block_addr)

                    iso_offset = start_sec * WII_SECTOR_SIZE
                    wbfs_block_data = self._read_iso_data(iso_offset, wbfs_sec_sz)

                    wbfs_offset = block_addr * wbfs_sec_sz
                    writer.write(wbfs_offset, wbfs_block_data)
                else:
                    struct.pack_into('>H', disc_info, wlba_table_offset + i * 2, 0)

            if progress_bar: progress_bar.close()

            writer.write(hd_sector_size, disc_info)

            wbfs_head = bytearray(hd_sector_size)
            n_hd_sec = (free_block_allocator * wbfs_sec_sz) // hd_sector_size
            struct.pack_into('>I', wbfs_head, 0, WBFS_MAGIC)
            struct.pack_into('>I', wbfs_head, 4, n_hd_sec)
            struct.pack_into('B', wbfs_head, 8, 9) # log2(512)
            struct.pack_into('B', wbfs_head, 9, wbfs_sec_sz_s)
            wbfs_head[12] = 1 # Mark disc slot 0 as used
            writer.write(0, wbfs_head)

            final_size = free_block_allocator * wbfs_sec_sz
            writer.truncate(final_size)

        finally:
            if self.iso_file:
                self.iso_file.close()
            if 'writer' in locals() and writer:
                writer.close()

        log.info("Conversion complete!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Convert a Wii ISO to a split WBFS file, replicating wbfs_file v2.9 default behavior.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("iso_path", help="Path to the input Wii ISO file.")
    parser.add_argument("output_dir", help="Directory to save the WBFS file(s). Will be created if it doesn't exist.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable detailed debug logging.")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    try:
        converter = WbfsConverter(args.iso_path, args.output_dir, args.verbose)
        converter.convert()
    except (FileNotFoundError, FileExistsError, Exception) as e:
        log.error(f"An error occurred: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
