// SPDX-FileCopyrightText: 2025 Manuel Quarneti <mq1@ik.me>
// SPDX-License-Identifier: GPL-2.0-only

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use aes::Aes128;
use cbc::Decryptor;
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::NoPadding};
use log::{debug, error, info};
use thiserror::Error;

// --- Constants ---
const WII_SECTOR_SIZE: u64 = 0x8000; // 32 KB
const WBFS_MAGIC: u32 = 0x5742_4653; // "WBFS"
const SPLIT_SIZE_4GB_MINUS_32KB: u64 = (4 * 1024 * 1024 * 1024) - (32 * 1024);
const WII_COMMON_KEY: [u8; 16] = [
    0xeb, 0xe4, 0x2a, 0x22, 0x5e, 0x85, 0x93, 0xe4, 0x48, 0xd9, 0xc5, 0x45, 0x73, 0x81, 0xaa, 0xf7,
];
const INVALID_PATH_CHARS: &[char] = &['/', '\\', ':', '|', '<', '>', '?', '*', '"', '\''];
const MAX_WII_SECTORS: usize = 143_432 * 2; // Dual Layer

// --- ISO Offsets and Sizes ---
const PARTITION_TABLE_OFFSET: u64 = 0x40000;
const PARTITION_INFO_SIZE: usize = 0x20;
const PARTITION_HEADER_SIZE: usize = 0x1C;
const PARTITION_TICKET_SIZE: usize = 0x2A4;
const PARTITION_DATA_OFFSET_IN_HEADER: usize = 0x14;
const PARTITION_MAIN_HEADER_SIZE: u64 = 0x480;
const FST_OFFSET_IN_PARTITION_HEADER: usize = 0x424;
const DOL_OFFSET_IN_PARTITION_HEADER: usize = 0x420;
const H3_TABLE_OFFSET_IN_HEADER: usize = 0x10;
const H3_TABLE_SIZE: u64 = 0x18000;

// --- Custom Error Type ---
#[derive(Error, Debug)]
pub enum WbfsError {
    #[error("I/O Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Output file already exists: {0}")]
    FileExists(String),
    #[error("Invalid Input file: {0}")]
    InvalidInput(String),
    #[error("Cryptography error: {0}")]
    Crypto(String),
    #[error("Ran out of allocatable WBFS blocks")]
    PartitionFull,
    #[error("Conversion error: {0}")]
    ConversionError(#[from] std::num::TryFromIntError),
    #[error("Slice conversion error: {0}")]
    SliceError(#[from] std::array::TryFromSliceError),
}

// --- Input Type Enum ---
enum InputType {
    Iso,
    Wbfs,
}

// --- Split File Writer ---
pub struct SplitWbfsWriter {
    file_handles: HashMap<usize, BufWriter<File>>,
    base_path: PathBuf,
    split_size: u64,
}

impl SplitWbfsWriter {
    /// # Errors
    ///
    /// This function will return an error if the file cannot be created.
    pub fn new(path: impl AsRef<Path>, split_size: u64) -> Result<Self, WbfsError> {
        let path = path.as_ref();
        let mut file_handles = HashMap::new();

        if split_size == 0 {
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(path)?;
            file_handles.insert(0, BufWriter::new(file));
        }

        Ok(Self {
            file_handles,
            base_path: path.to_path_buf(),
            split_size,
        })
    }

    fn get_file(&mut self, offset: u64) -> Result<(&mut BufWriter<File>, u64), WbfsError> {
        let file_index = usize::try_from(offset / self.split_size)?;
        let relative_offset = offset % self.split_size;

        if !self.file_handles.contains_key(&file_index) {
            let path = if file_index == 0 {
                self.base_path.clone()
            } else {
                self.base_path.with_extension(format!("wbf{file_index}"))
            };
            debug!("Opening split file for writing: {}", path.display());
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(path)?;
            self.file_handles.insert(file_index, BufWriter::new(file));
        }

        Ok((
            self.file_handles.get_mut(&file_index).unwrap(),
            relative_offset,
        ))
    }

    fn write(&mut self, mut offset: u64, mut data: &[u8]) -> Result<(), WbfsError> {
        let split_size = self.split_size;
        while !data.is_empty() {
            let (fh, rel_offset) = self.get_file(offset)?;
            fh.seek(SeekFrom::Start(rel_offset))?;

            let writable_len = usize::try_from(split_size - rel_offset)?;
            let chunk = &data[..std::cmp::min(data.len(), writable_len)];
            fh.write_all(chunk)?;

            data = &data[chunk.len()..];
            offset += chunk.len() as u64;
        }
        Ok(())
    }

    fn truncate(&mut self, total_size: u64) -> Result<(), WbfsError> {
        let mut remaining_size = total_size;
        let mut keys: Vec<_> = self.file_handles.keys().copied().collect();
        keys.sort_unstable();

        for i in keys {
            let fh = self.file_handles.get_mut(&i).unwrap();
            fh.flush()?;
            let chunk_size = std::cmp::min(remaining_size, self.split_size);
            debug!("Truncating file index {i} to {chunk_size} bytes.");
            fh.get_mut().set_len(chunk_size)?;
            remaining_size -= chunk_size;
            if remaining_size == 0 {
                break;
            }
        }
        Ok(())
    }
}

impl Drop for SplitWbfsWriter {
    fn drop(&mut self) {
        for (idx, mut fh) in self.file_handles.drain() {
            if let Err(e) = fh.flush() {
                error!("Failed to flush file handle for split {idx}: {e}");
            }
        }
    }
}

// --- Split File Reader ---
pub struct SplitWbfsReader {
    file_handles: HashMap<usize, BufReader<File>>,
    base_path: PathBuf,
    split_sizes: Vec<u64>,
    total_size: u64,
    current_pos: u64,
}

impl SplitWbfsReader {
    /// # Errors
    ///
    /// This function will return an error if the file cannot be opened.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, WbfsError> {
        let path = path.as_ref();
        let mut split_sizes = Vec::new();
        let mut total_size = 0;

        let base_file = File::open(path)?;
        let metadata = base_file.metadata()?;
        let size = metadata.len();
        if size == 0 {
            return Err(WbfsError::InvalidInput("WBFS file is empty".to_string()));
        }
        split_sizes.push(size);
        total_size += size;

        for i in 1.. {
            let split_path = path.with_extension(format!("wbf{i}"));
            if let Ok(metadata) = std::fs::metadata(&split_path) {
                let size = metadata.len();
                split_sizes.push(size);
                total_size += size;
            } else {
                break;
            }
        }

        Ok(Self {
            file_handles: HashMap::new(),
            base_path: path.to_path_buf(),
            split_sizes,
            total_size,
            current_pos: 0,
        })
    }
}

impl Read for SplitWbfsReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.current_pos >= self.total_size {
            return Ok(0);
        }

        let mut offset_accumulator = 0;
        let mut split_index = 0;
        let mut current_split_size = 0;

        for (i, &size) in self.split_sizes.iter().enumerate() {
            if self.current_pos < offset_accumulator + size {
                split_index = i;
                current_split_size = size;
                break;
            }
            offset_accumulator += size;
        }

        let relative_offset = self.current_pos - offset_accumulator;

        if !self.file_handles.contains_key(&split_index) {
            let path = if split_index == 0 {
                self.base_path.clone()
            } else {
                self.base_path.with_extension(format!("wbf{split_index}"))
            };
            let file = File::open(path)?;
            self.file_handles.insert(split_index, BufReader::new(file));
        }
        let fh = self.file_handles.get_mut(&split_index).unwrap();
        fh.seek(SeekFrom::Start(relative_offset))?;

        let readable_len = current_split_size - relative_offset;
        let read_len = usize::try_from(std::cmp::min(buf.len() as u64, readable_len))
            .map_err(io::Error::other)?;
        let bytes_read = fh.read(&mut buf[..read_len])?;

        self.current_pos += bytes_read as u64;
        Ok(bytes_read)
    }
}

impl Seek for SplitWbfsReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let invalid_seek = || io::Error::new(io::ErrorKind::InvalidInput, "invalid seek");

        let new_pos = match pos {
            SeekFrom::Start(p) => i64::try_from(p).map_err(|_| invalid_seek()),
            SeekFrom::End(p) => i64::try_from(self.total_size)
                .map_err(|_| invalid_seek())
                .and_then(|total_size| total_size.checked_add(p).ok_or_else(invalid_seek)),
            SeekFrom::Current(p) => i64::try_from(self.current_pos)
                .map_err(|_| invalid_seek())
                .and_then(|current_pos| current_pos.checked_add(p).ok_or_else(invalid_seek)),
        }?;

        if new_pos < 0 {
            return Err(invalid_seek());
        }

        self.current_pos = u64::try_from(new_pos).map_err(|_| invalid_seek())?;
        Ok(self.current_pos)
    }
}

// --- Main Converter Struct ---
/// A converter for Wii ISO or WBFS files to WBFS format.
pub struct WbfsConverter {
    input_path: PathBuf,
    output_dir: PathBuf,
    input_type: InputType,
}

struct IsoProcessor {
    iso_file: BufReader<File>,
    disc_key: [u8; 16],
    usage_table: Vec<bool>,
    part_data_offset: u64,
    sector_buffer: Vec<u8>,
    decrypted_buffer: Vec<u8>,
}

impl WbfsConverter {
    /// Creates a new `WbfsConverter` instance.
    ///
    /// # Arguments
    /// * `input_path` - Path to the input ISO or WBFS file
    /// * `output_dir` - Directory where the output WBFS file will be created
    ///
    /// # Errors
    /// Returns `WbfsError::IoError` if the input file cannot be opened or read
    pub fn new(
        input_path: impl AsRef<Path>,
        output_dir: impl AsRef<Path>,
    ) -> Result<Self, WbfsError> {
        let input_path = input_path.as_ref();
        let extension = input_path
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or("");

        let input_type = match extension.to_lowercase().as_str() {
            "iso" => InputType::Iso,
            "wbfs" => InputType::Wbfs,
            _ => {
                return Err(WbfsError::InvalidInput(
                    "Unsupported file type, expected .iso or .wbfs".to_string(),
                ));
            }
        };

        Ok(Self {
            input_path: input_path.to_path_buf(),
            output_dir: output_dir.as_ref().to_path_buf(),
            input_type,
        })
    }

    fn aes_decrypt(key: &[u8; 16], iv: &[u8; 16], data: &mut [u8]) -> Result<(), WbfsError> {
        let dec = Decryptor::<Aes128>::new_from_slices(key, iv)
            .map_err(|e| WbfsError::Crypto(e.to_string()))?;

        dec.decrypt_padded_mut::<NoPadding>(data)
            .map_err(|e| WbfsError::Crypto(e.to_string()))?;
        Ok(())
    }

    fn decrypt_title_key(ticket: &[u8]) -> Result<[u8; 16], WbfsError> {
        let mut iv = [0u8; 16];
        iv[..8].copy_from_slice(&ticket[0x1DC..0x1DC + 8]);
        let mut encrypted_key = ticket[0x1BF..0x1BF + 16].to_vec();

        debug!("Decrypting Title Key with IV: {}", hex::encode(iv));
        Self::aes_decrypt(&WII_COMMON_KEY, &iv, &mut encrypted_key)?;

        let mut key = [0u8; 16];
        key.copy_from_slice(&encrypted_key);
        Ok(key)
    }

    /// The main conversion method.
    ///
    /// Converts the input file to a split WBFS format.
    ///
    /// # Errors
    ///
    /// Returns an error if any I/O operation fails or if the input is not a valid Wii disc/WBFS file.
    pub fn convert(&self) -> Result<(), WbfsError> {
        match self.input_type {
            InputType::Iso => self.convert_from_iso(),
            InputType::Wbfs => self.convert_from_wbfs(),
        }
    }

    fn convert_from_iso(&self) -> Result<(), WbfsError> {
        let sector_size = usize::try_from(WII_SECTOR_SIZE)?;
        let mut processor = IsoProcessor {
            iso_file: BufReader::new(File::open(&self.input_path)?),
            disc_key: [0; 16],
            usage_table: vec![false; MAX_WII_SECTORS],
            part_data_offset: 0,
            sector_buffer: vec![0; sector_size],
            decrypted_buffer: vec![0; sector_size],
        };

        processor.build_disc_usage_table()?;

        let iso_header = processor.read_iso_data(0, 0x100)?.to_vec();
        let game_id = String::from_utf8_lossy(&iso_header[..6]).to_string();
        let mut title: String = String::from_utf8_lossy(&iso_header[0x20..0x60])
            .trim_end_matches('\0')
            .trim()
            .to_string();
        title.retain(|c| !INVALID_PATH_CHARS.contains(&c));

        let output_name = format!("{title} [{game_id}]");
        let final_dir = self.output_dir.join(&output_name);
        std::fs::create_dir_all(&final_dir)?;
        let wbfs_base_path = final_dir.join(&game_id).with_extension("wbfs");

        info!("Game: '{title}' ({game_id})");
        info!("Output will be in: {}", final_dir.display());

        let mut writer = SplitWbfsWriter::new(wbfs_base_path, SPLIT_SIZE_4GB_MINUS_32KB)?;

        let hd_sector_size = 512u64;
        let wbfs_block_size_shift = 6;
        let wii_sec_per_wbfs_sec = 1 << wbfs_block_size_shift;
        let wbfs_sec_sz_s = wbfs_block_size_shift + 15;
        let wbfs_sec_sz = 1u64 << wbfs_sec_sz_s;

        let total_blocks_to_process = MAX_WII_SECTORS >> wbfs_block_size_shift;
        debug!("Processing {total_blocks_to_process} blocks for dual-layer compatibility.");

        let mut disc_info = vec![0u8; 0x100 + (MAX_WII_SECTORS >> wbfs_block_size_shift) * 2];
        disc_info[..0x100].copy_from_slice(&iso_header);
        let wlba_table_offset = 0x100;

        let mut free_block_allocator = 1u16;

        let mut wbfs_block_buffer = vec![0; usize::try_from(wbfs_sec_sz)?];

        for i in 0..total_blocks_to_process {
            let start_sec = i * wii_sec_per_wbfs_sec;
            let end_sec = start_sec + wii_sec_per_wbfs_sec;
            let mut used = false;
            for k in start_sec..std::cmp::min(end_sec, MAX_WII_SECTORS) {
                if processor.usage_table[k] {
                    used = true;
                    break;
                }
            }

            if used {
                let block_addr = free_block_allocator;
                free_block_allocator += 1;
                if free_block_allocator == 0 {
                    return Err(WbfsError::PartitionFull);
                }

                disc_info[wlba_table_offset + i * 2..wlba_table_offset + i * 2 + 2]
                    .copy_from_slice(&block_addr.to_be_bytes());

                let iso_offset = (start_sec as u64) * WII_SECTOR_SIZE;

                processor.iso_file.seek(SeekFrom::Start(iso_offset))?;
                processor.iso_file.read_exact(&mut wbfs_block_buffer)?;

                let wbfs_offset = u64::from(block_addr) * wbfs_sec_sz;
                writer.write(wbfs_offset, &wbfs_block_buffer)?;
            } else {
                disc_info[wlba_table_offset + i * 2..wlba_table_offset + i * 2 + 2]
                    .copy_from_slice(&0u16.to_be_bytes());
            }
        }

        writer.write(hd_sector_size, &disc_info)?;

        let mut wbfs_head = vec![0u8; usize::try_from(hd_sector_size)?];
        let n_hd_sec = (u64::from(free_block_allocator) * wbfs_sec_sz) / hd_sector_size;
        wbfs_head[0..4].copy_from_slice(&WBFS_MAGIC.to_be_bytes());
        wbfs_head[4..8].copy_from_slice(&u32::try_from(n_hd_sec)?.to_be_bytes());
        wbfs_head[8] = 9; // log2(512)
        wbfs_head[9] = u8::try_from(wbfs_sec_sz_s)?;
        wbfs_head[12] = 1; // Mark disc slot 0 as used
        writer.write(0, &wbfs_head)?;

        let final_size = u64::from(free_block_allocator) * wbfs_sec_sz;
        writer.truncate(final_size)?;

        info!("Conversion complete!");
        Ok(())
    }

    fn convert_from_wbfs(&self) -> Result<(), WbfsError> {
        info!("Re-splitting WBFS file: {}", self.input_path.display());
        let mut reader = SplitWbfsReader::new(&self.input_path)?;

        let mut src_header_buf = vec![0; 512];
        reader.read_exact(&mut src_header_buf)?;

        if src_header_buf[0..4] != WBFS_MAGIC.to_be_bytes() {
            return Err(WbfsError::InvalidInput("Invalid WBFS magic".to_string()));
        }
        let wbfs_sec_sz_s = src_header_buf[9];
        let wbfs_sec_sz = 1u64 << wbfs_sec_sz_s;
        let wbfs_block_size_shift = wbfs_sec_sz_s - 15;
        let wii_sec_per_wbfs_sec = 1 << wbfs_block_size_shift;

        let disc_info_size = 0x100 + (MAX_WII_SECTORS / wii_sec_per_wbfs_sec) * 2;
        let mut src_disc_info_buf = vec![0; disc_info_size];
        reader.seek(SeekFrom::Start(512))?;
        reader.read_exact(&mut src_disc_info_buf)?;

        let iso_header = &src_disc_info_buf[..0x100];
        let game_id = String::from_utf8_lossy(&iso_header[..6]).to_string();
        let mut title: String = String::from_utf8_lossy(&iso_header[0x20..0x60])
            .trim_end_matches('\0')
            .trim()
            .to_string();
        title.retain(|c| !INVALID_PATH_CHARS.contains(&c));

        let output_name = format!("{title} [{game_id}]");
        let final_dir = self.output_dir.join(&output_name);
        std::fs::create_dir_all(&final_dir)?;
        let wbfs_base_path = final_dir.join(&game_id).with_extension("wbfs");

        info!("Game: '{title}' ({game_id})");
        info!("Output will be in: {}", final_dir.display());

        let mut writer = SplitWbfsWriter::new(wbfs_base_path, SPLIT_SIZE_4GB_MINUS_32KB)?;

        let mut dest_disc_info_buf = vec![0; disc_info_size];
        dest_disc_info_buf[..0x100].copy_from_slice(iso_header);

        let src_wlba_table = &src_disc_info_buf[0x100..];
        let mut dest_block_allocator = 1u16;
        let mut wbfs_block_buffer = vec![0; usize::try_from(wbfs_sec_sz)?];

        for i in 0..(disc_info_size - 0x100) / 2 {
            let src_wlba = u16::from_be_bytes(src_wlba_table[i * 2..i * 2 + 2].try_into()?);

            if src_wlba > 0 {
                let dest_wlba = dest_block_allocator;
                dest_block_allocator += 1;
                if dest_block_allocator == 0 {
                    return Err(WbfsError::PartitionFull);
                }

                dest_disc_info_buf[0x100 + i * 2..0x100 + i * 2 + 2]
                    .copy_from_slice(&dest_wlba.to_be_bytes());

                let src_offset = u64::from(src_wlba) * wbfs_sec_sz;
                reader.seek(SeekFrom::Start(src_offset))?;
                reader.read_exact(&mut wbfs_block_buffer)?;

                let dest_offset = u64::from(dest_wlba) * wbfs_sec_sz;
                writer.write(dest_offset, &wbfs_block_buffer)?;
            } else {
                dest_disc_info_buf[0x100 + i * 2..0x100 + i * 2 + 2]
                    .copy_from_slice(&0u16.to_be_bytes());
            }
        }

        writer.write(512, &dest_disc_info_buf)?;

        let mut wbfs_head = vec![0u8; 512];
        let n_hd_sec = (u64::from(dest_block_allocator) * wbfs_sec_sz) / 512;
        wbfs_head[0..4].copy_from_slice(&WBFS_MAGIC.to_be_bytes());
        wbfs_head[4..8].copy_from_slice(&u32::try_from(n_hd_sec)?.to_be_bytes());
        wbfs_head[8] = 9;
        wbfs_head[9] = wbfs_sec_sz_s;
        wbfs_head[12] = 1;
        writer.write(0, &wbfs_head)?;

        let final_size = u64::from(dest_block_allocator) * wbfs_sec_sz;
        writer.truncate(final_size)?;

        info!("Conversion complete!");
        Ok(())
    }
}

impl IsoProcessor {
    fn read_iso_data(&mut self, offset: u64, size: usize) -> Result<&[u8], WbfsError> {
        self.iso_file.seek(SeekFrom::Start(offset))?;
        let buffer = &mut self.sector_buffer[..size];
        self.iso_file.read_exact(buffer)?;
        Ok(buffer)
    }

    fn mark_iso_sectors_used(&mut self, offset: u64, size: u64) {
        let start_sector = (offset / WII_SECTOR_SIZE) as usize;
        let end_sector = usize::try_from((offset + size).div_ceil(WII_SECTOR_SIZE))
            .expect("sector count should fit in usize");

        for i in start_sector..end_sector {
            if i < self.usage_table.len() {
                self.usage_table[i] = true;
            }
        }
    }

    fn read_and_decrypt_partition_data(
        &mut self,
        part_offset: u64,
        mut offset: u64,
        mut size: u64,
        output_buf: &mut Vec<u8>,
    ) -> Result<(), WbfsError> {
        output_buf.clear();
        output_buf.reserve(usize::try_from(size)?);

        while size > 0 {
            let block_index = offset / 0x7C00;
            let offset_in_block = (offset % 0x7C00) as usize;

            let block_offset =
                part_offset + self.part_data_offset + (block_index * WII_SECTOR_SIZE);

            self.iso_file.seek(SeekFrom::Start(block_offset))?;
            self.iso_file.read_exact(&mut self.sector_buffer)?;

            let iv: [u8; 16] = self.sector_buffer[0x3D0..0x3D0 + 16].try_into()?;
            let encrypted_data = &mut self.sector_buffer[0x400..0x400 + 0x7C00];

            self.decrypted_buffer[..0x7C00].copy_from_slice(encrypted_data);
            WbfsConverter::aes_decrypt(&self.disc_key, &iv, &mut self.decrypted_buffer[..0x7C00])?;

            let read_len = std::cmp::min(usize::try_from(size)?, 0x7C00 - offset_in_block);
            output_buf.extend_from_slice(
                &self.decrypted_buffer[offset_in_block..offset_in_block + read_len],
            );

            offset += read_len as u64;
            size -= read_len as u64;
        }
        Ok(())
    }

    fn mark_used_partition_sectors(
        &mut self,
        part_offset: u64,
        mut offset: u64,
        mut size: u64,
    ) -> Result<(), WbfsError> {
        while size > 0 {
            let block_index = offset / 0x7C00;
            let offset_in_block = (offset % 0x7C00) as usize;

            let block_offset =
                part_offset + self.part_data_offset + (block_index * WII_SECTOR_SIZE);

            self.mark_iso_sectors_used(block_offset, WII_SECTOR_SIZE);

            let read_len = std::cmp::min(usize::try_from(size)?, 0x7C00 - offset_in_block);
            offset += read_len as u64;
            size -= read_len as u64;
        }
        Ok(())
    }

    fn traverse_fst(&mut self, part_offset: u64, fst_data: &[u8]) -> Result<(), WbfsError> {
        let num_entries = u32::from_be_bytes(fst_data[8..12].try_into()?);
        debug!("FST has {num_entries} entries.");

        for i in 1..num_entries {
            let entry_offset = (i * 12) as usize;
            let entry = &fst_data[entry_offset..entry_offset + 12];
            let is_dir = entry[0] == 1;

            if !is_dir {
                let file_offset = u32::from_be_bytes(entry[4..8].try_into()?);
                let file_size = u32::from_be_bytes(entry[8..12].try_into()?);

                self.mark_used_partition_sectors(
                    part_offset,
                    u64::from(file_offset) * 4,
                    u64::from(file_size),
                )?;
            }
        }
        Ok(())
    }

    fn process_partition(
        &mut self,
        part_offset: u64,
        part_type: u32,
        i: u32,
    ) -> Result<(), WbfsError> {
        info!("Analyzing Partition {i}: type={part_type}, offset={part_offset:#x}");

        self.mark_iso_sectors_used(
            part_offset,
            (PARTITION_TICKET_SIZE + PARTITION_HEADER_SIZE) as u64,
        );

        let ticket = self
            .read_iso_data(part_offset, PARTITION_TICKET_SIZE)?
            .to_vec();
        self.disc_key = WbfsConverter::decrypt_title_key(&ticket)?;
        debug!(
            "Decrypted Disc Key for partition {}: {}",
            i,
            hex::encode(self.disc_key)
        );

        let part_header = self
            .read_iso_data(
                part_offset + PARTITION_TICKET_SIZE as u64,
                PARTITION_HEADER_SIZE,
            )?
            .to_vec();
        let tmd_size = u64::from(u32::from_be_bytes(part_header[0..4].try_into()?));
        let tmd_offset = u64::from(u32::from_be_bytes(part_header[4..8].try_into()?)) * 4;
        let cert_chain_size = u64::from(u32::from_be_bytes(part_header[8..12].try_into()?));
        let cert_chain_offset = u64::from(u32::from_be_bytes(part_header[12..16].try_into()?)) * 4;
        let h3_offset = u64::from(u32::from_be_bytes(
            part_header[H3_TABLE_OFFSET_IN_HEADER..H3_TABLE_OFFSET_IN_HEADER + 4].try_into()?,
        )) * 4;
        self.part_data_offset = u64::from(u32::from_be_bytes(
            part_header[PARTITION_DATA_OFFSET_IN_HEADER..PARTITION_DATA_OFFSET_IN_HEADER + 4]
                .try_into()?,
        )) * 4;

        self.mark_iso_sectors_used(part_offset + tmd_offset, tmd_size);
        self.mark_iso_sectors_used(part_offset + cert_chain_offset, cert_chain_size);
        self.mark_iso_sectors_used(part_offset + h3_offset, H3_TABLE_SIZE);

        self.mark_used_partition_sectors(part_offset, 0, PARTITION_MAIN_HEADER_SIZE)?;
        let mut part_main_header = Vec::new();
        self.read_and_decrypt_partition_data(
            part_offset,
            0,
            PARTITION_MAIN_HEADER_SIZE,
            &mut part_main_header,
        )?;

        let dol_offset = u64::from(u32::from_be_bytes(
            part_main_header[DOL_OFFSET_IN_PARTITION_HEADER..DOL_OFFSET_IN_PARTITION_HEADER + 4]
                .try_into()?,
        )) * 4;
        let fst_offset = u64::from(u32::from_be_bytes(
            part_main_header[FST_OFFSET_IN_PARTITION_HEADER..FST_OFFSET_IN_PARTITION_HEADER + 4]
                .try_into()?,
        )) * 4;
        let fst_size = u64::from(u32::from_be_bytes(
            part_main_header
                [FST_OFFSET_IN_PARTITION_HEADER + 4..FST_OFFSET_IN_PARTITION_HEADER + 8]
                .try_into()?,
        )) * 4;

        self.mark_used_partition_sectors(part_offset, dol_offset, fst_offset - dol_offset)?;
        self.mark_used_partition_sectors(part_offset, fst_offset, fst_size)?;

        debug!("FST located at offset {fst_offset:#x} with size {fst_size:#x}");
        let mut fst_data = Vec::new();
        self.read_and_decrypt_partition_data(part_offset, fst_offset, fst_size, &mut fst_data)?;
        self.traverse_fst(part_offset, &fst_data)?;
        Ok(())
    }

    fn build_disc_usage_table(&mut self) -> Result<(), WbfsError> {
        info!("Building disc usage table (scrubbing)...");
        self.mark_iso_sectors_used(0, WII_SECTOR_SIZE);
        self.mark_iso_sectors_used(PARTITION_TABLE_OFFSET, WII_SECTOR_SIZE);
        self.mark_iso_sectors_used(0x4E000, WII_SECTOR_SIZE);

        let part_table_info = self
            .read_iso_data(PARTITION_TABLE_OFFSET, PARTITION_INFO_SIZE)?
            .to_vec();
        let num_partitions = u32::from_be_bytes(part_table_info[0..4].try_into()?);
        let part_table_offset =
            u64::from(u32::from_be_bytes(part_table_info[4..8].try_into()?)) * 4;

        debug!("Found {num_partitions} partitions at offset {part_table_offset:#x}");
        let part_info_data = self
            .read_iso_data(part_table_offset, (num_partitions * 8) as usize)?
            .to_vec();

        for i in 0..num_partitions {
            let offset = (i * 8) as usize;
            let part_offset = u64::from(u32::from_be_bytes(
                part_info_data[offset..offset + 4].try_into()?,
            )) * 4;
            let part_type = u32::from_be_bytes(part_info_data[offset + 4..offset + 8].try_into()?);
            self.process_partition(part_offset, part_type, i)?;
        }
        Ok(())
    }
}
