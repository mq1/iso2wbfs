// SPDX-FileCopyrightText: 2025 Manuel Quarneti <mq1@ik.me>
// SPDX-License-Identifier: GPL-2.0-only

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use aes::Aes128;
use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use cbc::Decryptor;
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
const SINGLE_LAYER_WII_SECTORS: usize = 143_432;

// --- ISO Offsets and Sizes ---
const PARTITION_TABLE_OFFSET: u64 = 0x40000;
const PARTITION_INFO_SIZE: usize = 0x20;
const PARTITION_HEADER_SIZE: usize = 0x1C;
const PARTITION_TICKET_SIZE: usize = 0x2A4;
const PARTITION_DATA_OFFSET_IN_HEADER: usize = 0x14;
const PARTITION_MAIN_HEADER_SIZE: u64 = 0x480;
const FST_OFFSET_IN_PARTITION_HEADER: usize = 0x424;

// --- Custom Error Type ---
#[derive(Error, Debug)]
pub enum WbfsError {
    #[error("I/O Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Output file already exists: {0}")]
    FileExists(String),
    #[error("Invalid ISO file: {0}")]
    InvalidIso(String),
    #[error("Cryptography error: {0}")]
    Crypto(String),
    #[error("Ran out of allocatable WBFS blocks")]
    PartitionFull,
    #[error("Conversion error: {0}")]
    ConversionError(#[from] std::num::TryFromIntError),
    #[error("Slice conversion error: {0}")]
    SliceError(#[from] std::array::TryFromSliceError),
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

// --- Main Converter Struct ---
/// A converter for Wii ISO files to WBFS format.
pub struct WbfsConverter {
    output_dir: PathBuf,
    iso_file: BufReader<File>,
    disc_key: [u8; 16],
    usage_table: Vec<bool>,
    part_data_offset: u64,
    // --- Reusable Buffers for Optimization ---
    sector_buffer: Vec<u8>,
    decrypted_buffer: Vec<u8>,
}

impl WbfsConverter {
    /// Creates a new `WbfsConverter` instance.
    ///
    /// # Arguments
    /// * `iso_path` - Path to the input ISO file
    /// * `output_dir` - Directory where the output WBFS file will be created
    ///
    /// # Errors
    /// Returns `WbfsError::IoError` if the ISO file cannot be opened or read
    pub fn new(iso_path: impl AsRef<Path>, output_dir: impl AsRef<Path>) -> Result<Self, WbfsError> {
        let sector_size = usize::try_from(WII_SECTOR_SIZE)?;
        Ok(Self {
            output_dir: output_dir.as_ref().to_path_buf(),
            iso_file: BufReader::new(File::open(iso_path.as_ref())?),
            disc_key: [0; 16],
            usage_table: vec![false; MAX_WII_SECTORS],
            part_data_offset: 0,
            sector_buffer: vec![0; sector_size],
            decrypted_buffer: vec![0; sector_size],
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

    fn read_iso_data(&mut self, offset: u64, size: usize) -> Result<&[u8], WbfsError> {
        self.iso_file.seek(SeekFrom::Start(offset))?;
        let buffer = &mut self.sector_buffer[..size];
        self.iso_file.read_exact(buffer)?;
        Ok(buffer)
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
            Self::aes_decrypt(&self.disc_key, &iv, &mut self.decrypted_buffer[..0x7C00])?;

            let read_len = std::cmp::min(usize::try_from(size)?, 0x7C00 - offset_in_block);
            output_buf.extend_from_slice(&self.decrypted_buffer[offset_in_block..offset_in_block + read_len]);

            offset += read_len as u64;
            size -= read_len as u64;
        }
        Ok(())
    }

    fn mark_used_sectors(
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

            let usage_index = (block_offset / WII_SECTOR_SIZE) as usize;
            if usage_index < self.usage_table.len() {
                self.usage_table[usage_index] = true;
            }

            let read_len = std::cmp::min(usize::try_from(size)?, 0x7C00 - offset_in_block);
            offset += read_len as u64;
            size -= read_len as u64;
        }
        Ok(())
    }

    fn traverse_fst(
        &mut self,
        part_offset: u64,
        fst_data: &[u8],
    ) -> Result<(), WbfsError> {
        let num_entries = u32::from_be_bytes(fst_data[8..12].try_into()?);
        debug!("FST has {num_entries} entries.");

        for i in 1..num_entries {
            let entry_offset = (i * 12) as usize;
            let entry = &fst_data[entry_offset..entry_offset + 12];
            let is_dir = entry[0] == 1;

            if !is_dir {
                let file_offset = u32::from_be_bytes(entry[4..8].try_into()?);
                let file_size = u32::from_be_bytes(entry[8..12].try_into()?);

                // Mark sectors as used without reading/decrypting file data.
                self.mark_used_sectors(
                    part_offset,
                    u64::from(file_offset) * 4,
                    u64::from(file_size),
                )?;
            }
        }
        Ok(())
    }

    fn process_partition(&mut self, part_offset: u64, part_type: u32, i: u32) -> Result<(), WbfsError> {
        info!(
            "Analyzing Partition {i}: type={part_type}, offset={part_offset:#x}"
        );

        let ticket = self.read_iso_data(part_offset, PARTITION_TICKET_SIZE)?.to_vec();
        self.disc_key = Self::decrypt_title_key(&ticket)?;
        debug!(
            "Decrypted Disc Key for partition {}: {}",
            i,
            hex::encode(self.disc_key)
        );

        let part_header = self.read_iso_data(part_offset + PARTITION_TICKET_SIZE as u64, PARTITION_HEADER_SIZE)?.to_vec();
        self.part_data_offset =
            u64::from(u32::from_be_bytes(part_header[PARTITION_DATA_OFFSET_IN_HEADER..PARTITION_DATA_OFFSET_IN_HEADER + 4].try_into()?)) * 4;

        let mut part_main_header = Vec::new();
        self.read_and_decrypt_partition_data(part_offset, 0, PARTITION_MAIN_HEADER_SIZE, &mut part_main_header)?;

        let fst_offset =
            u64::from(u32::from_be_bytes(part_main_header[FST_OFFSET_IN_PARTITION_HEADER..FST_OFFSET_IN_PARTITION_HEADER + 4].try_into()?)) * 4;
        let fst_size =
            u64::from(u32::from_be_bytes(part_main_header[FST_OFFSET_IN_PARTITION_HEADER + 4..FST_OFFSET_IN_PARTITION_HEADER + 8].try_into()?)) * 4;

        debug!(
            "FST located at offset {fst_offset:#x} with size {fst_size:#x}"
        );
        let mut fst_data = Vec::new();
        self.read_and_decrypt_partition_data(part_offset, fst_offset, fst_size, &mut fst_data)?;
        self.traverse_fst(part_offset, &fst_data)?;
        Ok(())
    }

    fn build_disc_usage_table(&mut self) -> Result<(), WbfsError> {
        info!("Building disc usage table (scrubbing)...");
        self.usage_table[0] = true;
        self.usage_table[(PARTITION_TABLE_OFFSET / WII_SECTOR_SIZE) as usize] = true;
        self.usage_table[(0x4E000 / WII_SECTOR_SIZE) as usize] = true;

        let part_table_info = self.read_iso_data(PARTITION_TABLE_OFFSET, PARTITION_INFO_SIZE)?.to_vec();
        let num_partitions = u32::from_be_bytes(part_table_info[0..4].try_into()?);
        let part_table_offset =
            u64::from(u32::from_be_bytes(part_table_info[4..8].try_into()?)) * 4;

        debug!(
            "Found {num_partitions} partitions at offset {part_table_offset:#x}"
        );
        let part_info_data =
            self.read_iso_data(part_table_offset, (num_partitions * 8) as usize)?.to_vec();

        for i in 0..num_partitions {
            let offset = (i * 8) as usize;
            let part_offset = u64::from(u32::from_be_bytes(
                part_info_data[offset..offset + 4].try_into()?,
            )) * 4;
            let part_type =
                u32::from_be_bytes(part_info_data[offset + 4..offset + 8].try_into()?);
            self.process_partition(part_offset, part_type, i)?;
        }
        Ok(())
    }

    /// The main conversion method.
    ///
    /// Converts the ISO to WBFS format
    ///
    /// # Errors
    ///
    /// Returns an error if any I/O operation fails or if the ISO is not a valid Wii disc
    pub fn convert(&mut self) -> Result<(), WbfsError> {
        // --- Stage 1: Scrubbing ---
        self.build_disc_usage_table()?;

        // --- Stage 2: Conversion ---
        let iso_header = self.read_iso_data(0, 0x100)?.to_vec();
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

        // --- FIX: Determine accurate number of blocks to process ---
        let last_used_wii_sector = self.usage_table.iter().rposition(|&used| used).unwrap_or(0);
        let single_layer_wbfs_blocks = SINGLE_LAYER_WII_SECTORS >> wbfs_block_size_shift;

        let total_blocks_to_process = if last_used_wii_sector < SINGLE_LAYER_WII_SECTORS {
            debug!("Single-layer disc detected. Processing {single_layer_wbfs_blocks} blocks.");
            single_layer_wbfs_blocks
        } else {
            let dual_layer_wbfs_blocks = MAX_WII_SECTORS >> wbfs_block_size_shift;
            debug!("Dual-layer disc detected. Processing {dual_layer_wbfs_blocks} blocks.");
            dual_layer_wbfs_blocks
        };

        let mut disc_info = vec![0u8; 0x100 + (MAX_WII_SECTORS >> wbfs_block_size_shift) * 2];
        disc_info[..0x100].copy_from_slice(&iso_header);
        let wlba_table_offset = 0x100;

        let mut free_block_allocator = 1u16;

        let mut wbfs_block_buffer = vec![0; usize::try_from(wbfs_sec_sz)?];

        for i in 0..total_blocks_to_process {
            let start_sec = i * wii_sec_per_wbfs_sec;
            let end_sec = start_sec + wii_sec_per_wbfs_sec - 1;
            let mut used = false;
            for k in start_sec..=end_sec {
                if self.usage_table[k] {
                    used = true;
                    break;
                }
            }

            if used {
                let block_addr = free_block_allocator;
                free_block_allocator += 1;
                if free_block_allocator == 0 { // overflow
                    return Err(WbfsError::PartitionFull);
                }

                disc_info[wlba_table_offset + i * 2..wlba_table_offset + i * 2 + 2]
                    .copy_from_slice(&block_addr.to_be_bytes());

                let iso_offset = (start_sec as u64) * WII_SECTOR_SIZE;

                self.iso_file.seek(SeekFrom::Start(iso_offset))?;
                self.iso_file.read_exact(&mut wbfs_block_buffer)?;

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
}
