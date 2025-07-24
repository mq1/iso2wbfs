// SPDX-FileCopyrightText: 2025 Manuel Quarneti <mq1@ik.me>
// SPDX-License-Identifier: GPL-2.0-only

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use aes::Aes128;
use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use cbc::Decryptor;
use log::{debug, error, info};
use thiserror::Error;

// --- Type Aliases for Readability ---
type Aes128CbcDec = Decryptor<Aes128>;

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
}



/// Enum to report progress updates from the library to the consumer.
pub enum ProgressUpdate {
    /// Indicates the scrubbing process has started.
    ScrubbingStart,
    /// Indicates the main conversion has started, providing the total number of blocks.
    ConversionStart { total_blocks: u64 },
    /// Reports progress during the main conversion.
    ConversionUpdate { current_block: u64 },
    /// Indicates the entire process is complete.
    Done,
}

// --- Split File Writer (No changes) ---
struct SplitWbfsWriter {
    base_path: PathBuf,
    split_size: u64,
    file_handles: HashMap<usize, File>,
    temp_path: PathBuf,
    final_path: PathBuf,
}

impl SplitWbfsWriter {
    fn new(base_path: PathBuf, split_size: u64) -> Result<Self, WbfsError> {
        let temp_path = base_path.with_extension("wbfs.tmp");
        let final_path = base_path.with_extension("wbfs");

        if temp_path.exists() || final_path.exists() {
            return Err(WbfsError::FileExists(final_path.display().to_string()));
        }

        Ok(Self {
            base_path,
            split_size,
            file_handles: HashMap::new(),
            temp_path,
            final_path,
        })
    }

    fn get_file(&mut self, offset: u64) -> Result<(&mut File, u64), WbfsError> {
        let file_index = usize::try_from(offset / self.split_size)?;
        let relative_offset = offset % self.split_size;

        if !self.file_handles.contains_key(&file_index) {
            let path = if file_index == 0 {
                self.temp_path.clone()
            } else {
                self.base_path.with_extension(format!("wbf{file_index}"))
            };
            debug!("Opening split file for writing: {}", path.display());
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(path)?;
            self.file_handles.insert(file_index, file);
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
            fh.set_len(chunk_size)?;
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
        if self.temp_path.exists() {
            info!(
                "Renaming {} to {}",
                self.temp_path.display(),
                self.final_path.display()
            );
            if let Err(e) = std::fs::rename(&self.temp_path, &self.final_path) {
                error!("Failed to rename temporary file: {e}");
            }
        }
    }
}

// --- Main Converter Struct ---
/// A converter for Wii ISO files to WBFS format.
pub struct WbfsConverter {
    output_dir: PathBuf,
    iso_file: File,
    disc_key: [u8; 16],
    usage_table: Vec<bool>,
    part_data_offset: u64,
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
        Ok(Self {
            output_dir: output_dir.as_ref().to_path_buf(),
            iso_file: File::open(iso_path.as_ref())?,
            disc_key: [0; 16],
            usage_table: vec![false; MAX_WII_SECTORS],
            part_data_offset: 0,
        })
    }

    fn aes_decrypt(key: &[u8; 16], iv: &[u8; 16], data: &mut [u8]) -> Result<(), WbfsError> {
        let dec = Aes128CbcDec::new_from_slices(key, iv)
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

    fn read_iso_data(&mut self, offset: u64, size: usize) -> Result<Vec<u8>, WbfsError> {
        let mut buffer = vec![0; size];
        self.iso_file.seek(SeekFrom::Start(offset))?;
        self.iso_file.read_exact(&mut buffer)?;
        Ok(buffer)
    }

    fn read_iso_partition_data(
        &mut self,
        part_offset: u64,
        mut offset: u64,
        mut size: u64,
    ) -> Result<Vec<u8>, WbfsError> {
        let mut data = Vec::with_capacity(usize::try_from(size)?);
        while size > 0 {
            let block_index = offset / 0x7C00;
            let offset_in_block = (offset % 0x7C00) as usize;

            let block_offset =
            part_offset + self.part_data_offset + (block_index * WII_SECTOR_SIZE);
            let mut raw_block = self.read_iso_data(block_offset, usize::try_from(WII_SECTOR_SIZE)?)?;

            let usage_index = (block_offset / WII_SECTOR_SIZE) as usize;
            if usage_index < self.usage_table.len() {
                self.usage_table[usage_index] = true;
            }

            let iv: [u8; 16] = raw_block[0x3D0..0x3D0 + 16].try_into().unwrap();
            let encrypted_data = &mut raw_block[0x400..0x400 + 0x7C00];
            Self::aes_decrypt(&self.disc_key, &iv, encrypted_data)?;

            let read_len = std::cmp::min(usize::try_from(size)?, 0x7C00 - offset_in_block);
            data.extend_from_slice(&encrypted_data[offset_in_block..offset_in_block + read_len]);

            offset += read_len as u64;
            size -= read_len as u64;
        }
        Ok(data)
    }

    fn traverse_fst(&mut self, part_offset: u64, fst_data: &[u8]) -> Result<(), WbfsError> {
        let num_entries = u32::from_be_bytes(fst_data[8..12].try_into().unwrap());
        debug!("FST has {num_entries} entries.");

        for i in 1..num_entries {
            let entry_offset = (i * 12) as usize;
            let entry = &fst_data[entry_offset..entry_offset + 12];
            let is_dir = entry[0] == 1;

            if !is_dir {
                let file_offset = u32::from_be_bytes(entry[4..8].try_into().unwrap());
                let file_size = u32::from_be_bytes(entry[8..12].try_into().unwrap());
                // "Read" the file to mark its sectors as used.
                self.read_iso_partition_data(
                    part_offset,
                    u64::from(file_offset) * 4,
                                             u64::from(file_size),
                )?;
            }
        }
        Ok(())
    }

    fn build_disc_usage_table(&mut self) -> Result<(), WbfsError> {
        info!("Building disc usage table (scrubbing)...");
        self.usage_table[0] = true;
        self.usage_table[(0x40000 / WII_SECTOR_SIZE) as usize] = true;
        self.usage_table[(0x4E000 / WII_SECTOR_SIZE) as usize] = true;

        let part_table_info = self.read_iso_data(0x40000, 0x20)?;
        let num_partitions = u32::from_be_bytes(part_table_info[0..4].try_into().unwrap());
        let part_table_offset =
        u64::from(u32::from_be_bytes(part_table_info[4..8].try_into().unwrap())) * 4;

        debug!(
            "Found {num_partitions} partitions at offset {part_table_offset:#x}"
        );
        let part_info_data =
        self.read_iso_data(part_table_offset, (num_partitions * 8) as usize)?;

        for i in 0..num_partitions {
            let offset = (i * 8) as usize;
            let part_offset =
            u64::from(u32::from_be_bytes(part_info_data[offset..offset + 4].try_into().unwrap()))
            * 4;
            let part_type =
            u32::from_be_bytes(part_info_data[offset + 4..offset + 8].try_into().unwrap());
            info!(
                "Analyzing Partition {i}: type={part_type}, offset={part_offset:#x}"
            );

            let ticket = self.read_iso_data(part_offset, 0x2A4)?;
            self.disc_key = Self::decrypt_title_key(&ticket)?;
            debug!(
                "Decrypted Disc Key for partition {}: {}",
                i,
                hex::encode(self.disc_key)
            );

            let part_header = self.read_iso_data(part_offset + 0x2A4, 0x1C)?;
            self.part_data_offset =
            u64::from(u32::from_be_bytes(part_header[0x14..0x18].try_into().unwrap())) * 4;

            let part_main_header = self.read_iso_partition_data(part_offset, 0, 0x480)?;
            let fst_offset =
            u64::from(u32::from_be_bytes(part_main_header[0x424..0x428].try_into().unwrap())) * 4;
            let fst_size =
            u64::from(u32::from_be_bytes(part_main_header[0x428..0x42C].try_into().unwrap())) * 4;

            debug!(
                "FST located at offset {fst_offset:#x} with size {fst_size:#x}"
            );
            let fst_data = self.read_iso_partition_data(part_offset, fst_offset, fst_size)?;
            self.traverse_fst(part_offset, &fst_data)?;
        }
        Ok(())
    }

    /// The main conversion method.
    ///
    /// The `progress_callback` is an optional closure that receives `ProgressUpdate`
    /// events, allowing the caller to display progress.
    /// Converts the ISO to WBFS format
    ///
    /// # Errors
    ///
    /// Returns an error if any I/O operation fails or if the ISO is not a valid Wii disc
    pub fn convert(
        &mut self,
        progress_callback: Option<&impl Fn(ProgressUpdate)>,
    ) -> Result<(), WbfsError> {
        // --- Stage 1: Scrubbing ---
        if let Some(cb) = &progress_callback {
            cb(ProgressUpdate::ScrubbingStart);
        }
        self.build_disc_usage_table()?;

        // --- Stage 2: Conversion ---
        let iso_header = self.read_iso_data(0, 0x100)?;
        let game_id = String::from_utf8_lossy(&iso_header[..6]).to_string();
        let mut title: String = String::from_utf8_lossy(&iso_header[0x20..0x60])
        .trim_end_matches('\0')
        .trim()
        .to_string();
        title.retain(|c| !INVALID_PATH_CHARS.contains(&c));

        let output_name = format!("{title} [{game_id}]");
        let final_dir = self.output_dir.join(&output_name);
        std::fs::create_dir_all(&final_dir)?;
        let wbfs_base_path = final_dir.join(&game_id);

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

        if let Some(cb) = &progress_callback {
            cb(ProgressUpdate::ConversionStart {
                total_blocks: total_blocks_to_process as u64,
            });
        }

        let mut disc_info = vec![0u8; 0x100 + (MAX_WII_SECTORS >> wbfs_block_size_shift) * 2];
        disc_info[..0x100].copy_from_slice(&iso_header);
        let wlba_table_offset = 0x100;

        let mut free_block_allocator = 1u16;

        // The loop now iterates only over the necessary number of blocks.
        for i in 0..total_blocks_to_process {
            let start_sec = i * wii_sec_per_wbfs_sec;
            let end_sec = start_sec + wii_sec_per_wbfs_sec;
            let is_used = self.usage_table[start_sec..end_sec].iter().any(|&x| x);

            if is_used {
                if free_block_allocator == u16::MAX {
                    return Err(WbfsError::PartitionFull);
                }
                let block_addr = free_block_allocator;
                free_block_allocator += 1;

                disc_info[wlba_table_offset + i * 2..wlba_table_offset + i * 2 + 2]
                .copy_from_slice(&block_addr.to_be_bytes());

                let iso_offset = (start_sec as u64) * WII_SECTOR_SIZE;
                let wbfs_block_data = self.read_iso_data(iso_offset, usize::try_from(wbfs_sec_sz)?)?;

                let wbfs_offset = u64::from(block_addr) * wbfs_sec_sz;
                writer.write(wbfs_offset, &wbfs_block_data)?;
            } else {
                disc_info[wlba_table_offset + i * 2..wlba_table_offset + i * 2 + 2]
                .copy_from_slice(&0u16.to_be_bytes());
            }
            if let Some(cb) = &progress_callback {
                cb(ProgressUpdate::ConversionUpdate {
                    current_block: i as u64 + 1,
                });
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

        if let Some(cb) = &progress_callback {
            cb(ProgressUpdate::Done);
        } else {
            info!("Conversion complete!");
        }
        Ok(())
    }
}
