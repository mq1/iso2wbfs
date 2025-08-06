// SPDX-FileCopyrightText: 2025 Manuel Quarneti <mq1@ik.me>
// SPDX-License-Identifier: GPL-2.0-only

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use log::{debug, error, info};
use thiserror::Error;
// Use constants from nod to reduce duplication and improve robustness.
use nod::{DL_DVD_SIZE, SECTOR_SIZE};

// --- Constants ---
const WII_SECTOR_SIZE: u64 = SECTOR_SIZE as u64;
const MAX_WII_SECTORS: usize = (DL_DVD_SIZE / WII_SECTOR_SIZE) as usize;
// SECTOR_DATA_SIZE is the size of a Wii sector excluding the SHA-1 hash area (0x8000 - 0x400).
const SECTOR_DATA_SIZE: u64 = (SECTOR_SIZE - 0x400) as u64;
const WBFS_MAGIC: u32 = 0x5742_4653; // "WBFS"
const SPLIT_SIZE_4GB_MINUS_32KB: u64 = (4 * 1024 * 1024 * 1024) - (32 * 1024);
const INVALID_PATH_CHARS: &[char] = &['/', '\\', ':', '|', '<', '>', '?', '*', '"', '\''];
const PARTITION_MAIN_HEADER_SIZE: u64 = 0x480;
const WBFS_HEADER_SECTOR_SIZE: u64 = 512;
const WBFS_DISC_HEADER_SIZE: usize = 0x100;

// --- Custom Error Type ---
#[derive(Error, Debug)]
pub enum WbfsError {
    #[error("I/O Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid Input file: {0}")]
    InvalidInput(String),
    #[error("Ran out of allocatable WBFS blocks")]
    PartitionFull,
    #[error("Conversion error: {0}")]
    ConversionError(#[from] std::num::TryFromIntError),
    #[error("Slice conversion error: {0}")]
    SliceError(#[from] std::array::TryFromSliceError),
    #[error("Nod library error: {0}")]
    NodError(#[from] nod::Error),
}

// --- Split File Writer ---
pub struct SplitWbfsWriter {
    file_handles: HashMap<usize, BufWriter<File>>,
    base_path: PathBuf,
    split_size: u64,
}

impl SplitWbfsWriter {
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
/// A converter for Wii disc images to WBFS format.
pub struct WbfsConverter {
    input_path: PathBuf,
    output_dir: PathBuf,
}

impl WbfsConverter {
    pub fn new(
        input_path: impl AsRef<Path>,
        output_dir: impl AsRef<Path>,
    ) -> Result<Self, WbfsError> {
        Ok(Self {
            input_path: input_path.as_ref().to_path_buf(),
            output_dir: output_dir.as_ref().to_path_buf(),
        })
    }

    pub fn convert(&self) -> Result<(), WbfsError> {
        info!("Opening disc: {}", self.input_path.display());
        let options = nod::OpenOptions {
            rebuild_encryption: true,
            ..Default::default()
        };
        let mut disc = nod::Disc::new_with_options(&self.input_path, &options)?;

        if !disc.header().is_wii() {
            return Err(WbfsError::InvalidInput(
                "Input is not a Wii disc".to_string(),
            ));
        }

        let wbfs_base_path = self.prepare_output_paths(&disc)?;
        let usage_table = self.build_usage_table(&mut disc)?;
        self.write_wbfs(&mut disc, &usage_table, &wbfs_base_path)?;

        info!("Conversion complete!");
        Ok(())
    }

    fn prepare_output_paths(&self, disc: &nod::Disc) -> Result<PathBuf, WbfsError> {
        let disc_header = disc.header();
        let game_id = disc_header.game_id_str().to_string();
        let mut title: String = disc_header.game_title_str().trim().to_string();
        title.retain(|c| !INVALID_PATH_CHARS.contains(&c));

        let output_name = format!("{title} [{game_id}]");
        let final_dir = self.output_dir.join(&output_name);
        std::fs::create_dir_all(&final_dir)?;

        info!("Game: '{title}' ({game_id})");
        info!("Input format: {}", disc.meta().format);
        info!("Output will be in: {}", final_dir.display());

        Ok(final_dir.join(&game_id).with_extension("wbfs"))
    }

    fn build_usage_table(&self, disc: &mut nod::Disc) -> Result<Vec<bool>, WbfsError> {
        info!("Building disc usage table (scrubbing)...");
        let mut usage_table = vec![false; MAX_WII_SECTORS];

        mark_iso_sectors_used(&mut usage_table, 0, WII_SECTOR_SIZE);
        // Partition Table Offset
        mark_iso_sectors_used(&mut usage_table, 0x40000, WII_SECTOR_SIZE);
        if disc.region().is_some() {
            // Region Data Offset
            mark_iso_sectors_used(&mut usage_table, 0x4E000, WII_SECTOR_SIZE);
        }

        for part_info in disc.partitions() {
            info!(
                "Analyzing Partition {}: type={}",
                part_info.index, part_info.kind
            );
            let part_start_offset = part_info.start_sector as u64 * WII_SECTOR_SIZE;
            let wii_part_header = &part_info.header;

            // Mark headers and metadata as used.
            mark_iso_sectors_used(
                &mut usage_table,
                part_start_offset,
                std::mem::size_of_val(&**wii_part_header) as u64,
            );
            mark_iso_sectors_used(
                &mut usage_table,
                part_start_offset + wii_part_header.tmd_off(),
                wii_part_header.tmd_size(),
            );
            mark_iso_sectors_used(
                &mut usage_table,
                part_start_offset + wii_part_header.cert_chain_off(),
                wii_part_header.cert_chain_size(),
            );
            mark_iso_sectors_used(
                &mut usage_table,
                part_start_offset + wii_part_header.h3_table_off(),
                wii_part_header.h3_table_size(),
            );

            let mut partition = disc.open_partition(part_info.index)?;
            let meta = partition.meta()?;
            let fst = meta
                .fst()
                .map_err(|e| WbfsError::InvalidInput(e.to_string()))?;
            let part_header = meta.partition_header();

            let dol_offset = part_header.dol_offset(true);
            let fst_offset = part_header.fst_offset(true);
            let fst_size = part_header.fst_size(true);
            mark_partition_data_sectors(&mut usage_table, part_info, 0, PARTITION_MAIN_HEADER_SIZE);
            mark_partition_data_sectors(
                &mut usage_table,
                part_info,
                dol_offset,
                fst_offset - dol_offset,
            );
            mark_partition_data_sectors(&mut usage_table, part_info, fst_offset, fst_size);

            for node in fst.nodes {
                if node.is_file() {
                    mark_partition_data_sectors(
                        &mut usage_table,
                        part_info,
                        node.offset(true),
                        node.length(),
                    );
                }
            }
        }
        Ok(usage_table)
    }

    fn write_wbfs(
        &self,
        disc: &mut nod::Disc,
        usage_table: &[bool],
        wbfs_base_path: &Path,
    ) -> Result<(), WbfsError> {
        info!("Writing WBFS file...");
        let mut writer = SplitWbfsWriter::new(wbfs_base_path, SPLIT_SIZE_4GB_MINUS_32KB)?;

        let (disc_info, free_block_allocator, wbfs_sector_size) =
            create_wbfs_disc_info_and_write_data(disc, usage_table, &mut writer)?;

        writer.write(WBFS_HEADER_SECTOR_SIZE, &disc_info)?;

        create_and_write_wbfs_header(&mut writer, free_block_allocator, wbfs_sector_size)?;

        let final_size = u64::from(free_block_allocator) * wbfs_sector_size;
        writer.truncate(final_size)?;

        Ok(())
    }
}

/// Creates the disc info buffer (header + LBA mapping) and writes the used data blocks.
fn create_wbfs_disc_info_and_write_data(
    disc: &mut nod::Disc,
    usage_table: &[bool],
    writer: &mut SplitWbfsWriter,
) -> Result<(Vec<u8>, u16, u64), WbfsError> {
    let mut iso_header_buf = vec![0; WBFS_DISC_HEADER_SIZE];
    disc.seek(SeekFrom::Start(0))?;
    disc.read_exact(&mut iso_header_buf)?;

    let wbfs_block_size_shift = 6;
    let wii_sectors_per_wbfs_block = 1 << wbfs_block_size_shift;
    let wbfs_sector_size_shift = wbfs_block_size_shift + 15;
    let wbfs_sector_size = 1u64 << wbfs_sector_size_shift;

    let total_blocks_to_process = MAX_WII_SECTORS >> wbfs_block_size_shift;
    debug!("Processing {total_blocks_to_process} blocks for dual-layer compatibility.");

    let mut disc_info =
        vec![0u8; WBFS_DISC_HEADER_SIZE + (MAX_WII_SECTORS >> wbfs_block_size_shift) * 2];
    disc_info[..WBFS_DISC_HEADER_SIZE].copy_from_slice(&iso_header_buf);
    let wlba_table_offset = WBFS_DISC_HEADER_SIZE;

    let mut free_block_allocator = 1u16;
    let mut wbfs_block_buffer = vec![0; usize::try_from(wbfs_sector_size)?];

    for i in 0..total_blocks_to_process {
        let start_sec = i * wii_sectors_per_wbfs_block;
        let end_sec = start_sec + wii_sectors_per_wbfs_block;
        let is_used = (start_sec..std::cmp::min(end_sec, MAX_WII_SECTORS)).any(|k| usage_table[k]);

        if is_used {
            let block_addr = free_block_allocator;
            free_block_allocator += 1;
            if free_block_allocator == 0 {
                return Err(WbfsError::PartitionFull);
            }

            disc_info[wlba_table_offset + i * 2..wlba_table_offset + i * 2 + 2]
                .copy_from_slice(&block_addr.to_be_bytes());

            let iso_offset = (start_sec as u64) * WII_SECTOR_SIZE;
            disc.seek(SeekFrom::Start(iso_offset))?;
            disc.read_exact(&mut wbfs_block_buffer)?;

            let wbfs_offset = u64::from(block_addr) * wbfs_sector_size;
            writer.write(wbfs_offset, &wbfs_block_buffer)?;
        } else {
            disc_info[wlba_table_offset + i * 2..wlba_table_offset + i * 2 + 2]
                .copy_from_slice(&0u16.to_be_bytes());
        }
    }

    Ok((disc_info, free_block_allocator, wbfs_sector_size))
}

/// Creates and writes the main WBFS header to the start of the file.
fn create_and_write_wbfs_header(
    writer: &mut SplitWbfsWriter,
    free_block_allocator: u16,
    wbfs_sector_size: u64,
) -> Result<(), WbfsError> {
    let mut wbfs_head = vec![0u8; usize::try_from(WBFS_HEADER_SECTOR_SIZE)?];
    let num_header_sectors =
        (u64::from(free_block_allocator) * wbfs_sector_size) / WBFS_HEADER_SECTOR_SIZE;
    let wbfs_sector_size_shift = wbfs_sector_size.trailing_zeros();

    wbfs_head[0..4].copy_from_slice(&WBFS_MAGIC.to_be_bytes());
    wbfs_head[4..8].copy_from_slice(&u32::try_from(num_header_sectors)?.to_be_bytes());
    wbfs_head[8] = (WBFS_HEADER_SECTOR_SIZE as f64).log2() as u8;
    wbfs_head[9] = u8::try_from(wbfs_sector_size_shift)?;
    wbfs_head[12] = 1; // Mark disc slot 0 as used
    writer.write(0, &wbfs_head)?;
    Ok(())
}

/// Marks a range of absolute ISO sectors as used.
fn mark_iso_sectors_used(table: &mut [bool], offset: u64, size: u64) {
    if size == 0 {
        return;
    }
    let start_sector = (offset / WII_SECTOR_SIZE) as usize;
    let end_sector = ((offset + size - 1) / WII_SECTOR_SIZE) as usize + 1;
    for i in start_sector..end_sector {
        if i < table.len() {
            table[i] = true;
        }
    }
}

/// Marks a range of sectors within a partition's data area as used.
fn mark_partition_data_sectors(
    table: &mut [bool],
    part_info: &nod::PartitionInfo,
    offset: u64,
    size: u64,
) {
    if size == 0 {
        return;
    }
    let start_data_sector = (offset / SECTOR_DATA_SIZE) as u32;
    let end_data_sector = ((offset + size - 1) / SECTOR_DATA_SIZE) as u32;
    for s in start_data_sector..=end_data_sector {
        let abs_sector = part_info.data_start_sector + s;
        if (abs_sector as usize) < table.len() {
            table[abs_sector as usize] = true;
        }
    }
}
