// SPDX-FileCopyrightText: 2025 Manuel Quarneti <mq1@ik.me>
// SPDX-License-Identifier: GPL-2.0-only

//! A Rust library to convert Wii disc images to the split WBFS file format,
//! replicating the default behavior of `wbfs_file v2.9`.

use bitvec::prelude::*;
use log::{debug, info, trace, warn};
use nod::{Disc, SECTOR_SIZE as WII_SECTOR_SIZE};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use zerocopy::IntoBytes;

// --- Constants ---

/// Magic number for WBFS files ('W','B','F','S' in big-endian).
const WBFS_MAGIC: u32 = 0x57424653;
/// The size of a hard drive sector, as assumed by libwbfs.
const HD_SECTOR_SIZE: u32 = 512;
/// The maximum number of sectors on a dual-layer Wii disc.
const WII_MAX_SECTORS: usize = 286864; // 143432 * 2
/// The fixed split size for output files: 4 GiB - 32 KiB.
const SPLIT_SIZE: u64 = (4 * 1024 * 1024 * 1024) - (32 * 1024);
/// The maximum number of file splits allowed.
const MAX_SPLITS: usize = 10;
/// Invalid characters for filenames, to be replaced with '_'.
const INVALID_FILENAME_CHARS: &str = "/\\:|<>?*\"'";

// --- Error Handling ---

#[derive(Debug, thiserror::Error)]
pub enum ConversionError {
    #[error("Nod library error: {0}")]
    Nod(#[from] nod::Error),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Input file is not a valid Wii disc: {0}")]
    InvalidDisc(String),
    #[error("Failed to create WBFS structure: {0}")]
    WbfsCreation(String),
}

type Result<T> = std::result::Result<T, ConversionError>;

// --- WBFS Structure Definitions ---

/// Represents the main header of a WBFS file or partition.
/// This structure is written to the beginning of the first file.
struct WbfsHeader {
    magic: u32,
    n_hd_sec: u32,
    hd_sec_sz_s: u8,
    wbfs_sec_sz_s: u8,
}

impl WbfsHeader {
    /// Serializes the header into a byte vector in big-endian format.
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12);
        bytes.extend_from_slice(&self.magic.to_be_bytes());
        bytes.extend_from_slice(&self.n_hd_sec.to_be_bytes());
        bytes.push(self.hd_sec_sz_s);
        bytes.push(self.wbfs_sec_sz_s);
        bytes.extend_from_slice(&[0u8; 2]); // Padding
        bytes
    }
}

// --- I/O Handling for Split Files ---

/// Manages writing data across multiple split files.
struct SplitWriter {
    base_path: PathBuf,
    split_size: u64,
    files: Vec<Option<File>>,
    total_size: u64,
}

impl SplitWriter {
    /// Creates a new `SplitWriter`.
    fn new(base_path: &Path, split_size: u64) -> Self {
        Self {
            base_path: base_path.to_path_buf(),
            split_size,
            files: (0..MAX_SPLITS).map(|_| None).collect(),
            total_size: 0,
        }
    }

    /// Generates the filename for a given split index.
    fn get_filename(&self, index: usize) -> PathBuf {
        let mut path_str = self.base_path.to_string_lossy().to_string();
        if index > 0 {
            // Replace the last character with the split number for .wbf1, .wbf2, etc.
            path_str.pop();
            path_str.push_str(&index.to_string());
        }
        PathBuf::from(path_str)
    }

    /// Opens (or gets a handle to) the file for a given split index.
    fn get_file(&mut self, index: usize) -> io::Result<&mut File> {
        if self.files.get(index).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Split index out of bounds",
            ));
        }

        if self.files[index].is_none() {
            let filename = self.get_filename(index);
            debug!("Opening split file for writing: {}", filename.display());
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(filename)?;
            self.files[index] = Some(file);
        }

        Ok(self.files[index].as_mut().unwrap())
    }

    /// Writes a buffer of data at a specific absolute offset.
    fn write_all_at(&mut self, mut offset: u64, mut buf: &[u8]) -> io::Result<()> {
        trace!("Writing {} bytes at offset {}", buf.len(), offset);
        let split_size = self.split_size;
        while !buf.is_empty() {
            let split_index = (offset / split_size) as usize;
            let offset_in_split = offset % split_size;

            let file = self.get_file(split_index)?;
            file.seek(SeekFrom::Start(offset_in_split))?;

            let bytes_to_write = (split_size - offset_in_split).min(buf.len() as u64) as usize;
            file.write_all(&buf[..bytes_to_write])?;

            buf = &buf[bytes_to_write..];
            offset += bytes_to_write as u64;
        }
        Ok(())
    }

    /// Truncates the files to match the final total size.
    fn truncate(&mut self, total_size: u64) -> io::Result<()> {
        info!("Final WBFS size: {} bytes. Truncating files...", total_size);
        self.total_size = total_size;
        let mut remaining_size = total_size;

        for i in 0..MAX_SPLITS {
            let filename = self.get_filename(i);
            if let Some(file) = self.files[i].as_mut() {
                let size_for_this_file = remaining_size.min(self.split_size);
                if size_for_this_file > 0 {
                    debug!(
                        "Truncating {} to {} bytes",
                        filename.display(),
                        size_for_this_file
                    );
                    file.set_len(size_for_this_file)?;
                    remaining_size -= size_for_this_file;
                }
            }
        }

        // Delete any created but now-empty split files
        for i in 0..MAX_SPLITS {
            let filename = self.get_filename(i);
            if self.files[i].is_some() {
                if filename.exists() {
                    let file_size = filename.metadata()?.len();
                    if file_size == 0 {
                        debug!("Removing empty split file: {}", filename.display());
                        fs::remove_file(filename)?;
                    }
                }
            }
        }
        Ok(())
    }
}

/// The main converter object.
struct WbfsConverter<'a> {
    input_path: &'a Path,
    output_dir: &'a Path,
}

impl<'a> WbfsConverter<'a> {
    fn new(input_path: &'a Path, output_dir: &'a Path) -> Self {
        Self {
            input_path,
            output_dir,
        }
    }

    /// Builds a map of which 32 KiB sectors of the disc image are in use.
    fn build_used_sector_map(&self, disc: &mut Disc) -> Result<BitVec<u8, Lsb0>> {
        info!("Analyzing disc structure to find used data sectors...");
        let mut used_sectors = bitvec![u8, Lsb0; 0; WII_MAX_SECTORS];

        // Mark essential metadata sectors as used, replicating wbfs_file behavior.
        used_sectors.set(0, true); // Boot sector
        used_sectors.set(0x40000 / WII_SECTOR_SIZE, true); // Partition table
        used_sectors.set(0x4E000 / WII_SECTOR_SIZE, true); // Region data

        let partitions = disc.partitions().to_vec(); // Clone to avoid borrowing issues
        if partitions.is_empty() && disc.header().is_gamecube() {
            return Err(ConversionError::InvalidDisc(
                "GameCube discs are not supported by WBFS.".to_string(),
            ));
        }

        for part_info in &partitions {
            info!(
                "Processing partition {} ({:?})",
                part_info.index, part_info.kind
            );
            // Mark partition metadata area as used
            for s in part_info.start_sector..part_info.data_start_sector {
                used_sectors.set(s as usize, true);
            }

            let mut partition = disc.open_partition(part_info.index)?;
            let meta = partition.meta()?;
            let fst = meta
                .fst()
                .map_err(|e| ConversionError::InvalidDisc(e.to_string()))?;

            // Mark sectors used by the FST and DOL
            let is_wii = meta.header().is_wii();
            let dol_offset = meta.partition_header().dol_offset(is_wii);
            let fst_offset = meta.partition_header().fst_offset(is_wii);
            let fst_size = meta.partition_header().fst_size(is_wii);
            let dol_size = fst_offset - dol_offset; // DOL is right before FST

            let ranges_to_mark = [(dol_offset, dol_size), (fst_offset, fst_size)];
            for (offset, length) in ranges_to_mark {
                if length > 0 {
                    let start_data_sector = offset / (WII_SECTOR_SIZE - 0x400) as u64;
                    let end_data_sector = (offset + length - 1) / (WII_SECTOR_SIZE - 0x400) as u64;
                    for s in start_data_sector..=end_data_sector {
                        let physical_sector = part_info.data_start_sector as u64 + s;
                        used_sectors.set(physical_sector as usize, true);
                    }
                }
            }

            // Mark sectors used by files in the FST
            for (_, node, name_res) in fst.iter() {
                if node.is_file() {
                    let name = name_res.unwrap_or_else(|_| "[invalid name]".into());
                    trace!("Found file: {}, size: {}", name, node.length());
                    let offset = node.offset(is_wii);
                    let length = node.length();
                    if length > 0 {
                        let start_data_sector = offset / (WII_SECTOR_SIZE - 0x400) as u64;
                        let end_data_sector =
                            (offset + length - 1) / (WII_SECTOR_SIZE - 0x400) as u64;
                        for s in start_data_sector..=end_data_sector {
                            let physical_sector = part_info.data_start_sector as u64 + s;
                            used_sectors.set(physical_sector as usize, true);
                        }
                    }
                }
            }
        }
        let used_count = used_sectors.count_ones();
        info!(
            "Analysis complete. Found {} used sectors out of {} total.",
            used_count, WII_MAX_SECTORS
        );
        Ok(used_sectors)
    }

    /// Performs the main conversion logic.
    fn convert(&self) -> Result<()> {
        // 1. Open input disc and analyze it
        let mut disc = nod::Disc::new(self.input_path)?;
        let used_sectors = self.build_used_sector_map(&mut disc)?;

        // 2. Re-open disc with options to get a raw ISO stream
        let options = nod::OpenOptions {
            rebuild_encryption: true,
            ..Default::default()
        };
        let mut source_iso_stream = nod::Disc::new_with_options(self.input_path, &options)?;

        // 3. Prepare output files
        let header = disc.header();
        let game_id = header.game_id_str();
        let mut game_title = header.game_title_str().to_string();

        // The raw header bytes are needed for the WBFS metadata.
        let header_bytes = header.as_bytes();
        let mut disc_header_copy = [0u8; 256];
        disc_header_copy.copy_from_slice(&header_bytes[..256]);

        // Sanitize game title for use in a directory name.
        game_title = game_title.trim().to_string();
        for c in INVALID_FILENAME_CHARS.chars() {
            game_title = game_title.replace(c, "_");
        }

        // Create the game-specific subdirectory: TITLE [ID]
        let game_dir_name = format!("{} [{}]", game_title, game_id);
        let game_output_dir = self.output_dir.join(game_dir_name);
        info!("Creating game directory: {}", game_output_dir.display());
        fs::create_dir_all(&game_output_dir)?;

        // The base path for the .wbfs files is now inside the new directory.
        let out_base_path = game_output_dir.join(format!("{}.wbfs", game_id));

        info!("Output base path: {}", out_base_path.display());
        let mut writer = SplitWriter::new(&out_base_path, SPLIT_SIZE);

        // 4. Calculate WBFS parameters
        let n_wii_sec = WII_MAX_SECTORS as u32;
        let wii_sec_sz_s = (WII_SECTOR_SIZE as u32).trailing_zeros() as u8;

        // Determine the optimal WBFS sector size based on disc size, replicating libwbfs logic.
        let mut sz_s = 6; // Start with 2MB WBFS sectors (32KB * 2^6)
        while sz_s < 11 {
            if (n_wii_sec as u64) < ((1u64 << 16) * (1u64 << sz_s)) {
                break;
            }
            sz_s += 1;
        }
        if sz_s == 11 {
            warn!("Could not find a suitable WBFS sector size; using largest.");
        }

        let wbfs_sec_sz_s = sz_s + wii_sec_sz_s;
        let wbfs_sector_size = 1u64 << wbfs_sec_sz_s;
        let wii_sectors_per_wbfs_sector = 1u32 << sz_s;
        let num_wbfs_blocks_in_disc =
            (n_wii_sec + wii_sectors_per_wbfs_sector - 1) / wii_sectors_per_wbfs_sector;

        debug!(
            "WBFS sector size: {} bytes ({} Wii sectors)",
            wbfs_sector_size, wii_sectors_per_wbfs_sector
        );

        // 5. Main conversion loop
        info!("Starting data conversion...");
        let mut wlba_table = vec![0u16; num_wbfs_blocks_in_disc as usize];
        let mut next_free_wbfs_block: u32 = 1; // Block 0 is for metadata
        let mut data_buffer = vec![0u8; wbfs_sector_size as usize];

        for wbfs_block_idx in 0..num_wbfs_blocks_in_disc {
            let start_wii_sector = wbfs_block_idx * wii_sectors_per_wbfs_sector;
            let end_wii_sector = (start_wii_sector + wii_sectors_per_wbfs_sector).min(n_wii_sec);

            let is_used = (start_wii_sector..end_wii_sector)
                .any(|s| used_sectors.get(s as usize).map_or(false, |b| *b));

            if is_used {
                let wii_block_offset = start_wii_sector as u64 * WII_SECTOR_SIZE as u64;
                source_iso_stream.seek(SeekFrom::Start(wii_block_offset))?;
                source_iso_stream.read_exact(&mut data_buffer)?;

                let target_offset = next_free_wbfs_block as u64 * wbfs_sector_size;
                writer.write_all_at(target_offset, &data_buffer)?;

                wlba_table[wbfs_block_idx as usize] = next_free_wbfs_block as u16;
                next_free_wbfs_block += 1;
            }
        }
        info!(
            "Data conversion finished. {} WBFS blocks written.",
            next_free_wbfs_block - 1
        );

        // 6. Write metadata
        info!("Writing WBFS metadata...");
        let total_hd_sectors_used =
            (next_free_wbfs_block as u64 * wbfs_sector_size) / HD_SECTOR_SIZE as u64;

        let header = WbfsHeader {
            magic: WBFS_MAGIC,
            n_hd_sec: total_hd_sectors_used as u32,
            hd_sec_sz_s: HD_SECTOR_SIZE.trailing_zeros() as u8,
            wbfs_sec_sz_s,
        };

        let disc_info_size = (256 + wlba_table.len() * 2) as u32;
        let disc_info_size_aligned = (disc_info_size + HD_SECTOR_SIZE - 1) & !(HD_SECTOR_SIZE - 1);

        let free_blocks_map_size = (num_wbfs_blocks_in_disc as u32 / 8) + 1;
        let free_blocks_map_size_aligned =
            (free_blocks_map_size + HD_SECTOR_SIZE - 1) & !(HD_SECTOR_SIZE - 1);

        let mut metadata_buf = Vec::new();
        // WBFS Header + Disc Table (only one disc)
        metadata_buf.extend_from_slice(&header.to_bytes());
        metadata_buf.push(1); // Mark disc slot 0 as used
        metadata_buf.resize(HD_SECTOR_SIZE as usize, 0);

        // Disc Info (Header copy + WLBA table)
        metadata_buf.extend_from_slice(&disc_header_copy);
        for &lba in &wlba_table {
            metadata_buf.extend_from_slice(&lba.to_be_bytes());
        }
        metadata_buf.resize(HD_SECTOR_SIZE as usize + disc_info_size_aligned as usize, 0);

        // Free Blocks Table
        let freeblks_lba =
            (wbfs_sector_size - free_blocks_map_size_aligned as u64) / HD_SECTOR_SIZE as u64;
        let freeblks_offset = freeblks_lba * HD_SECTOR_SIZE as u64;

        // Create a simple free block map. All blocks up to `next_free_wbfs_block` are used.
        let mut free_map = bitvec![u8, Lsb0; 1; num_wbfs_blocks_in_disc as usize];
        for i in 1..next_free_wbfs_block {
            free_map.set(i as usize, false); // Mark as not free (used)
        }
        // The original tool writes the free map at a fixed offset from the end of the first WBFS block.
        let mut free_map_buf = vec![0u8; free_blocks_map_size_aligned as usize];
        free_map_buf[..free_map.as_raw_slice().len()].copy_from_slice(free_map.as_raw_slice());

        // Write metadata blocks
        writer.write_all_at(0, &metadata_buf)?;
        writer.write_all_at(freeblks_offset, &free_map_buf)?;

        // 7. Truncate files
        let final_size = next_free_wbfs_block as u64 * wbfs_sector_size;
        writer.truncate(final_size)?;

        Ok(())
    }
}

/// Public entry point for the conversion process.
///
/// # Arguments
/// * `input_path` - Path to the source Wii disc image.
/// * `output_dir` - Path to the directory where output files will be created.
pub fn convert(input_path: &Path, output_dir: &Path) -> Result<()> {
    let converter = WbfsConverter::new(input_path, output_dir);
    converter.convert()
}
