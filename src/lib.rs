// SPDX-FileCopyrightText: 2025 Manuel Quarneti <mq1@ik.me>
// SPDX-License-Identifier: GPL-2.0-only

//! A Rust library to convert Wii disc images to the split WBFS file format,
//! replicating the default behavior of `wbfs_file v2.9`.

use bitvec::prelude::*;
use nod::{Disc, DiscHeader, SECTOR_SIZE as WII_SECTOR_SIZE};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use tracing::{debug, info, trace, warn};
use zerocopy::IntoBytes;

// --- Constants ---

/// Magic number for WBFS files ('W','B','F','S' in big-endian).
const WBFS_MAGIC: u32 = 0x57424653;
/// The size of a hard drive sector, as assumed by libwbfs.
const HD_SECTOR_SIZE: u32 = 512;
/// The maximum number of sectors on a dual-layer Wii disc (143432 sectors/layer).
const WII_MAX_SECTORS: usize = 143432 * 2;
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
}

impl SplitWriter {
    /// Creates a new `SplitWriter`.
    fn new(base_path: &Path, split_size: u64) -> Self {
        Self {
            base_path: base_path.to_path_buf(),
            split_size,
            files: (0..MAX_SPLITS).map(|_| None).collect(),
        }
    }

    /// Generates the filename for a given split index.
    fn get_filename(&self, index: usize) -> PathBuf {
        let mut path_str = self.base_path.to_string_lossy().to_string();
        if index > 0 {
            // Replaces `.wbfs` with `.wbf1`, `.wbf2`, etc.
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
        let mut remaining_size = total_size;

        for i in 0..MAX_SPLITS {
            let filename = self.get_filename(i);
            if let Some(file) = self.files[i].as_mut() {
                let size_for_this_file = remaining_size.min(self.split_size);
                debug!(
                    "Truncating {} to {} bytes",
                    filename.display(),
                    size_for_this_file
                );
                file.set_len(size_for_this_file)?;
                remaining_size -= size_for_this_file;
            }
        }

        // Delete any created but now-empty split files
        for i in 0..MAX_SPLITS {
            let filename = self.get_filename(i);
            if self.files[i].is_some() && filename.exists() && filename.metadata()?.len() == 0 {
                debug!("Removing empty split file: {}", filename.display());
                fs::remove_file(filename)?;
            }
        }
        Ok(())
    }
}

/// Encapsulates the logic for creating output paths.
struct OutputPaths {
    /// The final base path for the `.wbfs` file, e.g., `.../TITLE [ID]/ID.wbfs`.
    base_path: PathBuf,
}

impl OutputPaths {
    fn new(output_dir: &Path, header: &DiscHeader) -> Result<Self> {
        let game_id = header.game_id_str();
        let mut game_title = header.game_title_str().to_string();

        // Sanitize game title for use in a directory name.
        game_title = game_title.trim().to_string();
        for c in INVALID_FILENAME_CHARS.chars() {
            game_title = game_title.replace(c, "_");
        }

        // Create the game-specific subdirectory: TITLE [ID]
        let game_dir_name = format!("{} [{}]", game_title, game_id);
        let game_output_dir = output_dir.join(game_dir_name);
        info!("Creating game directory: {}", game_output_dir.display());
        fs::create_dir_all(&game_output_dir)?;

        // The base path for the .wbfs files is now inside the new directory.
        let base_path = game_output_dir.join(format!("{}.wbfs", game_id));

        Ok(Self { base_path })
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

    /// Marks the sectors for a given data range within a partition as used.
    fn mark_used_data_sectors(
        used_sectors: &mut BitSlice<u8, Lsb0>,
        part_data_start_sector: u32,
        offset: u64,
        length: u64,
    ) {
        if length > 0 {
            // The data is stored in blocks of 0x7C00 bytes within the 0x8000 byte sectors.
            let data_block_size = (WII_SECTOR_SIZE - 0x400) as u64;
            let start_data_sector = offset / data_block_size;
            let end_data_sector = (offset + length - 1) / data_block_size;
            for s in start_data_sector..=end_data_sector {
                let physical_sector = part_data_start_sector as u64 + s;
                used_sectors.set(physical_sector as usize, true);
            }
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

        let partitions = disc.partitions().to_vec();
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
            // Mark the entire partition metadata area as used.
            (part_info.start_sector..part_info.data_start_sector)
                .for_each(|s| used_sectors.set(s as usize, true));

            let mut partition = disc.open_partition(part_info.index)?;
            let meta = partition.meta()?;
            let fst = meta
                .fst()
                .map_err(|e| ConversionError::InvalidDisc(e.to_string()))?;

            let is_wii = meta.header().is_wii();
            let dol_offset = meta.partition_header().dol_offset(is_wii);
            let fst_offset = meta.partition_header().fst_offset(is_wii);
            let fst_size = meta.partition_header().fst_size(is_wii);
            let dol_size = fst_offset - dol_offset;

            // Mark sectors for DOL and FST.
            Self::mark_used_data_sectors(
                &mut used_sectors,
                part_info.data_start_sector,
                dol_offset,
                dol_size,
            );
            Self::mark_used_data_sectors(
                &mut used_sectors,
                part_info.data_start_sector,
                fst_offset,
                fst_size,
            );

            // Mark sectors for all files in the FST.
            for (_, node, name_res) in fst.iter() {
                if node.is_file() {
                    trace!(
                        "Found file: {}",
                        name_res.unwrap_or_else(|_| "[invalid name]".into())
                    );
                    Self::mark_used_data_sectors(
                        &mut used_sectors,
                        part_info.data_start_sector,
                        node.offset(is_wii),
                        node.length(),
                    );
                }
            }
        }
        info!(
            "Analysis complete. Found {} used sectors.",
            used_sectors.count_ones()
        );
        Ok(used_sectors)
    }

    /// Performs the main conversion logic.
    fn convert(&self) -> Result<()> {
        let mut disc = nod::Disc::new(self.input_path)?;
        let used_sectors = self.build_used_sector_map(&mut disc)?;

        let options = nod::OpenOptions {
            rebuild_encryption: true,
            ..Default::default()
        };
        let mut source_iso_stream = nod::Disc::new_with_options(self.input_path, &options)?;

        let output_paths = OutputPaths::new(self.output_dir, disc.header())?;
        let mut writer = SplitWriter::new(&output_paths.base_path, SPLIT_SIZE);

        let n_wii_sec = WII_MAX_SECTORS as u32;
        let wii_sec_sz_s = (WII_SECTOR_SIZE as u32).trailing_zeros() as u8;

        // Determine the optimal WBFS sector size. This replicates the logic from the original C tool,
        // finding the smallest WBFS block size that can address the entire disc with a 16-bit index.
        let mut sz_s = 6; // Start with 2MB WBFS sectors (32KB * 2^6)
        while sz_s < 11 && (n_wii_sec as u64) >= ((1u64 << 16) * (1u64 << sz_s)) {
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

        info!("Starting data conversion...");
        let mut wlba_table = vec![0u16; num_wbfs_blocks_in_disc as usize];
        let mut next_free_wbfs_block: u32 = 1; // Block 0 is reserved for metadata.
        let mut data_buffer = vec![0u8; wbfs_sector_size as usize];

        for wbfs_block_idx in 0..num_wbfs_blocks_in_disc {
            let start_wii_sector = wbfs_block_idx * wii_sectors_per_wbfs_sector;
            let end_wii_sector = (start_wii_sector + wii_sectors_per_wbfs_sector).min(n_wii_sec);

            if (start_wii_sector..end_wii_sector).any(|s| used_sectors[s as usize]) {
                let wii_block_offset = start_wii_sector as u64 * WII_SECTOR_SIZE as u64;
                source_iso_stream.seek(SeekFrom::Start(wii_block_offset))?;
                source_iso_stream.read_exact(&mut data_buffer)?;

                let target_offset = next_free_wbfs_block as u64 * wbfs_sector_size;
                writer.write_all_at(target_offset, &data_buffer)?;

                wlba_table[wbfs_block_idx as usize] = (next_free_wbfs_block as u16).to_be();
                next_free_wbfs_block += 1;
            }
        }
        info!(
            "Data conversion finished. {} WBFS blocks written.",
            next_free_wbfs_block - 1
        );

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
        metadata_buf.extend_from_slice(&header.to_bytes());
        metadata_buf.push(1); // Mark disc slot 0 as used.
        metadata_buf.resize(HD_SECTOR_SIZE as usize, 0);

        let mut disc_header_copy = [0u8; 256];
        disc_header_copy.copy_from_slice(&disc.header().as_bytes()[..256]);
        metadata_buf.extend_from_slice(&disc_header_copy);
        metadata_buf.extend_from_slice(wlba_table.as_bytes());
        metadata_buf.resize(HD_SECTOR_SIZE as usize + disc_info_size_aligned as usize, 0);

        let freeblks_lba =
            (wbfs_sector_size - free_blocks_map_size_aligned as u64) / HD_SECTOR_SIZE as u64;
        let freeblks_offset = freeblks_lba * HD_SECTOR_SIZE as u64;

        let mut free_map = bitvec![u8, Lsb0; 1; num_wbfs_blocks_in_disc as usize];
        (1..next_free_wbfs_block).for_each(|i| free_map.set(i as usize, false));

        let mut free_map_buf = vec![0u8; free_blocks_map_size_aligned as usize];
        free_map_buf[..free_map.as_raw_slice().len()].copy_from_slice(free_map.as_raw_slice());

        writer.write_all_at(0, &metadata_buf)?;
        writer.write_all_at(freeblks_offset, &free_map_buf)?;

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
