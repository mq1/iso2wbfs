// SPDX-FileCopyrightText: 2025 Manuel Quarneti <mq1@ik.me>
// SPDX-License-Identifier: GPL-2.0-only

//! A Rust library to convert Wii and GameCube disc images, replicating the
//! default behavior of `wbfs_file v2.9` for Wii and creating NKit-compatible
//! scrubbed ISOs for GameCube.

use log::{debug, info, trace};
use nod::common::{Compression, Format};
use nod::read::{DiscOptions, DiscReader, PartitionEncryption};
use nod::write::{DiscWriter, FormatOptions, ProcessOptions};
use sanitize_filename_reader_friendly::sanitize;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// The fixed split size for output files: 4 GiB - 32 KiB.
const SPLIT_SIZE: u64 = (4 * 1024 * 1024 * 1024) - (32 * 1024);

// --- Error Handling ---

#[derive(Debug, thiserror::Error)]
pub enum ConversionError {
    #[error("Nod library error: {0}")]
    Nod(#[from] nod::Error),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Input file is not a valid Wii or GameCube disc: {0}")]
    InvalidDisc(String),
    #[error("Failed to calculate CRC32")]
    NoCrc32,
}

type Result<T> = std::result::Result<T, ConversionError>;

// --- I/O Handling for Split Files ---

/// Manages writing data across multiple split files for WBFS.
struct SplitWriter {
    base_path: PathBuf,
    split_size: u64,
    files: Vec<Option<File>>,
    total_written: u64,
}

impl SplitWriter {
    /// Creates a new `SplitWriter`.
    /// The `base_path` should not include an extension.
    fn new(base_path: &Path, split_size: u64) -> Self {
        Self {
            base_path: base_path.to_path_buf(),
            split_size,
            files: Vec::new(),
            total_written: 0,
        }
    }

    /// Generates the filename for a given split index. This is an internal helper.
    /// index 0 -> .wbfs
    /// index 1 -> .wbf1
    /// ...
    fn get_filename(&self, index: usize) -> PathBuf {
        let ext = match index {
            0 => "wbfs",
            n => &format!("wbf{}", n),
        };
        self.base_path.with_extension(ext)
    }

    /// Writes a buffer of data sequentially.
    fn write_all(&mut self, mut buf: &[u8]) -> io::Result<()> {
        trace!(
            "Writing {} bytes at offset {}",
            buf.len(),
            self.total_written
        );
        let split_size = self.split_size; // Avoid borrow checker issue.
        while !buf.is_empty() {
            let split_index = (self.total_written / split_size) as usize;
            let offset_in_split = self.total_written % split_size;

            let file = self.get_file(split_index)?;

            let bytes_to_write = (split_size - offset_in_split).min(buf.len() as u64) as usize;
            file.write_all(&buf[..bytes_to_write])?;

            buf = &buf[bytes_to_write..];
            self.total_written += bytes_to_write as u64;
        }
        Ok(())
    }

    /// Writes a buffer of data at a specific absolute offset.
    fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()> {
        trace!("Writing {} bytes at absolute offset {}", buf.len(), offset);
        let split_index = (offset / self.split_size) as usize;
        let offset_in_split = offset % self.split_size;

        let file = self.get_file(split_index)?;
        file.seek(SeekFrom::Start(offset_in_split))?;
        file.write_all(buf)
    }

    /// Opens (or gets a handle to) the file for a given split index.
    fn get_file(&mut self, index: usize) -> io::Result<&mut File> {
        if index >= self.files.len() {
            self.files.resize_with(index + 1, || None);
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

    /// Truncates the files to match the final total size.
    fn finalize(&mut self) -> io::Result<()> {
        info!(
            "Final WBFS size: {} bytes. Truncating files...",
            self.total_written
        );
        let mut remaining_size = self.total_written;

        for i in 0..self.files.len() {
            let filename = self.get_filename(i);
            if remaining_size > 0 {
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
            } else if filename.exists() {
                debug!("Removing unused split file: {}", filename.display());
                fs::remove_file(filename)?;
            }
        }
        Ok(())
    }
}

fn get_thread_count() -> (usize, usize) {
    let cpus = num_cpus::get();

    let preloader_threads = if cpus <= 4 {
        1
    } else if cpus <= 8 {
        2
    } else {
        4
    };

    let processor_threads = cpus - preloader_threads;

    (preloader_threads, processor_threads)
}

/// Public entry point for the conversion process.
///
/// # Arguments
/// * `input_path` - Path to the source Wii or GameCube disc image.
/// * `output_dir` - Path to the directory where output files will be created.
pub fn convert(
    input_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    mut progress_callback: impl FnMut(u64, u64),
) -> Result<()> {
    let input_path = input_path.as_ref();
    let output_dir = output_dir.as_ref();

    info!("Opening disc image: {}", input_path.display());

    // Set the number of threads based on the number of available CPUs.
    let (preloader_threads, processor_threads) = get_thread_count();

    // Make disc mutable to allow for direct copying for ISO conversion.
    let disc = DiscReader::new(
        input_path,
        &DiscOptions {
            partition_encryption: PartitionEncryption::Original,
            preloader_threads,
        },
    )?;

    // --- Common Path Setup ---
    let header = disc.header();
    let game_id = header.game_id_str();
    let game_title = header.game_title_str();
    let sanitized_title = sanitize(game_title);
    let game_dir_name = format!("{} [{}]", sanitized_title, game_id);

    if header.is_wii() {
        // --- Wii to Split WBFS Conversion ---
        info!("Detected Wii disc. Converting to split WBFS format.");
        let game_output_dir = output_dir.join("wbfs").join(&game_dir_name);

        // Check if game output directory already exists
        if game_output_dir.exists() {
            info!(
                "Game directory already exists at {}. Skipping conversion.",
                game_output_dir.display()
            );
            return Ok(());
        }

        info!("Creating game directory: {}", game_output_dir.display());
        fs::create_dir_all(&game_output_dir)?;
        // The base path should not contain an extension.
        let base_path = game_output_dir.join(game_id);

        let mut split_writer = SplitWriter::new(&base_path, SPLIT_SIZE);

        // Configure the WBFS writer using nod's defaults.
        let format_options = FormatOptions::new(Format::Wbfs);

        info!("Initializing WBFS writer...");
        let disc_writer = DiscWriter::new(disc, &format_options)?;

        let process_options = ProcessOptions {
            processor_threads,
            digest_crc32: true,
            digest_md5: false, // MD5 is slow, skip it
            digest_sha1: true,
            digest_xxh64: true,
        };
        info!(
            "Processing disc with {} threads...",
            preloader_threads + processor_threads
        );

        let finalization = disc_writer.process(
            |data, progress, total| {
                if !data.is_empty() {
                    split_writer.write_all(data.as_ref())?;
                }
                progress_callback(progress, total);
                Ok(())
            },
            &process_options,
        )?;

        info!("Writing final WBFS header...");
        if !finalization.header.is_empty() {
            split_writer.write_all_at(0, finalization.header.as_ref())?;
        }

        split_writer.finalize()?;
    } else if header.is_gamecube() {
        // --- GameCube to NKit-scrubbed ISO (using CISO format) ---
        info!("Detected GameCube disc. Converting to NKit-scrubbed ISO format.");
        let game_output_dir = output_dir.join("games").join(&game_dir_name);

        // Check if game output directory already exists
        if game_output_dir.exists() {
            info!(
                "Game directory already exists at {}. Skipping conversion.",
                game_output_dir.display()
            );
            return Ok(());
        }

        info!("Creating game directory: {}", game_output_dir.display());
        fs::create_dir_all(&game_output_dir)?;

        // --- Nintendont Naming Convention Logic ---
        let iso_filename = match header.disc_num {
            0 => "game.iso".to_string(),
            n => format!("disc{}.iso", n + 1),
        };
        let output_iso_path = game_output_dir.join(iso_filename);
        // --- End Nintendont Naming ---

        info!("Creating output file: {}", output_iso_path.display());
        let mut out_file = File::create(&output_iso_path)?;

        // Configure the CISO writer. In `nod`, CISO is uncompressed and
        // serves as the format for NKit-scrubbed ISOs.
        let format_options = FormatOptions::new(Format::Ciso);

        info!("Initializing CISO (NKit) writer...");
        let disc_writer = DiscWriter::new(disc, &format_options)?;

        let process_options = ProcessOptions {
            processor_threads,
            digest_crc32: true,
            digest_md5: false, // MD5 is slow, skip it
            digest_sha1: true,
            digest_xxh64: true,
        };
        info!(
            "Processing disc with {} threads...",
            preloader_threads + processor_threads
        );

        // The CISO writer requires a header to be written at the end.
        // We first write the data blocks, then seek back to write the header.
        let finalization = disc_writer.process(
            |data, progress, total| {
                if !data.is_empty() {
                    out_file.write_all(data.as_ref())?;
                }
                progress_callback(progress, total);
                Ok(())
            },
            &process_options,
        )?;

        info!("Writing final CISO (NKit) header...");
        if !finalization.header.is_empty() {
            out_file.rewind()?;
            out_file.write_all(finalization.header.as_ref())?;
        }
        out_file.flush()?;
    } else {
        return Err(ConversionError::InvalidDisc(
            "Input file is not a valid Wii or GameCube disc.".to_string(),
        ));
    }

    info!("Conversion complete!");
    Ok(())
}

pub fn crc32(
    input_path: impl AsRef<Path>,
    mut progress_callback: impl FnMut(u64, u64),
) -> Result<u32> {
    let input_path = input_path.as_ref();
    let (preloader_threads, processor_threads) = get_thread_count();

    let disc = DiscReader::new(
        input_path,
        &DiscOptions {
            partition_encryption: PartitionEncryption::Original,
            preloader_threads,
        },
    )?;
    let disc_writer = DiscWriter::new(disc, &FormatOptions::default())?;

    // Process the disc to calculate hashes
    let finalization = disc_writer.process(
        |_, progress, total| {
            progress_callback(progress, total);
            Ok(())
        },
        &ProcessOptions {
            processor_threads,
            digest_crc32: true,
            digest_md5: false, // MD5 is slow, skip it
            digest_sha1: true,
            digest_xxh64: true,
        },
    )?;

    let crc32 = finalization.crc32.ok_or(ConversionError::NoCrc32);

    crc32
}

pub fn archive(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    mut progress_callback: impl FnMut(u64, u64),
) -> Result<()> {
    let input_path = input_path.as_ref();
    let output_path = output_path.as_ref();
    let (preloader_threads, processor_threads) = get_thread_count();

    let disc = DiscReader::new(
        input_path,
        &DiscOptions {
            partition_encryption: PartitionEncryption::Original,
            preloader_threads,
        },
    )?;

    let mut output_file = File::create(output_path)?;

    let options = FormatOptions {
        format: Format::Rvz,
        compression: Compression::Zstandard(19),
        block_size: Format::Rvz.default_block_size(),
    };

    let writer = DiscWriter::new(disc, &options)?;

    let process_options = ProcessOptions {
        processor_threads,
        digest_crc32: true,
        digest_md5: false, // MD5 is slow, skip it
        digest_sha1: true,
        digest_xxh64: true,
    };

    let finalization = writer.process(
        |data, progress, total| {
            output_file.write_all(data.as_ref())?;
            progress_callback(progress, total);
            Ok(())
        },
        &process_options,
    )?;

    if !finalization.header.is_empty() {
        output_file.rewind()?;
        output_file.write_all(finalization.header.as_ref())?;
    }
    output_file.flush()?;

    Ok(())
}
