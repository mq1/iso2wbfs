// SPDX-FileCopyrightText: 2025 Manuel Quarneti <mq1@ik.me>
// SPDX-License-Identifier: GPL-2.0-only

//! A Rust library to convert Wii and GameCube disc images, replicating the
//! default behavior of `wbfs_file v2.9` for Wii and creating NKit-compatible
//! scrubbed ISOs for GameCube.

use anyhow::{Context, Result, bail};
use nod::common::{Compression, Format};
use nod::read::{DiscOptions, DiscReader, PartitionEncryption};
use nod::write::{DiscWriter, FormatOptions, ProcessOptions};
use sanitize_filename_reader_friendly::sanitize;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use tracing::{debug, info, instrument, trace};

/// The fixed split size for output files: 4 GiB - 32 KiB.
const SPLIT_SIZE: u64 = (4 * 1024 * 1024 * 1024) - (32 * 1024);

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
            bytes = buf.len(),
            offset = self.total_written,
            "Writing data sequentially"
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
        trace!(bytes = buf.len(), offset, "Writing data at absolute offset");
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
            debug!(path = %filename.display(), "Opening split file for writing");
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&filename)?;
            self.files[index] = Some(file);
        }

        Ok(self.files[index].as_mut().unwrap())
    }

    /// Truncates the files to match the final total size.
    fn finalize(&mut self) -> io::Result<()> {
        let mut remaining_size = self.total_written;
        debug!(
            final_size = self.total_written,
            "Finalizing WBFS files. Truncating..."
        );

        for i in 0..self.files.len() {
            let filename = self.get_filename(i);
            if remaining_size > 0 {
                if let Some(file) = self.files[i].as_mut() {
                    let size_for_this_file = remaining_size.min(self.split_size);
                    trace!(
                        path = %filename.display(),
                        size = size_for_this_file,
                        "Truncating file"
                    );
                    file.set_len(size_for_this_file)?;
                    remaining_size -= size_for_this_file;
                }
            } else if filename.exists() {
                trace!(path = %filename.display(), "Removing unused split file");
                fs::remove_file(&filename)?;
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
#[instrument(skip(progress_callback))]
pub fn convert(
    input_path: impl AsRef<Path> + std::fmt::Debug,
    output_dir: impl AsRef<Path> + std::fmt::Debug,
    mut progress_callback: impl FnMut(u64, u64),
) -> Result<()> {
    let input_path = input_path.as_ref();
    let output_dir = output_dir.as_ref();

    let (preloader_threads, processor_threads) = get_thread_count();

    let disc = DiscReader::new(
        input_path,
        &DiscOptions {
            partition_encryption: PartitionEncryption::Original,
            preloader_threads,
        },
    )
    .with_context(|| format!("Failed to read disc image: {}", input_path.display()))?;

    let header = disc.header();
    let game_id = header.game_id_str();
    let game_title = header.game_title_str();
    let sanitized_title = sanitize(game_title);
    let game_dir_name = format!("{} [{}]", sanitized_title, game_id);

    if header.is_wii() {
        info!(
            game_id,
            "Detected Wii disc. Converting to split WBFS format."
        );
        let game_output_dir = output_dir.join("wbfs").join(&game_dir_name);

        if game_output_dir.exists() {
            info!(
                path = %game_output_dir.display(),
                "Game directory already exists. Skipping conversion."
            );
            return Ok(());
        }

        fs::create_dir_all(&game_output_dir).with_context(|| {
            format!("Failed to create directory: {}", game_output_dir.display())
        })?;
        let base_path = game_output_dir.join(game_id);

        let mut split_writer = SplitWriter::new(&base_path, SPLIT_SIZE);
        let format_options = FormatOptions::new(Format::Wbfs);
        let disc_writer =
            DiscWriter::new(disc, &format_options).context("Failed to initialize WBFS writer")?;

        let process_options = ProcessOptions {
            processor_threads,
            digest_crc32: true,
            digest_md5: false,
            digest_sha1: true,
            digest_xxh64: true,
        };

        let finalization = disc_writer
            .process(
                |data, progress, total| {
                    if !data.is_empty() {
                        split_writer.write_all(data.as_ref())?;
                    }
                    progress_callback(progress, total);
                    Ok(())
                },
                &process_options,
            )
            .context("Failed to process disc for WBFS conversion")?;

        if !finalization.header.is_empty() {
            split_writer
                .write_all_at(0, finalization.header.as_ref())
                .context("Failed to write final WBFS header")?;
        }

        split_writer
            .finalize()
            .context("Failed to finalize split writer")?;
    } else if header.is_gamecube() {
        info!(
            game_id,
            "Detected GameCube disc. Converting to NKit-scrubbed ISO format."
        );
        let game_output_dir = output_dir.join("games").join(&game_dir_name);

        if game_output_dir.exists() {
            info!(
                path = %game_output_dir.display(),
                "Game directory already exists. Skipping conversion."
            );
            return Ok(());
        }

        fs::create_dir_all(&game_output_dir).with_context(|| {
            format!("Failed to create directory: {}", game_output_dir.display())
        })?;

        let iso_filename = match header.disc_num {
            0 => "game.iso".to_string(),
            n => format!("disc{}.iso", n + 1),
        };
        let output_iso_path = game_output_dir.join(iso_filename);

        let mut out_file = File::create(&output_iso_path).with_context(|| {
            format!(
                "Failed to create output file: {}",
                output_iso_path.display()
            )
        })?;

        let format_options = FormatOptions::new(Format::Ciso);
        let disc_writer =
            DiscWriter::new(disc, &format_options).context("Failed to initialize CISO writer")?;

        let process_options = ProcessOptions {
            processor_threads,
            digest_crc32: true,
            digest_md5: false,
            digest_sha1: true,
            digest_xxh64: true,
        };

        let finalization = disc_writer
            .process(
                |data, progress, total| {
                    if !data.is_empty() {
                        out_file.write_all(data.as_ref())?;
                    }
                    progress_callback(progress, total);
                    Ok(())
                },
                &process_options,
            )
            .context("Failed to process disc for CISO conversion")?;

        if !finalization.header.is_empty() {
            out_file.rewind().context("Failed to rewind output file")?;
            out_file
                .write_all(finalization.header.as_ref())
                .context("Failed to write final CISO header")?;
        }
        out_file.flush().context("Failed to flush output file")?;
    } else {
        bail!("Input file is not a valid Wii or GameCube disc.");
    }

    info!("Conversion complete!");
    Ok(())
}

#[instrument(skip(progress_callback))]
pub fn crc32(
    input_path: impl AsRef<Path> + std::fmt::Debug,
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
    )
    .with_context(|| format!("Failed to read disc image: {}", input_path.display()))?;
    let disc_writer = DiscWriter::new(disc, &FormatOptions::default())
        .context("Failed to initialize disc writer")?;

    let finalization = disc_writer
        .process(
            |_, progress, total| {
                progress_callback(progress, total);
                Ok(())
            },
            &ProcessOptions {
                processor_threads,
                digest_crc32: true,
                digest_md5: false,
                digest_sha1: true,
                digest_xxh64: true,
            },
        )
        .context("Failed to process disc for CRC32 calculation")?;

    let crc32 = finalization
        .crc32
        .context("CRC32 digest was not calculated")?;

    info!(crc32 = %format!("{:08X}", crc32), "CRC32 calculation complete");
    Ok(crc32)
}

#[instrument(skip(progress_callback))]
pub fn archive(
    input_path: impl AsRef<Path> + std::fmt::Debug,
    output_dir: impl AsRef<Path> + std::fmt::Debug,
    game_name: impl AsRef<str> + std::fmt::Debug,
    mut progress_callback: impl FnMut(u64, u64),
) -> Result<PathBuf> {
    let input_path = input_path.as_ref();

    let sanitized_game_name = sanitize(game_name.as_ref());
    let output_path = output_dir
        .as_ref()
        .join(format!("{}.rvz", sanitized_game_name));

    let (preloader_threads, processor_threads) = get_thread_count();

    let disc = DiscReader::new(
        input_path,
        &DiscOptions {
            partition_encryption: PartitionEncryption::Original,
            preloader_threads,
        },
    )
    .with_context(|| format!("Failed to read disc image: {}", input_path.display()))?;

    let mut output_file = File::create(&output_path)
        .with_context(|| format!("Failed to create output file: {}", output_path.display()))?;

    let options = FormatOptions {
        format: Format::Rvz,
        compression: Compression::Zstandard(19),
        block_size: Format::Rvz.default_block_size(),
    };

    let writer = DiscWriter::new(disc, &options).context("Failed to initialize RVZ writer")?;

    let process_options = ProcessOptions {
        processor_threads,
        digest_crc32: true,
        digest_md5: false,
        digest_sha1: true,
        digest_xxh64: true,
    };

    let finalization = writer
        .process(
            |data, progress, total| {
                output_file.write_all(data.as_ref())?;
                progress_callback(progress, total);
                Ok(())
            },
            &process_options,
        )
        .context("Failed to process disc for RVZ archival")?;

    if !finalization.header.is_empty() {
        output_file.rewind().context("Failed to rewind RVZ file")?;
        output_file
            .write_all(finalization.header.as_ref())
            .context("Failed to write final RVZ header")?;
    }
    output_file.flush().context("Failed to flush RVZ file")?;

    info!("RVZ archival complete");

    Ok(output_path)
}
