// SPDX-FileCopyrightText: 2025 Manuel Quarneti <mq1@ik.me>
// SPDX-License-Identifier: GPL-2.0-only

//! A Rust library to convert Wii disc images to the split WBFS file format,
//! replicating the default behavior of `wbfs_file v2.9`.

use nod::common::Format;
use nod::read::{DiscOptions, DiscReader};
use nod::write::{DiscWriter, FormatOptions, ProcessOptions};
use sanitize_filename_reader_friendly::sanitize;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use tracing::{debug, info, trace};

// --- Constants ---

/// The fixed split size for output files: 4 GiB - 32 KiB.
const SPLIT_SIZE: u64 = (4 * 1024 * 1024 * 1024) - (32 * 1024);

// --- Error Handling ---

#[derive(Debug, thiserror::Error)]
pub enum ConversionError {
    #[error("Nod library error: {0}")]
    Nod(#[from] nod::Error),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Input file is not a valid Wii disc: {0}")]
    InvalidDisc(String),
}

type Result<T> = std::result::Result<T, ConversionError>;

// --- I/O Handling for Split Files ---

/// Manages writing data across multiple split files.
struct SplitWriter {
    base_path: PathBuf,
    split_size: u64,
    files: Vec<Option<File>>,
    total_written: u64,
}

impl SplitWriter {
    /// Creates a new `SplitWriter`.
    fn new(base_path: &Path, split_size: u64) -> Self {
        Self {
            base_path: base_path.to_path_buf(),
            split_size,
            files: Vec::new(),
            total_written: 0,
        }
    }

    /// Generates the filename for a given split index.
    fn get_filename(&self, index: usize) -> PathBuf {
        if index == 0 {
            return self.base_path.clone();
        }
        let mut path_str = self.base_path.to_string_lossy().to_string();
        // Replaces `.wbfs` with `.wbf1`, `.wbf2`, etc.
        path_str.pop();
        path_str.push_str(&index.to_string());
        PathBuf::from(path_str)
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

/// Public entry point for the conversion process.
///
/// # Arguments
/// * `input_path` - Path to the source Wii disc image.
/// * `output_dir` - Path to the directory where output files will be created.
pub fn convert(input_path: &Path, output_dir: &Path) -> Result<()> {
    info!("Opening disc image: {}", input_path.display());
    let disc = DiscReader::new(input_path, &DiscOptions::default())?;

    if !disc.header().is_wii() {
        return Err(ConversionError::InvalidDisc(
            "Input file is not a Wii disc.".to_string(),
        ));
    }

    // --- Path setup ---
    let header = disc.header();
    let game_id = header.game_id_str();
    let game_title = header.game_title_str();
    let sanitized_title = sanitize(game_title);
    let game_dir_name = format!("{} [{}]", sanitized_title, game_id);
    let game_output_dir = output_dir.join(game_dir_name);
    info!("Creating game directory: {}", game_output_dir.display());
    fs::create_dir_all(&game_output_dir)?;
    let base_path = game_output_dir.join(format!("{}.wbfs", game_id));
    // --- End Path setup ---

    let mut split_writer = SplitWriter::new(&base_path, SPLIT_SIZE);

    // Configure the WBFS writer using nod's defaults.
    let format_options = FormatOptions::new(Format::Wbfs);

    info!("Initializing WBFS writer...");
    let disc_writer = DiscWriter::new(disc, &format_options)?;

    // Set the number of threads to use (one less than the number of physical cores)
    let processor_threads = (num_cpus::get_physical() - 1).min(1);

    let process_options = ProcessOptions {
        processor_threads,
        ..Default::default()
    };
    info!("Processing disc with {} threads...", processor_threads);

    let finalization = disc_writer.process(
        |data, _progress, _total| {
            if !data.is_empty() {
                split_writer.write_all(data.as_ref())?;
            }
            Ok(())
        },
        &process_options,
    )?;

    info!("Writing final WBFS header...");
    if !finalization.header.is_empty() {
        split_writer.write_all_at(0, finalization.header.as_ref())?;
    }

    split_writer.finalize()?;

    info!("Conversion complete!");
    Ok(())
}
