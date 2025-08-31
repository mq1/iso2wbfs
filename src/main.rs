// SPDX-FileCopyrightText: 2025 Manuel Quarneti <mq1@ik.me>
// SPDX-License-Identifier: GPL-2.0-only

#[cfg(feature = "cli")]
use anyhow::Result;
#[cfg(feature = "cli")]
use argh::FromArgs;
#[cfg(feature = "cli")]
use indicatif::{ProgressBar, ProgressStyle};
#[cfg(feature = "cli")]
use std::{
    mem::transmute,
    path::{Path, PathBuf},
};

#[cfg(feature = "cli")]
#[derive(FromArgs, Debug)]
/// A Rust utility to convert Wii and GameCube disc images.
struct TopLevel {
    /// increase logging verbosity (-v = info, -vv = debug, -vvv = trace)
    #[argh(switch, short = 'v')]
    verbose: i32,

    #[argh(subcommand)]
    command: SubCommand,
}

#[cfg(feature = "cli")]
#[derive(FromArgs, Debug)]
#[argh(subcommand)]
enum SubCommand {
    Convert(ConvertCommand),
    Crc32(Crc32Command),
    Archive(ArchiveCommand),
}

#[cfg(feature = "cli")]
#[derive(FromArgs, Debug)]
/// This tool converts Wii disc images (e.g., .iso, .wbfs) into the split WBFS
/// file format, replicating the default behavior of wbfs_file v2.9.
///
/// It also converts GameCube disc images into standard .iso files.
///
/// Output is organized into 'wbfs' (for Wii) and 'games' (for GameCube)
/// subdirectories within the specified output directory.
#[argh(subcommand, name = "convert")]
struct ConvertCommand {
    /// the input Wii or GameCube disc image file (.iso, .wbfs, .ciso, etc.)
    #[argh(positional)]
    input_file: PathBuf,

    /// the directory where the output files will be created
    #[argh(positional)]
    output_directory: PathBuf,
}

#[cfg(feature = "cli")]
#[derive(FromArgs, Debug)]
/// Calculate CRC32 checksum of a disc image.
#[argh(subcommand, name = "crc32")]
struct Crc32Command {
    /// the input Wii or GameCube disc image file (.iso, .wbfs, .ciso, etc.)
    #[argh(positional)]
    input_file: PathBuf,
}

#[cfg(feature = "cli")]
#[derive(FromArgs, Debug)]
/// Archive a disc image to RVZ format.
#[argh(subcommand, name = "archive")]
struct ArchiveCommand {
    /// the input Wii or GameCube disc image file (.iso, .wbfs, .ciso, etc.)
    #[argh(positional)]
    input_file: PathBuf,

    /// the path for the output RVZ file
    #[argh(positional)]
    output_file: PathBuf,
}

#[cfg(feature = "cli")]
fn main() -> Result<()> {
    let options: TopLevel = argh::from_env();
    init_logger(options.verbose as usize);

    match options.command {
        SubCommand::Convert(c) => {
            run_conversion(&c.input_file, &c.output_directory)?;
        }
        SubCommand::Crc32(c) => {
            run_crc32(&c.input_file)?;
        }
        SubCommand::Archive(c) => {
            run_archive(&c.input_file, &c.output_file)?;
        }
    }

    Ok(())
}

/// Initializes the logger with a verbosity level controlled by the `-v` flag.
#[cfg(feature = "cli")]
fn init_logger(verbosity: usize) {
    let level_num = verbosity.min(3) + 2;
    let level = unsafe { transmute(level_num) }; // don't ask
    env_logger::Builder::new().filter_level(level).init();
}

#[cfg(feature = "cli")]
fn create_progress_bar() -> ProgressBar {
    let pb = ProgressBar::new(0);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed}] [{bar}] {bytes}/{total_bytes} (~{eta} remaining)")
            .unwrap()
            .progress_chars("=> "),
    );
    pb
}

#[cfg(feature = "cli")]
fn run_conversion(input_file: &Path, output_directory: &Path) -> Result<()> {
    log::info!(
        "Starting conversion of '{}' into output directory '{}'",
        input_file.display(),
        output_directory.display()
    );

    let pb = create_progress_bar();

    iso2wbfs::convert(input_file, output_directory, |progress, total| {
        if pb.length().unwrap_or(0) == 0 {
            pb.set_length(total);
        }
        pb.set_position(progress);
    })?;

    pb.finish_with_message("Conversion finished");

    log::info!("Conversion completed successfully.");
    Ok(())
}

#[cfg(feature = "cli")]
fn run_crc32(input_file: &Path) -> Result<()> {
    log::info!("Calculating CRC32 for '{}'", input_file.display());

    let pb = create_progress_bar();

    let crc = iso2wbfs::crc32(input_file, |progress, total| {
        if pb.length().unwrap_or(0) == 0 {
            pb.set_length(total);
        }
        pb.set_position(progress);
    })?;

    pb.finish_with_message("CRC32 calculation finished");

    println!("{:08X}", crc);

    log::info!("CRC32 calculation completed successfully.");
    Ok(())
}

#[cfg(feature = "cli")]
fn run_archive(input_file: &Path, output_file: &Path) -> Result<()> {
    log::info!(
        "Archiving '{}' to '{}'",
        input_file.display(),
        output_file.display()
    );

    let pb = create_progress_bar();

    iso2wbfs::archive(input_file, output_file, |progress, total| {
        if pb.length().unwrap_or(0) == 0 {
            pb.set_length(total);
        }
        pb.set_position(progress);
    })?;

    pb.finish_with_message("Archiving finished");

    log::info!("Archiving completed successfully.");
    Ok(())
}

#[cfg(not(feature = "cli"))]
fn main() {
    println!("This binary is disabled. To enable it, compile with the `cli` feature.");
}