// SPDX-FileCopyrightText: 2025 Manuel Quarneti <mq1@ik.me>
// SPDX-License-Identifier: GPL-2.0-only

#[cfg(feature = "cli")]
use anyhow::{Context, Result};
#[cfg(feature = "cli")]
use clap::{Parser, Subcommand};
#[cfg(feature = "cli")]
use indicatif::{ProgressBar, ProgressStyle};
#[cfg(feature = "cli")]
use iso2wbfs::{archive, convert, crc32};
#[cfg(feature = "cli")]
use std::path::PathBuf;

#[cfg(feature = "cli")]
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "A Rust utility to convert and manage Wii and GameCube disc images.",
    long_about = "This tool converts Wii and GameCube disc images to various formats, calculates checksums, and handles archiving to RVZ."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Increase logging verbosity (-v = info, -vv = debug, -vvv = trace).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,
}

#[cfg(feature = "cli")]
#[derive(Subcommand, Debug)]
enum Commands {
    /// Convert a disc image to a different format.
    Convert(ConvertArgs),
    /// Calculate the CRC32 checksum of a disc image.
    Crc32(Crc32Args),
    /// Archive a disc image to the RVZ format.
    Archive(ArchiveArgs),
}

#[cfg(feature = "cli")]
#[derive(Parser, Debug)]
pub struct ConvertArgs {
    /// The input Wii or GameCube disc image file (.iso, .wbfs, .ciso, etc.).
    #[arg(required = true)]
    input_file: PathBuf,
    /// The directory where the output files will be created.
    #[arg(required = true)]
    output_directory: PathBuf,
}

#[cfg(feature = "cli")]
#[derive(Parser, Debug)]
pub struct Crc32Args {
    /// The input Wii or GameCube disc image file (.iso, .wbfs, .ciso, etc.).
    #[arg(required = true)]
    input_file: PathBuf,
}

#[cfg(feature = "cli")]
#[derive(Parser, Debug)]
pub struct ArchiveArgs {
    /// The input Wii or GameCube disc image file (.iso, .wbfs, .ciso, etc.).
    #[arg(required = true)]
    input_file: PathBuf,
    /// The path for the output RVZ file.
    #[arg(required = true)]
    output_file: PathBuf,
}

#[cfg(feature = "cli")]
fn main() -> Result<()> {
    let cli = Cli::parse();
    init_logger(cli.verbose);

    match cli.command {
        Commands::Convert(args) => {
            log::info!(
                "Converting '{}' to output directory '{}'",
                args.input_file.display(),
                args.output_directory.display()
            );
            run_with_progress("Conversion", |progress_cb| {
                convert(&args.input_file, &args.output_directory, progress_cb)
            })?;
            log::info!("Conversion completed successfully.");
        }
        Commands::Crc32(args) => {
            log::info!("Calculating CRC32 for '{}'", args.input_file.display());
            let crc = run_with_progress("CRC32 calculation", |progress_cb| {
                crc32(&args.input_file, progress_cb)
            })?;
            println!("{:08X}", crc);
            log::info!("CRC32 calculation completed successfully.");
        }
        Commands::Archive(args) => {
            log::info!(
                "Archiving '{}' to '{}'",
                args.input_file.display(),
                args.output_file.display()
            );
            run_with_progress("Archiving", |progress_cb| {
                archive(&args.input_file, &args.output_file, progress_cb)
            })?;
            log::info!("Archiving completed successfully.");
        }
    }

    Ok(())
}

/// Initializes the logger with a verbosity level controlled by the `-v` flag.
#[cfg(feature = "cli")]
fn init_logger(verbosity: u8) {
    let level = match verbosity {
        0 => log::LevelFilter::Warn,
        1 => log::LevelFilter::Info,
        2 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };
    env_logger::Builder::new().filter_level(level).init();
}

/// A generic helper to run an operation with a progress bar.
#[cfg(feature = "cli")]
fn run_with_progress<F, T>(operation_name: &str, operation: F) -> Result<T>
where
    F: FnOnce(&dyn Fn(u64, u64)) -> Result<T>,
{
    let pb = ProgressBar::new(0);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} (~{eta})")
            .context("Failed to create progress bar style")?
            .progress_chars("=> "),
    );

    let progress_callback = |progress, total| {
        if pb.length().unwrap_or(0) != total {
            pb.set_length(total);
        }
        pb.set_position(progress);
    };

    let result = operation(&progress_callback);

    pb.finish_with_message(format!("{} finished", operation_name));
    result
}

#[cfg(not(feature = "cli"))]
fn main() {
    println!("This binary is disabled. To enable it, compile with the `cli` feature.");
}
