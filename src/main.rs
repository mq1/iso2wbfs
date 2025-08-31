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
use tracing_subscriber::EnvFilter;

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
    init_subscriber(cli.verbose);

    match cli.command {
        Commands::Convert(args) => {
            let input_file = &args.input_file;
            let output_directory = &args.output_directory;
            tracing::info!(
                input_file = %input_file.display(),
                output_directory = %output_directory.display(),
                "Starting conversion."
            );
            run_with_progress("Conversion", |progress_cb| {
                convert(input_file, output_directory, progress_cb)
            })?;
            tracing::info!("Conversion completed successfully.");
        }
        Commands::Crc32(args) => {
            let input_file = &args.input_file;
            tracing::info!(input_file = %input_file.display(), "Calculating CRC32 checksum.");
            let crc = run_with_progress("CRC32 calculation", |progress_cb| {
                crc32(input_file, progress_cb)
            })?;
            println!("{:08X}", crc);
            tracing::info!("CRC32 calculation completed successfully.");
        }
        Commands::Archive(args) => {
            let input_file = &args.input_file;
            let output_file = &args.output_file;
            tracing::info!(
                input_file = %input_file.display(),
                output_file = %output_file.display(),
                "Archiving to RVZ format."
            );
            run_with_progress("Archiving", |progress_cb| {
                archive(input_file, output_file, progress_cb)
            })?;
            tracing::info!("Archiving completed successfully.");
        }
    }

    Ok(())
}

/// Initializes the JSON logger with a verbosity level controlled by the `-v` flag.
#[cfg(feature = "cli")]
fn init_subscriber(verbosity: u8) {
    let filter = match verbosity {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter));

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .json()
        .init();
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