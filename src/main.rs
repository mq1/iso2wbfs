// SPDX-FileCopyrightText: 2025 Manuel Quarneti <mq1@ik.me>
// SPDX-License-Identifier: GPL-2.0-only

use clap::{Parser, builder::Styles};
use color_eyre::eyre::Result;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

/// A Rust utility to convert Wii and GameCube disc images.
///
/// This tool converts Wii disc images (e.g., .iso, .wbfs) into the split WBFS
/// file format, replicating the default behavior of wbfs_file v2.9.
///
/// It also converts GameCube disc images into standard .iso files.
///
/// Output is organized into 'wbfs' (for Wii) and 'games' (for GameCube)
/// subdirectories within the specified output directory.
#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about, styles = Styles::styled())]
struct Options {
    /// Increase verbosity level (-v for debug, -vv for trace).
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// The input Wii or GameCube disc image file (.iso, .wbfs, .ciso, etc.).
    #[arg(name = "INPUT_FILE")]
    input_file: PathBuf,

    /// The directory where the output files will be created.
    #[arg(name = "OUTPUT_DIRECTORY")]
    output_directory: PathBuf,
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let options = Options::parse();

    init_logger(options.verbose);

    run_conversion(&options)?;

    Ok(())
}

/// Initializes the logger with a verbosity level controlled by the `-v` flag.
fn init_logger(verbosity: u8) {
    let filter_level = match verbosity {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter_level));

    tracing_subscriber::registry()
        .with(fmt::layer().with_writer(std::io::stderr))
        .with(filter)
        .init();
}

/// Runs the main conversion logic by calling the library function.
fn run_conversion(options: &Options) -> Result<()> {
    tracing::info!(
        "Starting conversion of '{}' into output directory '{}'",
        options.input_file.display(),
        options.output_directory.display()
    );

    // 1. Create a new progress bar.
    let pb = ProgressBar::new(0);
    // 2. Set a style for the progress bar for better visual feedback.
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed}] [{bar}] {bytes}/{total_bytes} (~{eta} remaining)")
            .unwrap()
            .progress_chars("=> "),
    );

    // Call the library's main conversion function.
    // It now internally handles whether the disc is a Wii or GameCube image.
    iso2wbfs::convert(
        &options.input_file,
        &options.output_directory,
        // 3. Implement the callback to update the progress bar.
        |progress, total| {
            // Set the total length of the bar when it's first known.
            if pb.length().unwrap_or(0) == 0 {
                pb.set_length(total);
            }
            // Update the current position of the bar.
            pb.set_position(progress);
        },
    )?;

    // 4. Finish the progress bar once the conversion is done.
    pb.finish_with_message("Conversion finished");

    tracing::info!("Conversion completed successfully.");
    Ok(())
}
