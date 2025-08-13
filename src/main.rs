// SPDX-FileCopyrightText: 2025 Manuel Quarneti <mq1@ik.me>
// SPDX-License-Identifier: GPL-2.0-only

use clap::Parser;
use std::path::PathBuf;
// Corrected: Import the necessary extension traits for `.with()` and `.init()`
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

/// A Rust utility to convert Wii disc images to the split WBFS file format,
/// replicating the default behavior of wbfs_file v2.9.
#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct Options {
    /// Increase verbosity level (-v for debug, -vv for trace).
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// The input Wii disc image file (.iso, .wbfs, .ciso, etc.).
    #[arg(name = "INPUT_FILE")]
    input_file: PathBuf,

    /// The directory where the output .wbfs files will be created.
    #[arg(name = "OUTPUT_DIRECTORY")]
    output_directory: PathBuf,
}

fn main() {
    let options = Options::parse();

    // --- Logger Initialization ---
    let filter_level = match options.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter_level));

    // The `.with()` and `.init()` methods are now available because their
    // providing traits (SubscriberExt, SubscriberInitExt) are in scope.
    tracing_subscriber::registry()
        .with(fmt::layer().with_writer(std::io::stderr))
        .with(filter)
        .init();

    // --- Execute Conversion ---
    tracing::info!(
        "Starting conversion of '{}' to '{}'",
        options.input_file.display(),
        options.output_directory.display()
    );

    if let Err(e) = iso2wbfs::convert(&options.input_file, &options.output_directory) {
        tracing::error!("Conversion failed: {}", e);
        std::process::exit(1);
    }

    tracing::info!("Conversion completed successfully.");
}
