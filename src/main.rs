// SPDX-FileCopyrightText: 2025 Manuel Quarneti <mq1@ik.me>
// SPDX-License-Identifier: GPL-2.0-only

use clap::{Parser, builder::Styles};
use color_eyre::eyre::Result;
use std::path::PathBuf;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

/// A Rust utility to convert Wii disc images to the split WBFS file format,
/// replicating the default behavior of wbfs_file v2.9.
#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None, styles = Styles::styled())]
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

fn main() -> Result<()> {
    color_eyre::install()?;
    let options = Options::parse();

    init_logger(options.verbose);

    run_conversion(&options)?;

    Ok(())
}

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

fn run_conversion(options: &Options) -> Result<()> {
    tracing::info!(
        "Starting conversion of '{}' to '{}'",
        options.input_file.display(),
        options.output_directory.display()
    );

    iso2wbfs::convert(&options.input_file, &options.output_directory)?;

    tracing::info!("Conversion completed successfully.");
    Ok(())
}
