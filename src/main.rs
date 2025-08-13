// SPDX-FileCopyrightText: 2025 Manuel Quarneti <mq1@ik.me>
// SPDX-License-Identifier: GPL-2.0-only

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(
    long_about = "A Rust utility to convert Wii disc images to the split WBFS file format, replicating the default behavior of wbfs_file v2.9."
)]
struct Args {
    /// Increase verbosity level. Can be used multiple times.
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// The input Wii disc image file (.iso, .wbfs, .ciso, etc.).
    #[arg(name = "INPUT_FILE")]
    input_file: PathBuf,

    /// The directory where the output .wbfs files will be created.
    #[arg(name = "OUTPUT_DIRECTORY")]
    output_directory: PathBuf,
}

use tracing::instrument;
use tracing_subscriber::FmtSubscriber;

#[instrument]
fn main() {
    let args = Args::parse();

    let level = match args.verbose {
        0 => tracing::Level::INFO,
        1 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .without_time()
        .with_target(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    tracing::info!(
        "Starting conversion of '{}' to '{}'",
        args.input_file.display(),
        args.output_directory.display()
    );

    if let Err(e) = iso2wbfs::convert(&args.input_file, &args.output_directory) {
        tracing::error!("Conversion failed: {e}");
        std::process::exit(1);
    }

    tracing::info!("Conversion completed successfully.");
}
