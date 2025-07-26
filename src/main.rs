// SPDX-FileCopyrightText: 2025 Manuel Quarneti <mq1@ik.me>
// SPDX-License-Identifier: GPL-2.0-only

use clap::Parser;
use iso2wbfs::{WbfsConverter, WbfsError};
use log::{error, info};
use std::path::PathBuf;
use std::process::exit;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the input Wii ISO file.
    #[arg()]
    iso_path: PathBuf,

    /// Directory to save the WBFS file(s). Will be created if it doesn't exist.
    #[arg()]
    output_dir: PathBuf,

    /// Enable detailed debug logging.
    #[arg(short, long)]
    verbose: bool,
}

fn main() {
    let args = Args::parse();

    // Setup logging
    let log_level = if args.verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    info!(
        "Starting conversion for: {}",
        args.iso_path.display()
    );

    match WbfsConverter::new(&args.iso_path, &args.output_dir) {
        Ok(mut converter) => {
            if let Err(e) = converter.convert() {
                handle_error(e);
            }
        }
        Err(e) => {
            handle_error(e);
        }
    }
}

fn handle_error(e: WbfsError) {
    error!("A critical error occurred: {}", e);
    if let WbfsError::Io(io_err) = e {
        error!("Underlying I/O error: {}", io_err);
    }
    exit(1);
}
