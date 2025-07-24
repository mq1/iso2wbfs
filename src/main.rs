// SPDX-FileCopyrightText: 2025 Manuel Quarneti <mq1@ik.me>
// SPDX-License-Identifier: GPL-2.0-only

use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use iso2wbfs::{ProgressUpdate, WbfsConverter, WbfsError};
use log::{error, info};
use std::path::PathBuf;
use std::process::exit;
use std::time::Duration;

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

    // Setup a single progress bar that we will manage across stages.
    let pb = ProgressBar::new(0); // Start with length 0
    pb.enable_steady_tick(Duration::from_millis(100));

    // Define the closure that will handle progress updates.
    let progress_callback = |update: ProgressUpdate| {
        match update {
            ProgressUpdate::ScrubbingStart => {
                pb.set_style(
                    ProgressStyle::default_spinner()
                    .template("{spinner:.green} [{elapsed_precise}] {wide_msg}")
                    .unwrap(),
                );
                pb.set_message("Building disc usage table (scrubbing)...");
            }
            ProgressUpdate::ConversionStart { total_blocks } => {
                pb.set_style(
                    ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {wide_msg}")
                    .unwrap()
                    .progress_chars("#>-"),
                );
                pb.set_length(total_blocks);
                pb.set_position(0);
                pb.set_message("Converting ISO to WBFS format...");
            }
            ProgressUpdate::ConversionUpdate { current_block } => {
                pb.set_position(current_block);
            }
            ProgressUpdate::Done => {
                pb.finish_with_message("Conversion complete!");
            }
        }
    };

    info!(
        "Starting conversion for: {}",
        args.iso_path.display()
    );

    match WbfsConverter::new(&args.iso_path, &args.output_dir) {
        Ok(mut converter) => {
            if let Err(e) = converter.convert(Some(&progress_callback)) {
                pb.abandon_with_message("Failed");
                handle_error(e);
            }
        }
        Err(e) => {
            pb.abandon_with_message("Failed");
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
