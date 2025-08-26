// SPDX-FileCopyrightText: 2025 Manuel Quarneti <mq1@ik.me>
// SPDX-License-Identifier: GPL-2.0-only

#[cfg(feature = "cli")]
use bpaf::Bpaf;
#[cfg(feature = "cli")]
use color_eyre::eyre::Result;
#[cfg(feature = "cli")]
use indicatif::{ProgressBar, ProgressStyle};
#[cfg(feature = "cli")]
use std::{mem::transmute, path::PathBuf};

/// A Rust utility to convert Wii and GameCube disc images.
///
/// This tool converts Wii disc images (e.g., .iso, .wbfs) into the split WBFS
/// file format, replicating the default behavior of wbfs_file v2.9.
///
/// It also converts GameCube disc images into standard .iso files.
///
/// Output is organized into 'wbfs' (for Wii) and 'games' (for GameCube)
/// subdirectories within the specified output directory.
#[cfg(feature = "cli")]
#[derive(Debug, Clone, Bpaf)]
#[bpaf(options, version)]
struct Options {
    /// Increase logging verbosity (-v = info, -vv = debug, -vvv = trace)
    #[bpaf(short('v'), long("verbose"), req_flag(()), many, map(|v| v.len() as usize))]
    verbose: usize,

    /// The input Wii or GameCube disc image file (.iso, .wbfs, .ciso, etc.).
    #[bpaf(positional("INPUT_FILE"))]
    input_file: PathBuf,

    /// The directory where the output files will be created.
    #[bpaf(positional("OUTPUT_DIRECTORY"))]
    output_directory: PathBuf,
}

#[cfg(feature = "cli")]
fn main() -> Result<()> {
    color_eyre::install()?;
    let options = options().run();
    init_logger(options.verbose);
    run_conversion(&options)?;

    Ok(())
}

/// Initializes the logger with a verbosity level controlled by the `-v` flag.
#[cfg(feature = "cli")]
fn init_logger(verbosity: usize) {
    let level_num = verbosity.min(3) + 2;
    let level = unsafe { transmute(level_num) }; // don't ask
    env_logger::Builder::new().filter_level(level).init();
}

/// Runs the main conversion logic by calling the library function.
#[cfg(feature = "cli")]
fn run_conversion(options: &Options) -> Result<()> {
    log::info!(
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

    log::info!("Conversion completed successfully.");
    Ok(())
}

#[cfg(not(feature = "cli"))]
fn main() {
    println!("This binary is disabled. To enable it, compile with the `cli` feature.");
}