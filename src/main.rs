// SPDX-FileCopyrightText: 2025 Manuel Quarneti <mq1@ik.me>
// SPDX-License-Identifier: GPL-2.0-only

use bpaf::{OptionParser, Parser, construct, positional, short};
use std::path::PathBuf;

/// A plain data structure to hold the parsed command-line arguments.
#[derive(Debug, Clone)]
struct Options {
    verbose: u64,
    input_file: PathBuf,
    output_directory: PathBuf,
}

/// Defines the command-line argument parser using bpaf's functional style.
fn options() -> OptionParser<Options> {
    // Parser for the 'verbose' flag. It's a flag that can be repeated.
    let verbose = short('v')
        .long("verbose")
        .help("Increase verbosity level. Can be used multiple times.")
        .req_flag(()) // Indicates it's a flag, not an option with a value.
        .many() // Allows the flag to be repeated (e.g., -vv).
        .map(|v| v.len() as u64); // The final value is the number of occurrences.

    // Parser for the positional input file argument.
    let input_file = positional::<PathBuf>("INPUT_FILE")
        .help("The input Wii disc image file (.iso, .wbfs, .ciso, etc.).");

    // Parser for the positional output directory argument.
    let output_directory = positional::<PathBuf>("OUTPUT_DIRECTORY")
        .help("The directory where the output .wbfs files will be created.");

    // The `construct!` macro combines the individual parsers into the Options struct.
    let parser = construct!(Options {
        verbose,
        input_file,
        output_directory,
    });

    // Attach metadata like description and version to the parser.
    parser
        .to_options()
        .descr("A Rust utility to convert Wii disc images to the split WBFS file format, replicating the default behavior of wbfs_file v2.9.")
        .version(env!("CARGO_PKG_VERSION"))
}

fn main() {
    let options = options().run();

    let log_level = match options.verbose {
        0 => log::LevelFilter::Info,
        1 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };

    env_logger::Builder::new()
        .filter_level(log_level)
        .format_timestamp(None)
        .format_target(false)
        .init();

    log::info!(
        "Starting conversion of '{}' to '{}'",
        options.input_file.display(),
        options.output_directory.display()
    );

    if let Err(e) = iso2wbfs::convert(&options.input_file, &options.output_directory) {
        log::error!("Conversion failed: {}", e);
        std::process::exit(1);
    }

    log::info!("Conversion completed successfully.");
}
