# iso2wbfs

A simple library / command-line tool to convert Nintendo Wii / GameCube Disc images for playing on Wiis.

This is only a thin wrapper around [NOD](https://github.com/encounter/nod)

## Features

- Simple CLI interface
- Cross-platform (macOS, Linux, Windows)
- Supports all Disc files that NOD supports

## Building

This crate can be used as a library or as a command-line tool.

### As a command-line tool

To build the command-line tool, you need to enable the `cli` feature:

```sh
git clone https://github.com/mq1/iso2wbfs.git
cd iso2wbfs
cargo build --release --features cli
```

### As a library

To use `iso2wbfs` as a library, add it to your `Cargo.toml` like this:

```toml
[dependencies]
iso2wbfs = { git = "https://github.com/mq1/iso2wbfs", tag = "v1.2.7" }
```

By default, this will only include the library components. The command-line tool and its dependencies will not be
compiled.

## Usage

```sh
./target/release/iso2wbfs -h
```

## License

GPL-2.0-only. Portions from wbfs_file 2.9 (GPL-2.0-only) and NOD (MIT).

## Credits

- Based on [wbfs_file 2.9](https://github.com/FunctionDJ/wbfs_file_2.9)
- Using [NOD](https://github.com/encounter/nod)
