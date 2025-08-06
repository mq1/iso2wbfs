# iso2wbfs

A simple library / command-line tool to convert Nintendo Wii Disc images to WBFS.

## Features

- Simple CLI interface
- Cross-platform (macOS, Linux, Windows)
- Supports all Disc files that NOD supports

## Build

Clone and build with Cargo:

```sh
git clone https://github.com/mq1/iso2wbfs.git
cd iso2wbfs
cargo build --release --features cli --bin iso2wbfs
```

## Usage

```sh
./target/release/iso2wbfs -h
```

## License

GPL-2.0-only. Portions from wbfs_file 2.9 (GPL-2.0-only) and NOD (MIT).

## Credits

- Based on [wbfs_file 2.9](https://github.com/FunctionDJ/wbfs_file_2.9)
- Using [NOD](https://github.com/encounter/nod)
