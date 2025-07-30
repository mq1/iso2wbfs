# iso2wbfs

A wbfs_file 2.9 reverse engineering experiment.

I wanted to test the reverse-engineering capabilities of Gemini 2.5 Pro, and this seemed the perfect project.
I included the initial prompts I used and the original source code (packed in one .txt with code2prompt).
The reverse engineering was made with the temperature set at 0.4.

I made a Python script (running with uv is preferred) and a Rust library and cli.

Run the python script (uv):
```
uv run iso2wbfs.py ./input.iso ./out_dir
```

Compile the example Rust cli implementation with:
```
cargo run --release --features=cli -- ./input.iso ./out_dir
```

# Licenses

This project is distributed under the [GPL-2.0-only](https://spdx.org/licenses/GPL-2.0-only.html) license.

wbfs_file 2.9 is distributed under the [GPL-2.0-only](https://spdx.org/licenses/GPL-2.0-only.html) license.

rvz-1.0.3 is distributed under the [BSD-3-Clause](https://spdx.org/licenses/BSD-3-Clause.html) license.
