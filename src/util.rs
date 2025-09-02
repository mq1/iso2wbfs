// SPDX-FileCopyrightText: 2025 Manuel Quarneti <mq1@ik.me>
// SPDX-License-Identifier: GPL-2.0-only

use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use tempfile::NamedTempFile;

/// Returns `true` if we can create a file >4 GiB in this directory
pub fn can_write_over_4gb(path: &Path) -> bool {
    let result = (|| {
        // Create a temp file in the target directory
        let mut tmp = NamedTempFile::new_in(path)?;

        // Seek to 4 GiB
        tmp.as_file_mut()
            .seek(SeekFrom::Start(4 * 1024 * 1024 * 1024))?;

        // Write a single byte
        tmp.as_file_mut().write_all(&[0])?;

        Ok::<_, std::io::Error>(())
    })();

    result.is_ok()
}
