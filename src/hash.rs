// Copyright (C) 2021, Achiefs.

// Constants definitions
const READ_CAPACITY: usize = 1024 * 1024 * 8; // Read file in chunks of 8MB
const PARTIAL_READ_LIMIT: usize = 1024 * 1024; // Read first 1MB for partial checksums
const SNAPSHOT_MAX_ATTEMPTS: usize = 5;
const SNAPSHOT_RETRY_DELAY_MS: u64 = 10;

// To get file checksums
use hex::{encode, decode};
//use sha3::{Digest, Sha3_256, Sha3_512, Sha3_224};
use sha3::{Digest, digest::DynDigest,
    Sha3_224, Sha3_256, Sha3_384, Sha3_512,
    Keccak224, Keccak256, Keccak384, Keccak512};
// To log the program process
use log::*;
// To manage hex to ascii conversion
use std::str;
// To manage files
use std::fmt;
use std::fs::{self, File, Metadata};
// To read file content
use std::io::{self, BufRead, BufReader};
use std::thread;
use std::time::Duration;

// ----------------------------------------------------------------------------

#[derive(Debug)]
#[derive(PartialEq)]
#[derive(Clone)]
pub enum ShaType {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Keccak224,
    Keccak256,
    Keccak384,
    Keccak512
}

/// Error returned while trying to obtain a checksum tied to one file snapshot.
#[derive(Debug)]
pub enum SnapshotError {
    NotFound,
    NotFile,
    Changed,
    Io(io::Error),
}

impl SnapshotError {
    fn retryable(&self) -> bool {
        match self {
            SnapshotError::NotFound | SnapshotError::Changed => true,
            SnapshotError::Io(error) => matches!(
                error.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            SnapshotError::NotFile => false,
        }
    }
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnapshotError::NotFound => write!(f, "file not found"),
            SnapshotError::NotFile => write!(f, "path is not a file"),
            SnapshotError::Changed => write!(f, "file changed while it was being read"),
            SnapshotError::Io(error) => write!(f, "I/O error: {}", error),
        }
    }
}

/// Checksum and file attributes obtained from the same opened file descriptor.
#[derive(Debug, Clone)]
pub struct FileSnapshot {
    pub hash: String,
    pub size: u64,
    pub permissions: u32,
    version: FileVersion,
}

impl FileSnapshot {
    /// Check that the path still points to the exact object and content
    /// version captured in this snapshot.
    pub fn matches_path(&self, filename: &str) -> bool {
        match get_path_version(filename) {
            Ok(current) => {
                self.version.same_object(&current) && self.version.same_content(&current)
            },
            Err(_) => false
        }
    }
}

// Metadata used to prove that a file did not change during a read. On Unix the
// inode identifies the object while mtime/ctime identify its contents version.
#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileVersion {
    size: u64,
    dev: u64,
    ino: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

#[cfg(unix)]
impl FileVersion {
    fn from_metadata(metadata: &Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;

        FileVersion {
            size: metadata.len(),
            dev: metadata.dev(),
            ino: metadata.ino(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }

    fn same_object(&self, other: &Self) -> bool {
        self.dev == other.dev && self.ino == other.ino
    }

    fn same_content(&self, other: &Self) -> bool {
        self.size == other.size
            && self.mtime == other.mtime
            && self.mtime_nsec == other.mtime_nsec
            && self.ctime == other.ctime
            && self.ctime_nsec == other.ctime_nsec
    }
}

#[cfg(not(unix))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileVersion {
    size: u64,
    created: Option<std::time::SystemTime>,
    modified: Option<std::time::SystemTime>,
}

#[cfg(not(unix))]
impl FileVersion {
    fn from_metadata(metadata: &Metadata) -> Self {
        FileVersion {
            size: metadata.len(),
            created: metadata.created().ok(),
            modified: metadata.modified().ok(),
        }
    }

    fn same_object(&self, other: &Self) -> bool {
        self.created == other.created
    }

    fn same_content(&self, other: &Self) -> bool {
        self.size == other.size && self.modified == other.modified
    }
}

#[cfg(test)]
mod test;

// To calculate file content hash
pub fn get_checksum(filename: String, read_limit: usize, algorithm: ShaType) -> String {
    match get_file_snapshot(&filename, read_limit, algorithm) {
        Ok(snapshot) => snapshot.hash,
        Err(e) => {
            debug!("Cannot read file '{}' to get checksum, error: {}", filename, e);
            String::from("UNKNOWN")
        }
    }
}

// ----------------------------------------------------------------------------

/// Return a checksum and the file attributes that belong to the same snapshot.
/// The file is opened once, so the hash and the size always describe the same
/// inode. If the path is replaced, or the file is truncated/overwritten while
/// being read, the observation is discarded and retried.
pub fn get_file_snapshot(
    filename: &str,
    read_limit: usize,
    algorithm: ShaType,
) -> Result<FileSnapshot, SnapshotError> {
    let mut last_error = SnapshotError::NotFound;

    for attempt in 0..SNAPSHOT_MAX_ATTEMPTS {
        match get_file_snapshot_once(filename, read_limit, &algorithm) {
            Ok(snapshot) => return Ok(snapshot),
            Err(error) => {
                let retryable = error.retryable();
                last_error = error;
                if !retryable {
                    break;
                }
                if attempt + 1 < SNAPSHOT_MAX_ATTEMPTS {
                    debug!(
                        "File '{}' changed while being hashed, retrying ({}/{}).",
                        filename,
                        attempt + 1,
                        SNAPSHOT_MAX_ATTEMPTS
                    );
                    thread::sleep(Duration::from_millis(SNAPSHOT_RETRY_DELAY_MS));
                }
            }
        }
    }

    Err(last_error)
}

// ----------------------------------------------------------------------------

fn get_file_snapshot_once(
    filename: &str,
    read_limit: usize,
    algorithm: &ShaType,
) -> Result<FileSnapshot, SnapshotError> {
    let path_metadata = fs::metadata(filename).map_err(classify_io_error)?;
    if !path_metadata.is_file() {
        return Err(SnapshotError::NotFile);
    }

    let file = File::open(filename).map_err(classify_io_error)?;
    let before_metadata = file.metadata().map_err(SnapshotError::Io)?;
    if !before_metadata.is_file() {
        return Err(SnapshotError::NotFile);
    }

    let before = FileVersion::from_metadata(&before_metadata);
    let limit: usize = read_limit.saturating_mul(1024 * 1024);
    let partial = before.size > limit as u64;
    let capacity = if partial { PARTIAL_READ_LIMIT } else { READ_CAPACITY };
    let mut reader = BufReader::with_capacity(capacity, file);
    let mut hasher: Box<dyn DynDigest> = new_hasher(algorithm);

    if partial {
        update_partial_checksum(&mut reader, hasher.as_mut(), before.size)
            .map_err(SnapshotError::Io)?;
    } else {
        update_full_checksum(&mut reader, hasher.as_mut(), limit)
            .map_err(SnapshotError::Io)?;
    }

    let hash = encode(hasher.finalize());
    let after_metadata = reader.get_ref().metadata().map_err(SnapshotError::Io)?;
    let after = FileVersion::from_metadata(&after_metadata);

    // The file descriptor must still describe the same unchanged object.
    if !before.same_object(&after) || !before.same_content(&after) {
        return Err(SnapshotError::Changed);
    }

    // The path must still point to the object that was hashed.
    let path_version = get_path_version(filename)?;
    if !after.same_object(&path_version) || !after.same_content(&path_version) {
        return Err(SnapshotError::Changed);
    }

    // Re-check both views once more to close the window between fstat and stat.
    let confirmed = FileVersion::from_metadata(
        &reader.get_ref().metadata().map_err(SnapshotError::Io)?,
    );
    let confirmed_path = get_path_version(filename)?;
    if !after.same_content(&confirmed)
        || !confirmed.same_object(&confirmed_path)
        || !confirmed.same_content(&confirmed_path)
    {
        return Err(SnapshotError::Changed);
    }

    Ok(FileSnapshot {
        hash,
        size: after.size,
        permissions: metadata_permissions(&after_metadata),
        version: after,
    })
}

// ----------------------------------------------------------------------------

fn new_hasher(algorithm: &ShaType) -> Box<dyn DynDigest> {
    match algorithm {
        ShaType::Sha224 => Box::new(Sha3_224::new()),
        ShaType::Sha256 => Box::new(Sha3_256::new()),
        ShaType::Sha384 => Box::new(Sha3_384::new()),
        ShaType::Sha512 => Box::new(Sha3_512::new()),
        ShaType::Keccak224 => Box::new(Keccak224::new()),
        ShaType::Keccak256 => Box::new(Keccak256::new()),
        ShaType::Keccak384 => Box::new(Keccak384::new()),
        ShaType::Keccak512 => Box::new(Keccak512::new()),
    }
}

// ----------------------------------------------------------------------------

fn update_full_checksum(
    reader: &mut BufReader<File>,
    hasher: &mut dyn DynDigest,
    limit: usize,
) -> io::Result<()> {
    let mut length = 1;
    let mut iteration = 0;
    let mut data_read = 0;

    while length > 0 && data_read <= limit {
        if iteration == 2 {
            debug!("Big file detected, the hash will take a while");
        }

        let buffer = reader.fill_buf()?;
        length = buffer.len();
        if length > 0 {
            hasher.update(buffer);
        }
        reader.consume(length);
        data_read += length;
        iteration += 1;
    }

    Ok(())
}

// ----------------------------------------------------------------------------

fn update_partial_checksum(
    reader: &mut BufReader<File>,
    hasher: &mut dyn DynDigest,
    size: u64,
) -> io::Result<()> {
    let buffer = reader.fill_buf()?;
    let length = buffer.len();
    if length > 0 {
        hasher.update(buffer);
    }
    reader.consume(length);
    hasher.update(&[size as u8]);
    Ok(())
}

// ----------------------------------------------------------------------------

fn get_path_version(filename: &str) -> Result<FileVersion, SnapshotError> {
    let metadata = fs::metadata(filename).map_err(classify_io_error)?;
    if !metadata.is_file() {
        return Err(SnapshotError::Changed);
    }
    Ok(FileVersion::from_metadata(&metadata))
}

// ----------------------------------------------------------------------------

fn classify_io_error(error: io::Error) -> SnapshotError {
    if error.kind() == io::ErrorKind::NotFound {
        SnapshotError::NotFound
    } else {
        SnapshotError::Io(error)
    }
}

// ----------------------------------------------------------------------------

#[cfg(unix)]
fn metadata_permissions(metadata: &Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;

    format!("{:o}", metadata.permissions().mode())
        .parse::<u32>()
        .unwrap_or(0)
}

#[cfg(not(unix))]
fn metadata_permissions(_metadata: &Metadata) -> u32 {
    0
}

// ----------------------------------------------------------------------------

/// Produce partial checksum of file, it read the first MB of the file
/// This method is targeted for big files where you cannot get checksum in a reasonable time.
pub fn get_partial_checksum(filename: String, algorithm: ShaType) -> String {
    match get_partial_checksum_once(&filename, &algorithm) {
        Ok(hash) => hash,
        Err(e) => {
            debug!("Cannot read file '{}' to get partial checksum, error: {}", filename, e);
            String::from("UNKNOWN")
        }
    }
}

fn get_partial_checksum_once(
    filename: &str,
    algorithm: &ShaType,
) -> Result<String, SnapshotError> {
    let path_metadata = fs::metadata(filename).map_err(classify_io_error)?;
    if !path_metadata.is_file() {
        return Err(SnapshotError::NotFile);
    }

    let file = File::open(filename).map_err(classify_io_error)?;
    let metadata = file.metadata().map_err(SnapshotError::Io)?;
    if !metadata.is_file() {
        return Err(SnapshotError::NotFile);
    }

    let mut reader = BufReader::with_capacity(PARTIAL_READ_LIMIT, file);
    let mut hasher: Box<dyn DynDigest> = new_hasher(algorithm);
    update_partial_checksum(&mut reader, hasher.as_mut(), metadata.len())
        .map_err(SnapshotError::Io)?;
    Ok(encode(hasher.finalize()))
}


// ----------------------------------------------------------------------------

pub fn hex_to_ascii(hex: String) -> String {
    debug!("HEX: {}", hex);
    let bytes = match decode(hex){
        Ok(d) => d,
        Err(e) => {
            debug!("Could not decode HEX data. Error: {}", e);
            Vec::new()
        }
    };
    String::from(str::from_utf8(&bytes).unwrap())
        .replace('\u{0000}', " ")
}

// ----------------------------------------------------------------------------
