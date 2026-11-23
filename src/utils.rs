// Copyright (C) 2021, Achiefs.

// To manage unique event identifier
use uuid::Uuid;
// To get own process ID
use std::process;
// To get Operating system
use std::env;
// To use files IO operations.
use std::fs::{File, metadata};
use std::io::{Read, SeekFrom};
use std::io::prelude::*;
use crate::appconfig;
// To manage paths
use std::path::{Component, Path, PathBuf};
// To run commands
use std::process::Command;
// To log the program process
use log::{warn, debug, error};
// To manage maps
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use walkdir::WalkDir;

#[cfg(test)]
mod test;

// ----------------------------------------------------------------------------

/// Function to pop last char of a given String
pub fn pop(string: &str) -> &str {
    let mut chars = string.chars();
    chars.next_back();
    chars.as_str()
}

// ----------------------------------------------------------------------------

pub fn get_hostname() -> String {
    gethostname::gethostname().into_string().unwrap()
}

// ----------------------------------------------------------------------------

pub fn get_uuid() -> String {
    format!("{}", Uuid::new_v4())
}

// ----------------------------------------------------------------------------

pub fn get_pid() -> u32 {
    process::id()
}

// ----------------------------------------------------------------------------

pub const fn get_os() -> &'static str {
    env::consts::OS
}

// ----------------------------------------------------------------------------

// Function to read file from begin to end
pub fn read_file(path: &str) -> String {
    let mut file = File::open(path).unwrap();
    let mut contents = String::new();

    file.read_to_string(&mut contents).unwrap();
    contents
}

// ----------------------------------------------------------------------------

// (Only supported in Linux) Function to get machine id of the host
pub fn get_machine_id() -> String {
    read_file(appconfig::MACHINE_ID_PATH)
}

// ----------------------------------------------------------------------------

// Function to get file name of a given path
pub fn get_filename_path(path: &str) -> String {
    String::from(
        match Path::new(path).file_name() {
            Some(value) => value,
            None => {
                debug!("Cannot retrieve event file, event path is empty.");
                std::ffi::OsStr::new(path)
            }
        }.to_str().unwrap()
    )
}

// ----------------------------------------------------------------------------

// Function to clean trailing slash of a path
pub fn clean_path(path: &str) -> String {
    let mut clean = path;
    while clean.ends_with('/') || clean.ends_with('\\') {
        clean = pop(clean);
    }
    String::from(clean)
}

// ----------------------------------------------------------------------------

// Resolve a path against a base directory. Absolute paths are kept as they are,
// relative paths are joined to the provided working directory. An empty
// working directory means the process current directory.
pub fn resolve_path(path: &str, cwd: &str) -> String {
    let raw_path = Path::new(path);
    if raw_path.is_absolute() {
        return String::from(path);
    }

    let base = if cwd.is_empty() { get_current_dir() } else { String::from(cwd) };
    Path::new(&base).join(raw_path).to_string_lossy().into_owned()
}

// ----------------------------------------------------------------------------

// Convert a path to an absolute one without resolving symbolic links.
fn absolute_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        Path::new(&get_current_dir()).join(path)
    }
}

// ----------------------------------------------------------------------------

// Remove '.', '..' and duplicated separators from an absolute path.
fn normalize_components(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {},
            Component::ParentDir => {
                if normalized.file_name().is_some() {
                    normalized.pop();
                }else if ! normalized.has_root() {
                    normalized.push("..");
                }
            },
            Component::Normal(name) => normalized.push(name)
        }
    }
    normalized
}

// ----------------------------------------------------------------------------

// Resolve symbolic links on every component that exists in the filesystem.
// Components that do not exist yet are kept literally, so paths to files that
// are being created or removed can still be matched against their parent.
fn resolve_symlinks(path: &Path) -> PathBuf {
    let absolute = absolute_path(path);
    let mut resolved = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(prefix) => resolved.push(prefix.as_os_str()),
            Component::RootDir => resolved.push(component.as_os_str()),
            Component::CurDir => {},
            Component::ParentDir => {
                if resolved.file_name().is_some() {
                    resolved.pop();
                }
            },
            Component::Normal(name) => {
                let mut candidate = resolved.clone();
                candidate.push(name);
                match candidate.canonicalize() {
                    Ok(canonical) => resolved = canonical,
                    Err(_) => resolved.push(name)
                }
            }
        }
    }
    resolved
}

// ----------------------------------------------------------------------------

// Lexically normalized absolute representation of a path.
pub fn lexical_path(path: &str) -> PathBuf {
    normalize_components(&absolute_path(Path::new(path)))
}

// ----------------------------------------------------------------------------

// Canonical absolute representation of a path, resolving symbolic links when
// possible and falling back to the lexical representation for missing paths.
pub fn canonical_path(path: &str) -> PathBuf {
    resolve_symlinks(Path::new(path))
}

// ----------------------------------------------------------------------------

// Check whether the symlink-aware and the lexical representations agree. When
// they don't, matching must use the canonical representation to avoid paths
// escaping from a monitored root through a symbolic link.
pub fn is_lexically_stable(path: &str) -> bool {
    lexical_path(path) == canonical_path(path)
}

// ----------------------------------------------------------------------------

// Keep the previous behaviour of comparing a file with the directory that
// contains it. Missing files are assumed to be directories/prefixes.
fn match_path_dir(path: PathBuf) -> PathBuf {
    if let Ok(md) = metadata(&path) {
        if md.is_file() {
            if let Some(parent) = path.parent() {
                return parent.to_path_buf();
            }
        }
    }
    path
}

// ----------------------------------------------------------------------------

// Component-wise prefix match without resolving symbolic links.
pub fn match_path_lexical(raw_path: &str, compare_path: &str) -> bool {
    let raw_tokens = match_path_dir(lexical_path(raw_path));
    let compare_tokens = match_path_dir(lexical_path(compare_path));
    raw_tokens.starts_with(&compare_tokens)
}

// ----------------------------------------------------------------------------

// Function to get the last byte of a given file
pub fn get_file_end(file: &str, itx: u64) -> u64 {
    if itx < 5 {
        match File::open(file) {
            Ok(mut d) => d.seek(SeekFrom::End(0)).unwrap(),
            Err(e) => {
                warn!("Cannot open file '{}', due to: {}, retrying...", file, e);
                get_file_end(file, itx + 1)
            }
        }
    }else{ 0 }
}

// ----------------------------------------------------------------------------

// Function to get the last byte of a given file
pub fn open_file(file: &str, itx: u64) -> File {
    if itx < 5 {
        match File::open(file) {
            Ok(d) => d,
            Err(e) => {
                warn!("Cannot open file '{}', due to: {}, retrying...", file, e);
                open_file(file, itx + 1)
            }
        }
    }else{
        panic!("Cannot open '{}'", file);
    }
}

// ----------------------------------------------------------------------------

pub fn check_auditd() -> bool {
    match Command::new("which")
        .arg("auditctl")
        .output()
        .expect("[ERROR] Failed to execute auditctl command check")
        .status
        .success() {
        true => {
            debug!("Auditctl command available");
            true
        },
        _ => {
            warn!("Auditctl command unavailable");
            false
        }
    }
}

// ------------------------------------------------------------------------

// Returns if raw_path is inside compare_path. Both paths are normalized to a
// common root, resolving '.', '..', trailing separators and symbolic links so
// the event and the configured (include/exclude) path are compared in the same
// namespace.
pub fn match_path(raw_path: &str, compare_path: &str) -> bool {
    let raw_tokens = match_path_dir(canonical_path(raw_path));
    let compare_tokens = match_path_dir(canonical_path(compare_path));
    raw_tokens.starts_with(&compare_tokens)
}

// ----------------------------------------------------------------------------

#[cfg(not(tarpaulin_include))]
/// Get the current workdir for FIM, it returns a String with complete path.
pub fn get_current_dir() -> String {
    String::from(env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).to_str()
        .unwrap_or("."))
}

// ----------------------------------------------------------------------------

pub fn get_field(data: HashMap<String, String>, field_name: &str) -> String {
    let alternative = match field_name {
        "nametype" => "objtype",
        _ => field_name
    };
    match data.get(field_name) {
        Some(value) => String::from(value),
        None => {
            debug!("Cannot not fetch field name trying alternative");
            match data.get(alternative) {
                Some(alt) => String::from(alt),
                None => {
                    debug!("Cannot not fetch alternative. Using default");
                    String::from("UNKNOWN")
                }
            }
        }
    }
}

// ----------------------------------------------------------------------------

pub fn get_file_size(filename: &str) -> u64 {
    match metadata(filename) {
        Ok(data) => data.len(),
        Err(e) => {
            debug!("Cannot retrieve file size, error: {}", e);
            0
        }
    }
}

// ----------------------------------------------------------------------------

pub fn get_audit_rule_permissions(value: Option<&str>) -> String {
    let mut rule: String = String::new();
    match value {
        Some(value) => {
            for c in value.chars(){
                match c {
                    'r'|'R' => rule.push('r'),
                    'w'|'W' => rule.push('w'),
                    'a'|'A' => rule.push('a'),
                    'x'|'X' => rule.push('x'),
                    _ => rule = String::from("wax")
                }
            }
            rule.clone()
        },
        None => String::from("wax")
    }
}

// ----------------------------------------------------------------------------

pub fn run_auditctl(args: &[&str]) {
    let auditctl_path = if Path::new("/usr/sbin/auditctl").exists() { "/usr/sbin/auditctl"
    } else { "/sbin/auditctl" };

    match Command::new(auditctl_path)
    .args(args)
    .output()
    {
        Ok(d) => debug!("Auditctl command info: {:?}", d),
        Err(e) => error!("Auditctl command error: {}", e)
    };
}

// ----------------------------------------------------------------------------

pub fn get_current_time_millis() -> String {
    format!("{:?}", SystemTime::now().duration_since(UNIX_EPOCH)
        .expect("Time went backwards").as_millis())
}

// ----------------------------------------------------------------------------

pub fn get_fs_list(root: String) -> Vec<String> {
    let mut list = Vec::new();
    for result in WalkDir::new(root) {
        list.push(String::from(result.unwrap().path().to_str().unwrap()))
    }
    list
}

// ----------------------------------------------------------------------------

#[cfg(target_family = "unix")]
pub fn get_unix_permissions(file: &str) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    let metadata = Path::new(file).metadata().unwrap();
    format!("{:o}", metadata.permissions().mode()).parse::<u32>().unwrap()
}

// ----------------------------------------------------------------------------

#[cfg(target_family = "windows")]
pub fn get_unix_permissions(_v: &str) -> u32 {
    return 0
}

// ----------------------------------------------------------------------------
