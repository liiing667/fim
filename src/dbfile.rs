// Copyright (C) 2024, Achiefs.

use crate::utils;
use crate::hash;
use crate::appconfig::*;

use std::fmt;
use log::*;

pub struct DBFileError {
    kind: String,
    message: String
}

pub struct DBFile {
    pub id: String,
    pub timestamp: String,
    pub hash: String,
    pub path: String,
    pub size: u64,
    pub permissions: u32
}

#[cfg(test)]
mod test;

// ----------------------------------------------------------------------------

impl DBFileError {
    pub fn not_found_error() -> Self {
        DBFileError {
            kind: String::from("DBFileNotFoundError"),
            message: String::from("Could not find requested file in the database."),
        }
    }

    // ------------------------------------------------------------------------

    pub fn kind(&self) -> String {
        self.kind.clone()
    }
}

// ----------------------------------------------------------------------------

impl From<rusqlite::Error> for DBFileError {
    fn from(error: rusqlite::Error) -> Self {
        DBFileError {
            kind: String::from("RusqliteError"),
            message: error.to_string()
        }
    }
}

// ----------------------------------------------------------------------------

impl fmt::Debug for DBFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result{
        f.debug_tuple("")
        .field(&self.kind)
        .field(&self.message)
        .finish()
    }
}

// ----------------------------------------------------------------------------

impl fmt::Debug for DBFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result{
        f.debug_tuple("")
        .field(&self.id)
        .field(&self.timestamp)
        .field(&self.hash)
        .field(&self.path)
        .field(&self.size)
        .field(&self.permissions)
        .finish()
    }
}

// ----------------------------------------------------------------------------

impl fmt::Display for DBFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "DBFile(ID: {}, TIMESTAMP: {}, HASH: {}, PATH: {}, SIZE: {}, PERMISSIONS: {})",
            self.id,
            self.timestamp,
            self.hash,
            self.path,
            self.size,
            self.permissions)
    }
}

// ----------------------------------------------------------------------------

impl DBFile {
    pub fn new(cfg: AppConfig, path: &str, id: Option<String>) -> Self {
        match Self::try_new(cfg, path, id.clone()) {
            Some(dbfile) => dbfile,
            None => {
                warn!(
                    "Could not obtain a stable snapshot of '{}', storing UNKNOWN metadata.",
                    path
                );
                DBFile {
                    id: match id {
                        Some(data) => data,
                        None => utils::get_uuid()
                    },
                    timestamp: utils::get_current_time_millis(),
                    hash: String::from("UNKNOWN"),
                    path: String::from(path),
                    size: 0,
                    permissions: 0
                }
            }
        }
    }

    // ------------------------------------------------------------------------

    /// Build a DBFile only when the complete hash, size and permissions could
    /// be read from one stable file snapshot. Returns None if the file cannot
    /// be read consistently.
    pub fn try_new(cfg: AppConfig, path: &str, id: Option<String>) -> Option<Self> {
        Self::try_new_with_snapshot(cfg, path, id).map(|(dbfile, _snapshot)| dbfile)
    }

    // ------------------------------------------------------------------------

    /// Build a DBFile and return the snapshot it came from, so callers can
    /// verify the path still matches after writing it to the database.
    pub fn try_new_with_snapshot(
        cfg: AppConfig,
        path: &str,
        id: Option<String>
    ) -> Option<(Self, hash::FileSnapshot)> {
        let snapshot = match hash::get_file_snapshot(
            path,
            cfg.events_max_file_checksum,
            cfg.hashscanner_algorithm
        ) {
            Ok(snapshot) => snapshot,
            Err(e) => {
                warn!("Cannot get a consistent snapshot of '{}', error: {}", path, e);
                return None;
            }
        };

        let target_id = match id {
            Some(data) => data,
            None => utils::get_uuid()
        };

        Some((
            DBFile {
                id: target_id,
                timestamp: utils::get_current_time_millis(),
                hash: snapshot.hash.clone(),
                path: String::from(path),
                size: snapshot.size,
                permissions: snapshot.permissions
            },
            snapshot
        ))
    }

    // ------------------------------------------------------------------------

    pub fn clone(&self) -> Self {
        DBFile {
            id: self.id.clone(),
            timestamp: self.timestamp.clone(),
            hash: self.hash.clone(),
            path: self.path.clone(),
            size: self.size,
            permissions: self.permissions
        }
    }

    // ------------------------------------------------------------------------

    pub fn get_file_hash(&self, cfg: AppConfig) -> String {
        match hash::get_file_snapshot(
            &self.path,
            cfg.events_max_file_checksum,
            cfg.hashscanner_algorithm
        ) {
            Ok(snapshot) => snapshot.hash,
            Err(e) => {
                debug!("Cannot get checksum of '{}', error: {}", self.path, e);
                String::from("UNKNOWN")
            }
        }
    }
}
