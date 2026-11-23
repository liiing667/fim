// Copyright (C) 2024, Achiefs.

use crate::dbfile::*;
use crate::appconfig::AppConfig;

use rusqlite::{Connection, Error, params};
use rusqlite::Error::QueryReturnedNoRows;
use log::*;
use std::path::{Component, Path, PathBuf};

#[derive(Clone)]
pub struct DB {
    pub path: String
}

#[cfg(test)]
mod test;

// ----------------------------------------------------------------------------

/// Escape the characters SQLite interprets specially inside a LIKE pattern.
fn escape_like(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' | '%' | '_' => {
                escaped.push('\\');
                escaped.push(character);
            },
            _ => escaped.push(character)
        }
    }
    escaped
}

// ----------------------------------------------------------------------------

/// Lexically normalize a path without accessing the filesystem.
/// This removes `.` components and resolves `..` components when possible,
/// keeping relative paths relative and preserving leading `..` components.
fn normalize_path(path: &str) -> String {
    let mut normalized = PathBuf::new();

    for component in Path::new(path).components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => (),
            Component::ParentDir => {
                let can_pop = matches!(
                    normalized.components().next_back(),
                    Some(Component::Normal(_))
                );
                if can_pop {
                    normalized.pop();
                } else {
                    let at_root = matches!(
                        normalized.components().next_back(),
                        Some(Component::RootDir) | Some(Component::Prefix(_))
                    );
                    if !at_root {
                        normalized.push(component.as_os_str());
                    }
                }
            },
            Component::Normal(part) => normalized.push(part)
        }
    }

    if normalized.as_os_str().is_empty() {
        String::from(".")
    } else {
        normalized.to_string_lossy().into_owned()
    }
}

// ----------------------------------------------------------------------------

/// Check whether `candidate` belongs to the directory tree rooted at `root`.
/// Both paths are compared after lexical normalization so that `.`, `..` and
/// equivalent relative fragments refer to the same root.
fn path_is_within_root(root: &str, candidate: &str) -> bool {
    let normalized_root = normalize_path(root);
    let normalized_candidate = normalize_path(candidate);

    if normalized_root == normalized_candidate {
        return true;
    }

    // "." represents the current directory, so every relative path that does
    // not climb out of it belongs to that root.
    if normalized_root == "." {
        let parent_prefix = format!("..{}", std::path::MAIN_SEPARATOR);
        return normalized_candidate != ".."
            && !normalized_candidate.starts_with(&parent_prefix)
            && !Path::new(&normalized_candidate).is_absolute();
    }

    let mut root_prefix = normalized_root;
    if !root_prefix.ends_with(std::path::MAIN_SEPARATOR) {
        root_prefix.push(std::path::MAIN_SEPARATOR);
    }
    normalized_candidate.starts_with(&root_prefix)
}

// ----------------------------------------------------------------------------

impl DB {
    /// Create a new db object
    pub fn new(path: &str) -> DB {
        DB {
            path: String::from(path),
        }
    }

    // ------------------------------------------------------------------------

    /// Open a handle to the db
    pub fn open(&self) -> Connection {
        match Connection::open(self.path.clone()) {
            Ok(database) => {
                debug!("Database connection opened ready to read/write");
                database
            }
            Err(e) => {
                error!("Database cannot be opened, Err: [{}]", e);
                info!("Please, check if {} is locked or in use.", self.path);
                panic!();
            }
        }
    }

    // ------------------------------------------------------------------------

    /// Close the db handle
    pub fn close(&self, connection: Connection) {
        match connection.close(){
            Ok(_) => debug!("DB connection closed successfully"),
            Err(e) => warn!("DB connection could not be closed, error: {:?}", e)
        };
    }

    // ------------------------------------------------------------------------

    /// Check if current db is empty
    pub fn is_empty(&self) -> bool {
        let connection = self.open();
        let result = connection.query_row("SELECT * FROM files LIMIT 1", [], |_row| Ok(0));
        self.close(connection);
        match result {
            Ok(_v) => false,
            Err(e) => {
                if e == QueryReturnedNoRows {
                    true
                } else {
                    error!("Could not check if the database is empty, Error: {}", e);
                    true
                }
            }
        }
    }

    // ------------------------------------------------------------------------

    /// Create the `files` table where store all files information
    /// Defines files table schema
    pub fn create_table(&self) {
        let connection = self.open();
        let result = connection.execute(
            "CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                hash TEXT NOT NULL,
                path TEXT NOT NULL UNIQUE,
                size INTEGER,
                permissions INTEGER)",
            (),
        );
        match result {
            Ok(_v) => info!("Database successfully created."),
            Err(e) => error!("Error creating database, Error: '{}'", e)
        }
        self.close(connection);
    }

    // ------------------------------------------------------------------------

    /// Insert information of a given DBFile in db
    pub fn insert_file(&self, file: DBFile) {
        let connection = self.open();
        let result = connection.execute(
            "INSERT INTO files (id, timestamp, hash, path, size, permissions) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            (file.id, file.timestamp, file.hash, file.path, file.size, file.permissions)
        );
        match result {
            Ok(_) => debug!("Inserted new file in DB"),
            Err(e) => warn!("Could not insert file in DB (Probably duplicated path), error: {:?}", e)
        }
        self.close(connection);
    }

    // ------------------------------------------------------------------------

    /// Retrieve the DBFile object from db, using the path of file
    pub fn get_file_by_path(&self, path: String) -> Result<DBFile, DBFileError> {
        let connection = self.open();
        let result = connection.query_row(
            "SELECT * FROM files WHERE path = ?1 LIMIT 1",
            [path.clone()],
            |row| Ok(DBFile {
                id: row.get(0).unwrap(),
                timestamp: row.get(1).unwrap(),
                hash: row.get(2).unwrap(),
                path: row.get(3).unwrap(),
                size: row.get(4).unwrap(),
                permissions: row.get(5).unwrap()
            })
        );

        let data = match result {
            Ok(d) => Ok(d),
            Err(e) => {
                match e {
                    Error::QueryReturnedNoRows => Err(DBFileError::not_found_error()),
                    _ => {
                        error!("Could not get file '{}' information in database, Error: {:?}", path, e);
                        Err(DBFileError::from(e))
                    }
                }
            }
        };

        self.close(connection);
        data
    }

    // ------------------------------------------------------------------------

    /// Retrieve a list of files that match the given path
    pub fn get_file_list(&self, path: String) -> Vec<DBFile> {
        let connection = self.open();
        let mut list = Vec::new();

        // An empty request has no root to match. Do not let it turn into the
        // LIKE '%%' pattern that matches the entire database.
        if path.is_empty() {
            self.close(connection);
            return list;
        }

        // Use the final component as a parameterized, escaped pre-filter. The
        // exact root check is done below on normalized paths, which keeps
        // sibling directories and LIKE metacharacters out of the result.
        let normalized_path = normalize_path(&path);
        let pattern = match Path::new(&normalized_path)
            .file_name().and_then(|name| name.to_str()) {
            Some(name) => format!("%{}%", escape_like(name)),
            None => String::from("%")
        };

        let prepared = connection.prepare_cached(
            "SELECT * FROM files WHERE path LIKE ?1 ESCAPE '\\'");
        match prepared {
            Ok(mut statement) => {
                match statement.query_map([pattern], |row| {
                    Ok(DBFile {
                        id: row.get(0)?,
                        timestamp: row.get(1)?,
                        hash: row.get(2)?,
                        path: row.get(3)?,
                        size: row.get(4)?,
                        permissions: row.get(5)?
                    })
                }) {
                    Ok(mapped_rows) => {
                        for file in mapped_rows {
                            match file {
                                Ok(file) => {
                                    if path_is_within_root(&path, &file.path) {
                                        list.push(file);
                                    }
                                },
                                Err(e) => error!("Could not read database file list row, error: {:?}", e)
                            }
                        }
                    },
                    Err(e) => error!("Could not get database file list, error: {:?}", e)
                };
            },
            Err(e) => error!("Could not prepare database file list query, error: {:?}", e)
        }

        self.close(connection);
        list
    }

    // ------------------------------------------------------------------------

    /// Update db information of the given DBFile information
    pub fn update_file(&self, cfg: AppConfig, dbfile: DBFile) -> Option<DBFile>{
        let connection = self.open();
        let current_dbfile = DBFile::new(cfg, &dbfile.path, Some(dbfile.id));
        let query = "UPDATE files SET timestamp = ?1, hash = ?2, size = ?3, permissions = ?4 WHERE id = ?5";

        let mut statement = connection.prepare(query).unwrap();
        let result = statement.execute(params![
            current_dbfile.timestamp,
            current_dbfile.hash,
            current_dbfile.size,
            current_dbfile.permissions,
            current_dbfile.id]);
        match result {
            Ok(_v) => {
                debug!("File '{}', updated with new information.", dbfile.path);
                Some(current_dbfile)
            },
            Err(e) => {
                error!("Cannot update file '{}' information, Error: {:?}", dbfile.path, e);
                None
            }
        }
    }

    // ------------------------------------------------------------------------

    /// Delete information inside db related to the given DBFile
    pub fn delete_file(&self, dbfile: DBFile) -> Result<u8, DBFileError>{
        let connection = self.open();
        let mut statement = connection.prepare("DELETE FROM files WHERE id = ?1").unwrap();
        let result = statement.execute(params![dbfile.id]);
        match result {
            Ok(_v) => {
                debug!("File '{}', deleted from database.", dbfile.path);
                Ok(0)
            },
            Err(e) => {
                error!("Cannot delete file '{}' information, Error: {:?}", dbfile.path, e);
                Err(DBFileError::from(e))
            }
        }
    }
}
