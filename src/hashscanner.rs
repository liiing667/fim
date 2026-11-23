// Copyright (C) 2024, Achiefs.

use crate::db;
use crate::dbfile::*;
use crate::appconfig::AppConfig;
use crate::hash;
use crate::hashevent;
use crate::hashevent::HashEvent;
use crate::utils;

use walkdir::WalkDir;
use log::*;
use std::collections::HashSet;
use std::time::Duration;
use std::thread;
use tokio::runtime::Runtime;
use std::path::Path;

#[cfg(test)]
mod test;

const DB_SNAPSHOT_RETRIES: usize = 5;

// ----------------------------------------------------------------------------

/// Insert a new file only after its snapshot is stable, then check the path
/// again once the row was written. If the file changed in between, the row is
/// replaced with a fresh, verified snapshot.
fn insert_consistent_file(db: &db::DB, cfg: &AppConfig, path: &str) -> Option<DBFile> {
    let (mut current, mut snapshot) =
        DBFile::try_new_with_snapshot(AppConfig::clone(cfg), path, None)?;
    let id = current.id.clone();
    db.insert_file(current.clone());

    for _ in 0..DB_SNAPSHOT_RETRIES {
        if snapshot.matches_path(path) {
            return Some(current);
        }
        let (next, next_snapshot) =
            DBFile::try_new_with_snapshot(AppConfig::clone(cfg), path, Some(id.clone()))?;
        if db.update_file_snapshot(next.clone()).is_none() {
            return None;
        }
        current = next;
        snapshot = next_snapshot;
    }

    if snapshot.matches_path(path) {
        Some(current)
    } else {
        None
    }
}

// ----------------------------------------------------------------------------

/// Update an existing row with the snapshot used to detect the change and
/// verify it after the write. Retry with a fresh snapshot when the path moved.
fn update_consistent_file(
    db: &db::DB,
    cfg: &AppConfig,
    path: &str,
    id: String,
    mut current: DBFile,
    mut snapshot: hash::FileSnapshot
) -> Option<DBFile> {
    if db.update_file_snapshot(current.clone()).is_none() {
        return None;
    }

    for _ in 0..DB_SNAPSHOT_RETRIES {
        if snapshot.matches_path(path) {
            return Some(current);
        }
        let (next, next_snapshot) =
            DBFile::try_new_with_snapshot(AppConfig::clone(cfg), path, Some(id.clone()))?;
        if db.update_file_snapshot(next.clone()).is_none() {
            return None;
        }
        current = next;
        snapshot = next_snapshot;
    }

    if snapshot.matches_path(path) {
        Some(current)
    } else {
        None
    }
}

// ----------------------------------------------------------------------------

pub fn scan_path(cfg: AppConfig, root: String) {
    let db = db::DB::new(&cfg.hashscanner_file);
    for res in WalkDir::new(root) {
        let entry = res.unwrap();
        let metadata = entry.metadata().unwrap();
        let path = entry.path();
        if metadata.clone().is_file(){
            match insert_consistent_file(&db, &cfg, path.to_str().unwrap()) {
                Some(_) => (),
                None => warn!(
                    "Could not insert file '{}' in DB, no stable snapshot available.",
                    path.display()
                )
            }
        }
    }
}

// ----------------------------------------------------------------------------

/// This function iterate over the files on `root` directory
/// If hash or permissions of a file change it should trigger a HashEvent
/// Just in case the first scan after reboot or a hash change between scans
/// It also updates the DBFile definition in the DB
pub async fn check_path(cfg: AppConfig, root: String, first_scan: bool) {
    let db = db::DB::new(&cfg.hashscanner_file);
    for res in WalkDir::new(root) {
        let entry = res.unwrap();
        let metadata = entry.metadata().unwrap();
        let path = entry.path();

        if metadata.clone().is_file(){
            let result = db.get_file_by_path(String::from(path.to_str().unwrap()));
            match result {
                Ok(dbfile) => {
                    match DBFile::try_new_with_snapshot(
                        cfg.clone(),
                        path.to_str().unwrap(),
                        Some(dbfile.id.clone())
                    ) {
                        Some((current_dbfile, snapshot)) => {
                            if dbfile.hash != current_dbfile.hash
                                || dbfile.permissions != current_dbfile.permissions
                                || dbfile.size != current_dbfile.size {
                                debug!("The file '{}' information has changed.", path.display());
                                match update_consistent_file(
                                    &db,
                                    &cfg,
                                    path.to_str().unwrap(),
                                    dbfile.id.clone(),
                                    current_dbfile,
                                    snapshot
                                ) {
                                    Some(data) => {
                                        let event = HashEvent::new(Some(dbfile), data, String::from(hashevent::WRITE));
                                        event.process(cfg.clone()).await;
                                    },
                                    None => warn!("Could not update file information in database, file: '{}'", path.display())
                                }
                            }
                        },
                        None => warn!(
                            "Could not read a consistent snapshot of file '{}', keeping previous DB information.",
                            path.display()
                        )
                    }
                },
                Err(e) => {
                    if e.kind() == "DBFileNotFoundError" {
                        debug!("New file '{}' found in directory.", path.display());
                        match insert_consistent_file(&db, &cfg, path.to_str().unwrap()) {
                            Some(dbfile) => {
                                // Only trigger new file event in case it is a first scan else monitor will notify.
                                if first_scan {
                                    let event = HashEvent::new(None, dbfile, String::from(hashevent::CREATE));
                                    event.process(cfg.clone()).await;
                                }
                            },
                            None => warn!(
                                "Could not insert new file '{}' in DB, no stable snapshot available.",
                                path.display()
                            )
                        }
                    } else {
                        error!("Could not get file '{}' information from database, Error: {:?}", path.display(), e)
                    }
                }
            };
        }
    }
}

// ----------------------------------------------------------------------------

/// This function update the DB in case files were removed from given path
/// In case changes were detected, it trigger hashEvents on first scan after reboot
pub async fn update_db(cfg: AppConfig, root: String, first_scan: bool) {
    let db = db::DB::new(&cfg.hashscanner_file);

    let db_list = db.get_file_list(root.clone());
    let path_list = utils::get_fs_list(root);

    let path_set: HashSet<_> = path_list.iter().collect();
    let diff: Vec<_> = db_list.iter().filter(|item| !path_set.contains(&item.path)).collect();

    for file in diff {
        let dbfile = DBFile {
            id: file.id.clone(),
            timestamp: file.timestamp.clone(),
            hash: file.hash.clone(),
            path: file.path.clone(),
            size: file.size,
            permissions: file.permissions
        };
        let result = db.delete_file(dbfile.clone());
        match result {
            Ok(_v) => {
                // Only trigger delete file event in case it is a first scan else monitor will notify.
                if first_scan {
                    let event = HashEvent::new(None, dbfile, String::from(hashevent::REMOVE));
                    event.process(cfg.clone()).await;
                }
                debug!("File {} deleted from databse", file.path)
            },
            Err(e) => error!("Could not delete file {} from database, error: {:?}", file.path, e)
        }
    }
}

// ----------------------------------------------------------------------------

#[cfg(not(tarpaulin_include))]
pub fn scan(cfg: AppConfig) {
    let db = db::DB::new(&cfg.hashscanner_file);
    let rt = Runtime::new().unwrap();
    let interval = cfg.clone().hashscanner_interval;
    let mut first_scan = true;
    debug!("Starting file scan to create hash database.");

    let config_paths = match cfg.clone().engine.as_str() {
        "audit" => cfg.clone().audit,
        _ => cfg.clone().monitor,
    };

    loop{

        for element in config_paths.clone() {
            let path = String::from(element["path"].as_str().unwrap());
            match Path::new(&path).exists() {
                true => {
                    if db.is_empty() {
                        scan_path(cfg.clone(), path.clone());
                    } else {
                        rt.block_on(check_path(cfg.clone(), path.clone(), first_scan));
                        rt.block_on(update_db(cfg.clone(), path.clone(), first_scan));
                        first_scan = false;
                    }
                    debug!("Path '{}' scanned all files are hashed in DB.", path.clone());
                },
                false => warn!("[HashScanner] Could not scan '{}' path, folder does not exists.", path)
            }
        }

        debug!("Sleeping HashScanner thread for {} minutes", interval.clone());
        thread::sleep(Duration::from_secs(interval.try_into().unwrap()));
    }

}
