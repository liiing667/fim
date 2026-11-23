use super::*;
use std::fs::{create_dir_all, remove_dir_all, File};
use serial_test::serial;
use std::path::Path;
use std::io::Write;
use tokio_test::block_on;
use std::fs;
use std::thread;
use std::time::Duration;

use crate::db::DB;

// ----------------------------------------------------------------------------

fn remove_db(path: &str) {
    use std::fs::remove_file;

    if Path::new(path).exists() {
        match remove_file(path){
            Ok(_v) => (),
            Err(e) => println!("Error deleting db, {}", e)
        };
    };
}

// ----------------------------------------------------------------------------

fn create_large_file(filename: &str, size: usize, byte: u8) {
    let mut file = File::create(filename).unwrap();
    let chunk = vec![byte; 1024 * 1024];
    let full_chunks = size / chunk.len();
    for _ in 0..full_chunks {
        file.write_all(&chunk).unwrap();
    }
    let remaining = size % chunk.len();
    if remaining > 0 {
        file.write_all(&chunk[..remaining]).unwrap();
    }
    file.flush().unwrap();
}

// ----------------------------------------------------------------------------

#[test]
#[serial]
#[cfg(target_family = "unix")]
/// Check dir scan result, DB should contains a DBFile definition with the given filepath
fn test_scan_path_unix() {
    let cfg = AppConfig::new(&utils::get_os(), None);
    let tdb = DB::new(&cfg.hashscanner_file);
    let scan_dir = String::from("./tmp/test_scan_path");
    let filepath = format!("{}/{}", scan_dir.clone(), "test_scan_path.txt");
    let _ = create_dir_all(scan_dir.clone());

    let _file = match File::create(&filepath) {
        Ok(file) => file,
        Err(e) => panic!("Could not create test file, error: '{}'", e)
    };

    remove_db(&cfg.hashscanner_file);
    tdb.create_table();
    scan_path(cfg.clone(), scan_dir.clone());

    let dbfile = tdb.get_file_by_path(filepath.clone()).unwrap();
    assert_eq!(dbfile.path, filepath);
    assert_eq!(dbfile.size, utils::get_file_size(&filepath));

    let _ = remove_dir_all(scan_dir);
}

// ----------------------------------------------------------------------------

#[test]
#[serial]
#[cfg(target_family = "unix")]
/// Check that modify a file is reflected in DB, it should modify the size and hash of DBFile
fn test_check_path() {
    let cfg = AppConfig::new(&utils::get_os(), None);
    let tdb = DB::new(&cfg.hashscanner_file);
    let scan_dir = String::from("./tmp/test_check_path");
    let filepath = format!("{}/{}", scan_dir.clone(), "test_check_path.txt");
    let _ = create_dir_all(scan_dir.clone());

    let mut _file = match File::create(&filepath) {
        Ok(file) => file,
        Err(e) => panic!("Could not create test file, error: '{}'", e)
    };

    remove_db(&cfg.hashscanner_file);
    tdb.create_table();
    scan_path(cfg.clone(), scan_dir.clone());
    let _result = writeln!(_file, "{}", "This is an additional line.");
    block_on(check_path(cfg.clone(), scan_dir.clone(), true));

    let dbfile = tdb.get_file_by_path(filepath.clone()).unwrap();
    assert_eq!(dbfile.path, filepath);
    assert_eq!(dbfile.size, utils::get_file_size(&filepath));

    let _ = remove_dir_all(scan_dir);
}

// ----------------------------------------------------------------------------

#[test]
#[serial]
#[cfg(target_family = "unix")]
/// A file replaced while scan_path hashes it must be stored in DB using one
/// single snapshot: checksum and size from the replacement file.
fn test_scan_path_concurrent_replacement() {
    let mut cfg = AppConfig::new(&utils::get_os(), None);
    cfg.events_max_file_checksum = 64;
    let tdb = DB::new(&cfg.hashscanner_file);
    let scan_dir = String::from("./tmp/test_scan_path_concurrent_replacement");
    let filepath = format!("{}/{}", scan_dir.clone(), "file.txt");
    let replacement = String::from("./tmp/test_scan_path_concurrent_replacement.new");

    let _ = create_dir_all(scan_dir.clone());
    create_large_file(&filepath, 16 * 1024 * 1024, b'A');
    create_large_file(&replacement, 4 * 1024 * 1024, b'B');

    remove_db(&cfg.hashscanner_file);
    tdb.create_table();

    let target = filepath.clone();
    let source = replacement.clone();
    let handle = thread::spawn(move || {
        thread::sleep(Duration::from_millis(5));
        fs::rename(&source, &target).unwrap();
    });

    scan_path(cfg.clone(), scan_dir.clone());
    handle.join().unwrap();

    let dbfile = tdb.get_file_by_path(filepath.clone()).unwrap();
    let snapshot = crate::hash::get_file_snapshot(
        &filepath,
        cfg.events_max_file_checksum,
        cfg.hashscanner_algorithm.clone()
    ).unwrap();

    assert_eq!(dbfile.size, snapshot.size);
    assert_eq!(dbfile.hash, snapshot.hash);
    assert_eq!(dbfile.size, 4 * 1024 * 1024);

    let _ = remove_dir_all(scan_dir);
}

// ----------------------------------------------------------------------------

#[test]
#[serial]
#[cfg(target_family = "unix")]
/// Truncating a file during check_path must update the DB with the checksum
/// and size of the truncated file, never with a mixed observation.
fn test_check_path_concurrent_truncation() {
    let mut cfg = AppConfig::new(&utils::get_os(), None);
    cfg.events_max_file_checksum = 64;
    let tdb = DB::new(&cfg.hashscanner_file);
    let scan_dir = String::from("./tmp/test_check_path_concurrent_truncation");
    let filepath = format!("{}/{}", scan_dir.clone(), "file.txt");

    let _ = create_dir_all(scan_dir.clone());
    create_large_file(&filepath, 16 * 1024 * 1024, b'A');

    remove_db(&cfg.hashscanner_file);
    tdb.create_table();
    scan_path(cfg.clone(), scan_dir.clone());
    let previous = tdb.get_file_by_path(filepath.clone()).unwrap();

    let target = filepath.clone();
    let handle = thread::spawn(move || {
        thread::sleep(Duration::from_millis(5));
        let file = fs::OpenOptions::new().write(true).open(&target).unwrap();
        file.set_len(1024 * 1024).unwrap();
    });

    block_on(check_path(cfg.clone(), scan_dir.clone(), true));
    handle.join().unwrap();

    let dbfile = tdb.get_file_by_path(filepath.clone()).unwrap();
    let snapshot = crate::hash::get_file_snapshot(
        &filepath,
        cfg.events_max_file_checksum,
        cfg.hashscanner_algorithm.clone()
    ).unwrap();

    assert_eq!(dbfile.size, snapshot.size);
    assert_eq!(dbfile.hash, snapshot.hash);
    assert_eq!(dbfile.size, 1024 * 1024);
    assert_ne!(dbfile.hash, previous.hash);

    let _ = remove_dir_all(scan_dir);
}

// ----------------------------------------------------------------------------

#[test]
#[serial]
#[cfg(target_family = "unix")]
#[should_panic(expected = "DBFileNotFoundError")]
/// Check file deletion of filesystem and DB, it should panic with DBFileNotFoundError
fn test_update_db() {
    let cfg = AppConfig::new(&utils::get_os(), None);
    let tdb = DB::new(&cfg.hashscanner_file);
    let scan_dir = String::from("./tmp/test_update_db");
    let filepath = format!("{}/{}", scan_dir.clone(), "test_update_db.txt");
    let filepath2 = format!("{}/{}", scan_dir.clone(), "test_update_db2.txt");
    let _ = create_dir_all(scan_dir.clone());

    let mut _file = match File::create(&filepath) {
        Ok(file) => file,
        Err(e) => panic!("Could not create test file, error: '{}'", e)
    };
    let mut _file2 = match File::create(&filepath2) {
        Ok(file) => file,
        Err(e) => panic!("Could not create test file, error: '{}'", e)
    };

    remove_db(&cfg.hashscanner_file);
    tdb.create_table();
    scan_path(cfg.clone(), scan_dir.clone());
    fs::remove_file(filepath.clone()).unwrap();
    block_on(update_db(cfg, scan_dir.clone(), true));

    let dbfile = tdb.get_file_by_path(filepath2.clone()).unwrap();
    assert_eq!(dbfile.path, filepath2);
    assert_eq!(dbfile.size, utils::get_file_size(&filepath2));
    let _ = remove_dir_all(scan_dir);

    // Panic line
    let _dbfile = tdb.get_file_by_path(filepath.clone()).unwrap();
}
