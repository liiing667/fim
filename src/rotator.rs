// Copyright (C) 2023, Achiefs.

use std::fs::{metadata, File, copy, remove_file, create_dir, rename, read_dir};
use std::path::Path;
use std::time::Duration;
use std::thread;
use log::{debug, error, info, warn};
use std::sync::Mutex;
use std::sync::Arc;

use crate::appconfig::*;

// ----------------------------------------------------------------------------

// Compress given file into zip.
#[cfg(windows)]
fn compress_zip_file(filepath: &str) -> Result<String, String> {
    use std::io::Write;
    use zip::write::SimpleFileOptions;
    use std::io::{BufReader, BufRead};
    let filename = Path::new(filepath).file_name().unwrap().to_str().unwrap();
    let zipfilename = format!("{}.zip", filepath);
    let path = Path::new(&zipfilename);
    let zipfile = File::create(path).unwrap();

    let mut zip = zip::ZipWriter::new(zipfile);
    match zip.start_file(filename, SimpleFileOptions::default()){
        Ok(_v) => {
            let file = match File::open(filepath) {
                Ok(f) => f,
                Err(e) => {
                    error!("Cannot open file '{}' to compress, error: {}", filepath, e);
                    return Err(format!("{}", e));
                }
            };
            let reader = BufReader::new(file);

            let mut counter: u64 = 0;
            for line in reader.lines() {
                // Sleep during compression to avoid increase CPU load.
                if counter == 4096 {
                    thread::sleep(Duration::from_millis(500));
                    counter = 0;
                }
                match line {
                    Ok(content) => {
                        // Keep the line terminator so the archived content
                        // matches the original file line by line.
                        match zip.write_all(content.as_bytes())
                            .and_then(|_| zip.write_all(b"\n")) {
                            Ok(_v) => debug!("Line written into zip file from rotated file."),
                            Err(e) => {
                                error!("Error writting line to zip file, error: {}", e);
                                let _ = remove_file(zipfilename.clone());
                                return Err(format!("{}", e));
                            }
                        };
                    },
                    Err(e) => {
                        error!("Error reading line to compress, error: {}", e);
                        let _ = remove_file(zipfilename.clone());
                        return Err(format!("{}", e));
                    }
                };
                counter += 1;
            }
            match zip.finish(){
                Ok(_v) => {
                    debug!("File compressed successfully, result: {}", zipfilename);
                    Ok(format!("File {} compressed successfully.", filename))
                },
                Err(e) => {
                    error!("Error compressing rotated file, error:{}", e);
                    let _ = remove_file(zipfilename.clone());
                    Err(format!("{}", e))
                }
            }
        },
        Err(e) => {
            error!("Cannot create file inside zip file, error: {}", e);
            Err(format!("{}", e))
        }
    }
}

// ----------------------------------------------------------------------------

// Compress given file into tar.gz.
#[cfg(not(windows))]
fn compress_tgz_file(filepath: &str) -> Result<String, String> {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    let filename = Path::new(filepath).file_name().unwrap().to_str().unwrap();
    let tarname = format!("{}.tar.gz", filepath);

    let mut file = match File::open(filepath) {
        Ok(f) => f,
        Err(e) => {
            error!("Cannot open file '{}' to compress, error: {}", filepath, e);
            return Err(format!("{}", e));
        }
    };
    let tgz = match File::create(tarname.as_str()) {
        Ok(f) => f,
        Err(e) => {
            error!("Cannot create archive '{}', error: {}", tarname, e);
            return Err(format!("{}", e));
        }
    };
    let enc = GzEncoder::new(tgz, Compression::default());
    let mut tar = tar::Builder::new(enc);

    if let Err(e) = tar.append_file(filename, &mut file) {
        error!("Cannot not create tar.gz archive, error: {}", e);
        let _ = remove_file(tarname.as_str());
        return Err(format!("{}", e));
    }
    // Finish the tar archive explicitly so no trailing data is missing.
    if let Err(e) = tar.finish() {
        error!("Cannot finish tar archive, error: {}", e);
        let _ = remove_file(tarname.as_str());
        return Err(format!("{}", e));
    }
    let enc = match tar.into_inner() {
        Ok(enc) => enc,
        Err(e) => {
            error!("Cannot retrieve archive encoder, error: {}", e);
            let _ = remove_file(tarname.as_str());
            return Err(format!("{}", e));
        }
    };
    // Finish the gzip stream explicitly so the archive is complete and valid.
    match enc.finish() {
        Ok(_) => Ok(format!("File {} compressed successfully.", filename)),
        Err(e) => {
            error!("Cannot finish gzip compression, error: {}", e);
            let _ = remove_file(tarname.as_str());
            Err(format!("{}", e))
        }
    }
}

// ----------------------------------------------------------------------------

// Get the number of entries of a given directory (legacy helper).
pub fn get_iteration(filepath: &str) -> u32{
    Path::new(filepath).read_dir().expect("read_dir call failed").count() as u32
}

// ----------------------------------------------------------------------------

// Extract the shard iteration from a file name managed by FIM.
// Matches current and old shard formats: '<filename>.<N>',
// '<filename>.<N>.tar.gz' and '<filename>.<N>.zip'.
// Returns None for any other file.
fn parse_shard_iteration(name: &str, filename: &str) -> Option<u32> {
    let rest = match name.strip_prefix(filename).and_then(|r| r.strip_prefix('.')) {
        Some(rest) => rest,
        None => return None
    };
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    match &rest[digits.len()..] {
        "" | ".tar.gz" | ".zip" => digits.parse::<u32>().ok(),
        _ => None
    }
}

// ----------------------------------------------------------------------------

// List the shards of a given file stored in the archive directory,
// sorted by iteration ascending (oldest first).
fn list_shards(archive_path: &str, filename: &str) -> Vec<(u32, String)> {
    let mut shards: Vec<(u32, String)> = Vec::new();
    match read_dir(archive_path) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if let Some(iteration) = parse_shard_iteration(name.as_str(), filename) {
                    shards.push((iteration, entry.path().to_string_lossy().into_owned()));
                }
            }
        },
        Err(e) => debug!("Cannot read archive directory '{}', error: {}", archive_path, e)
    };
    shards.sort_by_key(|(iteration, _)| *iteration);
    shards
}

// ----------------------------------------------------------------------------

// List the archive shards of a given file, ordered from the oldest to the
// newest one. Old format shards are included.
pub fn get_archive_shards(archive_path: &str, filename: &str) -> Vec<String> {
    list_shards(archive_path, filename).iter().map(|(_, path)| path.clone()).collect()
}

// ----------------------------------------------------------------------------

// Get the next free iteration for the shards of a given file. Iterations of
// existing shards are never reused, even if some shard was removed in
// between, so a rotation can never overwrite evidence of a previous one.
pub fn get_next_iteration(archive_path: &str, filename: &str) -> u32 {
    match list_shards(archive_path, filename).last() {
        Some((iteration, _)) => iteration + 1,
        None => 0
    }
}

// ----------------------------------------------------------------------------

// Check if a shard (plain or compressed) already exists for the given
// iteration of a file.
fn shard_exists(archive_path: &str, filename: &str, iteration: u32) -> bool {
    let base = format!("{}/{}.{}", archive_path, filename, iteration);
    Path::new(base.as_str()).exists() ||
        Path::new(format!("{}.tar.gz", base).as_str()).exists() ||
        Path::new(format!("{}.zip", base).as_str()).exists()
}

// ----------------------------------------------------------------------------

// Compress a rotated shard and remove it once the archive is complete.
// On compression failure the shard is kept as it is, so no evidence is lost
// and the compression can be retried on the next rotator cycle.
fn compress_shard(file_rotated: &str) {
    if ! Path::new(file_rotated).exists() {
        error!("Cannot compress missing shard '{}'.", file_rotated);
        return;
    }
    info!("Compressing rotated file {}", file_rotated);
    #[cfg(windows)]
    let result = compress_zip_file(file_rotated);
    #[cfg(not(windows))]
    let result = compress_tgz_file(file_rotated);
    match result {
        Ok(message) => {
            info!("{}", message);
            match remove_file(file_rotated) {
                Ok(_v) => info!("File {} removed.", file_rotated),
                Err(e) => error!("Cannot remove rotated file, error: {}", e)
            }
        },
        Err(e) => error!("Error compressing file, shard kept for next iteration, error: {}", e)
    };
}

// ----------------------------------------------------------------------------

fn rotate_file(iteration: u32, lock: Arc<Mutex<String>>){
    let filepath = lock.lock().unwrap().clone();
    info!("Rotating {} file...", filepath);

    let path = Path::new(filepath.as_str());
    let filename = path.file_name().unwrap().to_str().unwrap();
    let mut parent_path = path.parent().unwrap().to_path_buf();
    parent_path.push("archive");

    // Never reuse the iteration of an existing shard. Reusing a name could
    // overwrite a previous shard, destroying the evidence it holds.
    let mut iteration = iteration;
    while shard_exists(parent_path.to_str().unwrap(), filename, iteration) {
        iteration += 1;
    }
    let file_rotated = format!("{}/{}.{}",
        parent_path.to_str().unwrap(), filename, iteration);

    {
        // Block writers only while swapping the file. The rename is atomic,
        // so events are written either to the shard or to the new file,
        // never lost in between as happened with the former copy+truncate.
        let _guard = lock.lock().unwrap();
        match rename(filepath.as_str(), file_rotated.as_str()){
            Ok(_v) => {
                debug!("File renamed successfully.");
                match File::create(filepath.as_str()){
                    Ok(_) => debug!("New file created successfully."),
                    Err(e) => error!("Cannot create new file after rotation, writers will recreate it, error: {}", e)
                };
            },
            Err(e) => {
                warn!("Cannot rename file, falling back to copy and truncate, error: {}", e);
                match copy(filepath.as_str(), file_rotated.clone()){
                    Ok(_v) => {
                        debug!("File copied successfully.");
                        match File::create(filepath.as_str()){
                            Ok(_) => debug!("File truncated successfully."),
                            Err(e) => {
                                error!("Error truncating file, removing rotated copy to avoid duplicated evidence, error: {}", e);
                                let _ = remove_file(file_rotated.clone());
                            }
                        };
                    },
                    Err(e) => error!("File cannot be copied, retrying on next iteration, error: {}", e)
                };
            }
        };
    }

    info!("File {} rotated.", &filepath);
    // Compression is done out of the lock, writers are not blocked by it.
    compress_shard(file_rotated.as_str());
}

// ----------------------------------------------------------------------------

// Compress shards that were left uncompressed by a previous failed attempt,
// so transient compression errors do not accumulate plain shards.
#[cfg(not(tarpaulin_include))]
fn compress_leftovers(archive_path: &str, filename: &str) {
    for shard in get_archive_shards(archive_path, filename) {
        if shard.ends_with(".tar.gz") || shard.ends_with(".zip") {
            continue;
        }
        info!("Compressing shard left uncompressed: {}", shard);
        compress_shard(shard.as_str());
    }
}

// ----------------------------------------------------------------------------

#[cfg(not(tarpaulin_include))]
pub fn rotator(cfg: AppConfig){
    loop{
        let log_size = if Path::new(cfg.clone().log_file.as_str()).exists() {
            metadata(cfg.clone().log_file).unwrap().len() as usize
        }else{ 0 };
            
        let events_size = if Path::new(cfg.clone().events_file.as_str()).exists() {
            metadata(cfg.clone().events_file).unwrap().len() as usize
        }else{ 0 };

        if events_size >= cfg.events_max_file_size * 1000000 {
            let events_path = Path::new(cfg.events_file.as_str());
            let mut parent_path = events_path.parent().unwrap().to_path_buf();
            parent_path.push("archive");

            if ! parent_path.exists(){
                match create_dir(parent_path.clone()){
                    Ok(_v) => debug!("Archive directory created successfully."),
                    Err(e) => error!("Cannot create archive directory, error: {}", e)
                };
            }

            rotate_file(
                get_next_iteration(parent_path.to_str().unwrap(),
                    events_path.file_name().unwrap().to_str().unwrap()),
                cfg.clone().events_lock);
        }

        if log_size >= cfg.log_max_file_size * 1000000 {
            let log_path = Path::new(cfg.log_file.as_str());
            let mut parent_path = log_path.parent().unwrap().to_path_buf();
            parent_path.push("archive");

            if ! parent_path.exists(){
                match create_dir(parent_path.clone()){
                    Ok(_v) => debug!("Archive directory created successfully."),
                    Err(e) => error!("Cannot create archive directory, error: {}", e)
                };
            }

            rotate_file(
                get_next_iteration(parent_path.to_str().unwrap(),
                    log_path.file_name().unwrap().to_str().unwrap()),
                cfg.clone().log_lock);
        }

        // Compress shards left behind by failed attempts of previous cycles.
        let events_path = Path::new(cfg.events_file.as_str());
        let mut events_archive = events_path.parent().unwrap().to_path_buf();
        events_archive.push("archive");
        if events_archive.exists() {
            compress_leftovers(events_archive.to_str().unwrap(),
                events_path.file_name().unwrap().to_str().unwrap());
        }

        let log_path = Path::new(cfg.log_file.as_str());
        let mut log_archive = log_path.parent().unwrap().to_path_buf();
        log_archive.push("archive");
        if log_archive.exists() {
            compress_leftovers(log_archive.to_str().unwrap(),
                log_path.file_name().unwrap().to_str().unwrap());
        }

        debug!("Sleeping rotator thread for 30 minutes");
        //thread::sleep(Duration::from_secs(1800));
        thread::sleep(Duration::from_secs(60));
    }
}

// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils;
    use std::fs::{create_dir, remove_dir, remove_dir_all};
    use std::env;
    use serial_test::serial;

    #[test]
    fn test_get_iteration() {
        let mut current_path = env::current_dir().unwrap();
        current_path.push("test_get_iteration");
        let test_path = current_path.to_str().unwrap();

        create_dir(test_path).unwrap();
        assert_eq!(get_iteration(test_path), 0);
        assert_ne!(get_iteration(test_path), 1);
        remove_dir(test_path).unwrap();
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_parse_shard_iteration() {
        assert_eq!(parse_shard_iteration("events.json.0", "events.json"), Some(0));
        assert_eq!(parse_shard_iteration("events.json.12", "events.json"), Some(12));
        assert_eq!(parse_shard_iteration("events.json.3.tar.gz", "events.json"), Some(3));
        assert_eq!(parse_shard_iteration("events.json.4.zip", "events.json"), Some(4));
        assert_eq!(parse_shard_iteration("events.json.position", "events.json"), None);
        assert_eq!(parse_shard_iteration("events.json.1.tmp", "events.json"), None);
        assert_eq!(parse_shard_iteration("fim.log.1", "events.json"), None);
        assert_eq!(parse_shard_iteration("events.json", "events.json"), None);
        assert_eq!(parse_shard_iteration("events.json.", "events.json"), None);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_next_iteration() {
        let mut current_path = env::current_dir().unwrap();
        current_path.push("test_get_next_iteration");
        let test_path = String::from(current_path.to_str().unwrap());

        create_dir(test_path.as_str()).unwrap();
        // Empty archive directory starts at iteration 0.
        assert_eq!(get_next_iteration(test_path.as_str(), "events.json"), 0);

        // Current and old shard formats are taken into account.
        File::create(format!("{}/events.json.0", test_path)).unwrap();
        File::create(format!("{}/events.json.1.tar.gz", test_path)).unwrap();
        File::create(format!("{}/events.json.2.zip", test_path)).unwrap();
        // Files of other names or formats do not interfere.
        File::create(format!("{}/events.json.position", test_path)).unwrap();
        File::create(format!("{}/fim.log.9", test_path)).unwrap();
        assert_eq!(get_next_iteration(test_path.as_str(), "events.json"), 3);
        assert_eq!(get_next_iteration(test_path.as_str(), "fim.log"), 10);

        // A removed shard does not free its iteration for reuse, so a new
        // rotation can never overwrite a previous shard.
        remove_file(format!("{}/events.json.1.tar.gz", test_path)).unwrap();
        assert_eq!(get_next_iteration(test_path.as_str(), "events.json"), 3);

        remove_dir_all(test_path).unwrap();
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_archive_shards() {
        let mut current_path = env::current_dir().unwrap();
        current_path.push("test_get_archive_shards");
        let test_path = String::from(current_path.to_str().unwrap());

        create_dir(test_path.as_str()).unwrap();
        File::create(format!("{}/events.json.2.tar.gz", test_path)).unwrap();
        File::create(format!("{}/events.json.0", test_path)).unwrap();
        File::create(format!("{}/events.json.1.zip", test_path)).unwrap();
        File::create(format!("{}/events.json.position", test_path)).unwrap();
        File::create(format!("{}/fim.log.0", test_path)).unwrap();

        let shards = get_archive_shards(test_path.as_str(), "events.json");
        assert_eq!(shards.len(), 3);
        assert!(shards[0].ends_with("events.json.0"));
        assert!(shards[1].ends_with("events.json.1.zip"));
        assert!(shards[2].ends_with("events.json.2.tar.gz"));

        remove_dir_all(test_path).unwrap();
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_compress_zip_file() {
        let mut current_path = env::current_dir().unwrap();
        current_path.push("LICENSE");
        let test_path = current_path.to_str().unwrap();
        let zip_path = format!("{}.zip", test_path);

        compress_zip_file(test_path).unwrap();
        assert_eq!(Path::new(&zip_path).exists(), true);
        remove_file(zip_path).unwrap();
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_compress_tgz_file() {
        let mut current_path = env::current_dir().unwrap();
        current_path.push("LICENSE");
        let test_path = current_path.to_str().unwrap();
        let tgz_path = format!("{}.tar.gz", test_path);

        compress_tgz_file(test_path).unwrap();
        assert_eq!(Path::new(&tgz_path).exists(), true);
        remove_file(tgz_path).unwrap();
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_compress_tgz_file_content() {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let mut current_path = env::current_dir().unwrap();
        current_path.push("test_compress_tgz_file_content.txt");
        let test_path = String::from(current_path.to_str().unwrap());
        let tgz_path = format!("{}.tar.gz", test_path);
        let content = String::from("first line\nsecond line\nthird line\n");

        std::fs::write(test_path.as_str(), content.clone()).unwrap();
        compress_tgz_file(test_path.as_str()).unwrap();

        // The archive must be a complete and valid tar.gz holding the
        // original content byte by byte.
        let archive = File::open(tgz_path.as_str()).unwrap();
        let mut tar = tar::Archive::new(GzDecoder::new(archive));
        let mut entries = tar.entries().unwrap();
        let mut entry = entries.next().unwrap().unwrap();
        let mut extracted = String::new();
        entry.read_to_string(&mut extracted).unwrap();
        assert_eq!(extracted, content);
        assert!(entries.next().is_none());

        remove_file(test_path).unwrap();
        remove_file(tgz_path).unwrap();
    }

    // ------------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_rotate_file() {
        let mut current_path = env::current_dir().unwrap();
        current_path.push("LICENSE");
        let license_path = current_path.to_str().unwrap();

        let mut current_path = env::current_dir().unwrap();
        current_path.push("LICENSE.bk");
        let filename = current_path.file_name().unwrap().to_str().unwrap();
        let copy_path = current_path.to_str().unwrap();

        let mut archive_path = env::current_dir().unwrap();
        archive_path.push("archive");
        create_dir(archive_path.clone()).unwrap();

        copy(license_path, copy_path).unwrap();

        let lock = Arc::new(Mutex::new(String::from(copy_path)));
        let iteration = 0;
        let extension = if utils::get_os() == "windows" { "zip"
        }else{ "tar.gz" };
        let mut file_path = archive_path.clone();
        file_path.push(filename);
        let compressed_file = format!(
            "{}.{}.{}",
            file_path.to_str().unwrap(),
            iteration,
            extension);
        rotate_file(iteration, lock);
        assert_eq!(metadata(copy_path).unwrap().len(), 0);
        assert_ne!(metadata(compressed_file.clone()).unwrap().len(), 0);
        remove_file(copy_path).unwrap();
        remove_file(compressed_file).unwrap();
        remove_dir(archive_path).unwrap();
    }

    // ------------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_rotate_file_does_not_overwrite_shards() {
        let mut current_path = env::current_dir().unwrap();
        current_path.push("LICENSE");
        let license_path = current_path.to_str().unwrap();

        let mut current_path = env::current_dir().unwrap();
        current_path.push("LICENSE.rot");
        let filename = String::from(current_path.file_name().unwrap().to_str().unwrap());
        let copy_path = String::from(current_path.to_str().unwrap());

        let mut archive_path = env::current_dir().unwrap();
        archive_path.push("archive");
        create_dir(archive_path.clone()).unwrap();

        // Pre-existing shard holding evidence of a previous rotation.
        let extension = if utils::get_os() == "windows" { "zip"
        }else{ "tar.gz" };
        let mut file_path = archive_path.clone();
        file_path.push(filename.as_str());
        let previous_shard = format!("{}.0.{}", file_path.to_str().unwrap(), extension);
        std::fs::write(previous_shard.as_str(), "evidence").unwrap();

        copy(license_path, copy_path.as_str()).unwrap();

        let lock = Arc::new(Mutex::new(String::from(copy_path.as_str())));
        rotate_file(0, lock);

        // The previous shard is kept untouched and the new rotation uses
        // the next free iteration.
        assert_eq!(std::fs::read_to_string(previous_shard.as_str()).unwrap(), "evidence");
        let new_shard = format!("{}.1.{}", file_path.to_str().unwrap(), extension);
        assert_ne!(metadata(new_shard.clone()).unwrap().len(), 0);
        assert_eq!(metadata(copy_path.as_str()).unwrap().len(), 0);

        remove_file(copy_path).unwrap();
        remove_file(previous_shard).unwrap();
        remove_file(new_shard).unwrap();
        remove_dir(archive_path).unwrap();
    }

}
