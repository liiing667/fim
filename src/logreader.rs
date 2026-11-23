// Copyright (C) 2022, Achiefs.

// Global constants definitions
pub const AUDIT_PATH: &str = "/var/log/audit";
pub const AUDIT_LOG_PATH: &str = "/var/log/audit/audit.log";

// To manage file reading
use std::io::{BufReader, SeekFrom};
use std::io::prelude::*;
// To manage file system operations (shards and checkpoint state)
use std::fs;
use std::path::Path;
// To manage readed data into collection
use std::collections::HashMap;
// To log the program process
use log::{debug, error};

// Single event data management
use crate::auditevent::Event;
// To manage common functions
use crate::utils;
// To get configuration constants
use crate::appconfig::*;

// Defined type to simplify syntax
type SHashMap = HashMap<String, String>;

// ----------------------------------------------------------------------------

// Read file to extract last data until the Audit ID changes
pub fn read_log(file: String, cfg: AppConfig, position: u64, itx: u64) -> (Event, u64) {
    let mut event: Event = Event::new();
    let mut current_position = position;
    let log = utils::open_file(&file, 0);
    let mut buff = BufReader::new(log);
    match buff.seek(SeekFrom::Current(position as i64)) {
        Ok(p) => debug!("Seek audit log file, position: {}", p),
        Err(e) => error!("{}", e)
    };

    // Read from last registered position until we get event or the end
    let mut data: Vec<HashMap<String, String>> = Vec::new();
    let mut line = String::new();
    while current_position < utils::get_file_end(&file, 0) {
        debug!("Reading start: {}", current_position);
        let bytes_read = match buff.read_line(&mut line){
            Ok(bytes) => {
                debug!("Read string: '{}', bytes read: {}", line, bytes);
                bytes as u64
            },
            Err(e) => {
                error!("Reading string line, position: {}, error: {}", current_position, e);
                0
            }
        };
        current_position += bytes_read;
        debug!("End read position: {}\n", current_position);

        let line_info = parse_audit_log(line.clone());
        if line_info.contains_key("type") && (line_info["type"] == "SYSCALL" ||
            line_info["type"] == "CWD" ||
            line_info["type"] == "PATH" ||
            line_info["type"] == "PROCTITLE") {
            data.push(line_info.clone());
            if line_info.contains_key("type") &&
                line_info["type"] == "PROCTITLE" {
                debug!("PROCTITLE line detected, breaking loop. Data: {:?}", data);
                break;
            }
        }
        line = String::new();
    }
    if !data.is_empty() {
        let last = data.last().unwrap();
        let first = data.first().unwrap();
        if last.contains_key("type") &&
            first.contains_key("type") &&
            last["type"] == "PROCTITLE" &&
            first["type"] == "SYSCALL" {
            let (syscall, cwd, proctitle, paths) = extract_fields(data.clone());
            let audit_vec = cfg.audit.to_vec();

            // Skip the event generation of paths not monitored by FIM
            if paths.iter().any(|p| {
                let cwd_path = cwd["cwd"].as_str();
                cfg.path_in(p["name"].as_str(), cwd_path, audit_vec.clone()) ||
                cfg.path_in(cwd_path, "", audit_vec.clone())
            }) {
                event = Event::from(syscall, cwd, proctitle, paths, cfg.clone());
            }
        }else if data.iter().any(|line| {
            line["type"] == "SYSCALL" ||
            line["type"] == "CWD" ||
            line["type"] == "PATH" ||
            line["type"] == "PROCTITLE"
        }) && itx < 120 {
            current_position = position;
        }else{
            debug!("Audit log discarded, data: {:?}", data);
        }
    }
    (event, current_position)
}

// ----------------------------------------------------------------------------

// Read all complete events available in the given file starting at the given
// position. Returns the events found and the position of the first byte not
// consumed yet (just after the last complete event read).
pub fn read_events(file: &str, cfg: AppConfig, position: u64) -> (Vec<Event>, u64) {
    let mut events: Vec<Event> = Vec::new();
    if ! Path::new(file).exists() {
        error!("Cannot read events, file '{}' does not exist.", file);
        return (events, 0);
    }

    let mut last_position = position;
    let mut ctr = 0;
    let (event, pos) = read_log(String::from(file), cfg.clone(), last_position, ctr);
    if event.id != "0" {
        events.push(event);
    }else{
        ctr += 1;
    }
    last_position = pos;

    while last_position < utils::get_file_end(file, 0) {
        debug!("Reading events, iteration: {}", ctr);
        ctr += 1;
        let (event, pos) = read_log(String::from(file), cfg.clone(), last_position, ctr);
        if event.id != "0" {
            events.push(event);
            ctr = 0;
        }
        if pos == last_position {
            // No progress: the last event is incomplete. read_log discards it
            // after enough retries (itx >= 120), break as a safety measure.
            if ctr >= 120 {
                break;
            }
        }else{
            ctr = 0;
        }
        last_position = pos;
    }
    debug!("Events read from '{}', position: {}", file, last_position);
    (events, last_position)
}

// ----------------------------------------------------------------------------

// Identity of a file used to detect rotations, even across restarts.
#[cfg(target_family = "unix")]
pub fn get_file_identity(file: &str) -> u64 {
    use std::os::unix::fs::MetadataExt;
    match fs::metadata(file) {
        Ok(md) => md.ino(),
        Err(e) => {
            debug!("Cannot get identity of file '{}', error: {}", file, e);
            0
        }
    }
}

#[cfg(target_family = "windows")]
pub fn get_file_identity(file: &str) -> u64 {
    use std::os::windows::fs::MetadataExt;
    match fs::metadata(file) {
        Ok(md) => md.file_index().unwrap_or(0),
        Err(e) => {
            debug!("Cannot get identity of file '{}', error: {}", file, e);
            0
        }
    }
}

// ----------------------------------------------------------------------------

// List the rotated shards of a log file, ordered from the most recent to the
// oldest one (audit.log.1, audit.log.2, ...). Old format shards produced by
// auditd or logrotate ('<file>.<N>') are recognized.
pub fn get_rotated_shards(file: &str) -> Vec<String> {
    let mut shards: Vec<(u32, String)> = Vec::new();
    let path = Path::new(file);
    let filename = match path.file_name() {
        Some(name) => name.to_string_lossy().into_owned(),
        None => {
            error!("Cannot get file name of '{}'", file);
            return Vec::new();
        }
    };
    let parent = match path.parent() {
        Some(p) => p,
        None => {
            error!("Cannot get parent directory of '{}'", file);
            return Vec::new();
        }
    };

    match fs::read_dir(parent) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                match name.strip_prefix(filename.as_str())
                    .and_then(|rest| rest.strip_prefix('.')) {
                    Some(rest) => {
                        if ! rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
                            if let Ok(iteration) = rest.parse::<u32>() {
                                shards.push((iteration,
                                    entry.path().to_string_lossy().into_owned()));
                            }
                        }
                    },
                    None => debug!("File '{}' is not a shard of '{}'", name, file)
                };
            }
        },
        Err(e) => debug!("Cannot read directory '{}', error: {}", parent.display(), e)
    };
    shards.sort_by_key(|(iteration, _)| *iteration);
    shards.iter().map(|(_, path)| path.clone()).collect()
}

// ----------------------------------------------------------------------------

// Reading checkpoint persisted to survive restarts. It identifies the file
// being read (inode on Unix, file index on Windows) and the byte offset of
// the first byte not consumed yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    pub identity: u64,
    pub position: u64
}

impl Checkpoint {
    pub fn new(identity: u64, position: u64) -> Checkpoint {
        Checkpoint { identity, position }
    }
}

// ----------------------------------------------------------------------------

// Persist the given checkpoint into a state file. The write is atomic
// (write to a temporary file, then rename) so an abrupt stop cannot corrupt
// the previously stored state.
pub fn store_checkpoint(file: &str, checkpoint: Checkpoint) -> Result<(), String> {
    if let Some(parent) = Path::new(file).parent() {
        if ! parent.as_os_str().is_empty() && ! parent.exists() {
            if let Err(e) = fs::create_dir_all(parent) {
                error!("Cannot create checkpoint directory '{}', error: {}", parent.display(), e);
                return Err(format!("{}", e));
            }
        }
    }
    let tmp = format!("{}.tmp", file);
    let contents = format!("{} {}\n", checkpoint.identity, checkpoint.position);
    match fs::write(tmp.as_str(), contents) {
        Ok(_) => match fs::rename(tmp.as_str(), file) {
            Ok(_) => {
                debug!("Checkpoint stored in '{}': {:?}", file, checkpoint);
                Ok(())
            },
            Err(e) => {
                error!("Cannot rename checkpoint file '{}', error: {}", file, e);
                Err(format!("{}", e))
            }
        },
        Err(e) => {
            error!("Cannot write checkpoint file '{}', error: {}", tmp, e);
            Err(format!("{}", e))
        }
    }
}

// ----------------------------------------------------------------------------

// Load a checkpoint previously stored with store_checkpoint. Returns None if
// the state file does not exist or holds invalid data.
pub fn load_checkpoint(file: &str) -> Option<Checkpoint> {
    match fs::read_to_string(file) {
        Ok(contents) => {
            let fields: Vec<&str> = contents.split_whitespace().collect();
            if fields.len() != 2 {
                error!("Invalid checkpoint data found in '{}'", file);
                return None;
            }
            match (fields[0].parse::<u64>(), fields[1].parse::<u64>()) {
                (Ok(identity), Ok(position)) => Some(Checkpoint::new(identity, position)),
                _ => {
                    error!("Invalid checkpoint data found in '{}'", file);
                    None
                }
            }
        },
        Err(_) => {
            debug!("No checkpoint file found at '{}'", file);
            None
        }
    }
}

// ----------------------------------------------------------------------------

// Plan produced by recover_reading to resume the audit log reading after a
// restart or a rotation without losing (gap) or duplicating (replay) events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPlan {
    // Shards that still hold unread events, as (path, start offset) pairs
    // ordered from the oldest to the newest one.
    pub pending: Vec<(String, u64)>,
    // Byte offset where the reading of the live file must resume.
    pub position: u64,
    // Identity of the live file, to detect the next rotation.
    pub identity: u64
}

// ----------------------------------------------------------------------------

// Compute how to resume the reading of a log file given the last persisted
// checkpoint. The shard list is compared with the checkpoint to find out
// which data was already consumed:
// - No checkpoint: legacy behavior, jump to the end of the live file.
// - Checkpoint of the live file: resume at the stored offset (or at 0 if
//   the file shrank below it, to avoid seeking past the end).
// - Checkpoint of a rotated shard: drain the unread tail of that shard and
//   every newer shard, then read the live file from the beginning.
// - Unknown checkpoint (shard removed): drain every available shard, oldest
//   first, so no evidence is skipped, then read the live file from 0.
pub fn recover_reading(file: &str, checkpoint: Option<Checkpoint>) -> RecoveryPlan {
    let identity = get_file_identity(file);
    let end = utils::get_file_end(file, 0);
    match checkpoint {
        None => RecoveryPlan { pending: Vec::new(), position: end, identity },
        Some(cp) => {
            if cp.identity == identity {
                let position = if cp.position <= end { cp.position } else { 0 };
                RecoveryPlan { pending: Vec::new(), position, identity }
            }else{
                let shards = get_rotated_shards(file);
                let mut pending: Vec<(String, u64)> = Vec::new();
                match shards.iter().position(|s| get_file_identity(s) == cp.identity) {
                    Some(index) => {
                        // Drain the unread tail of the shard we were reading...
                        pending.push((shards[index].clone(), cp.position));
                        // ...then every newer shard in full, oldest first.
                        for shard in shards[..index].iter().rev() {
                            pending.push((shard.clone(), 0));
                        }
                    },
                    None => {
                        // The shard we were reading is gone (rotated out or
                        // removed). Drain everything available, oldest first,
                        // so no evidence is skipped.
                        for shard in shards.iter().rev() {
                            pending.push((shard.clone(), 0));
                        }
                    }
                };
                // The live file only holds data written after the last
                // rotation, read it from the beginning.
                RecoveryPlan { pending, position: 0, identity }
            }
        }
    }
}

// ----------------------------------------------------------------------------

pub fn extract_fields(data: Vec<HashMap<String, String>>) -> (SHashMap,
    SHashMap, SHashMap, Vec<SHashMap>) {
    let mut paths: Vec<SHashMap> = Vec::new();
    let mut syscall = SHashMap::new();
    let mut cwd = SHashMap::from([ (String::from("cwd"), String::from("/UNKNOWN")) ]);
    let mut proctitle = SHashMap::new();

    data.iter().for_each(|v| {
        match v["type"].as_str() {
            "SYSCALL" => syscall.clone_from(v),
            "PATH" => paths.push(v.clone()),
            "CWD" => cwd.clone_from(v),
            "PROCTITLE" => proctitle.clone_from(v),
            _ => error!("Unidentified Audit field")
        }
    });
    (syscall, cwd, proctitle, paths)
}

// ----------------------------------------------------------------------------

pub fn parse_audit_log(log: String) -> HashMap<String, String> {
    let fields: Vec<&str> = log.split(' ').collect();
    fields.iter()
        .map(|f| {
            let obj: Vec<&str> = f.split('=').collect();
            if obj.len() == 2 {
                (String::from(obj[0]), String::from(obj[1]).replace(['\"', '\n'], ""))
            }else{
                (String::from(obj[0]), String::from("UNKNOWN"))
            }
        }).collect::<HashMap<String, String>>()
}

// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_read_log() {
        if utils::get_os() == "linux" {
            let cfg = AppConfig::new("linux", Some("test/system/audit_config.yml"));
            let (event, position) = read_log(String::from("test/unit/audit.log"),
                cfg, 0, 0);

            assert_eq!(event.id.len(), 36);
            assert_eq!(event.path, ".");
            assert_eq!(event.operation, "CREATE");
            assert_eq!(event.file, "sedTsutP7");
            assert_eq!(event.timestamp, "1659026449689");
            assert_eq!(event.proctitle, "736564002D6900737C68656C6C6F7C4849217C670066696C6531302E747874");
            assert_eq!(event.cap_fver, "0");
            assert_eq!(event.inode, "1972630");
            assert_eq!(event.cap_fp, "0");
            assert_eq!(event.cap_fe, "0");
            assert_eq!(event.item, "1");
            assert_eq!(event.cap_fi, "0");
            assert_eq!(event.dev, "08:02");
            assert_eq!(event.mode, "0100000");
            assert_eq!(event.cap_frootid, "0");
            assert_eq!(event.ouid, "0");
            assert_eq!(event.paths[0]["item"], "0");
            assert_eq!(event.paths[0]["name"], "./");
            assert_eq!(event.paths[0]["inode"], "1966138");
            assert_eq!(event.paths[0]["dev"], "08:02");
            assert_eq!(event.paths[0]["mode"], "040755");
            assert_eq!(event.paths[0]["ouid"], "1000");
            assert_eq!(event.paths[0]["ogid"], "0");
            assert_eq!(event.paths[0]["rdev"], "00:00");
            assert_eq!(event.paths[0]["nametype"], "PARENT");
            assert_eq!(event.paths[0]["cap_fp"], "0");
            assert_eq!(event.paths[0]["cap_fi"], "0");
            assert_eq!(event.paths[0]["cap_fe"], "0");
            assert_eq!(event.paths[0]["cap_fver"], "0");
            assert_eq!(event.paths[0]["cap_frootid"], "0");
            assert_eq!(event.paths[1]["item"], "1");
            assert_eq!(event.paths[1]["name"], "./sedTsutP7");
            assert_eq!(event.paths[1]["inode"], "1972630");
            assert_eq!(event.paths[1]["dev"], "08:02");
            assert_eq!(event.paths[1]["mode"], "0100000");
            assert_eq!(event.paths[1]["ouid"], "0");
            assert_eq!(event.paths[1]["ogid"], "0");
            assert_eq!(event.paths[1]["rdev"], "00:00");
            assert_eq!(event.paths[1]["nametype"], "CREATE");
            assert_eq!(event.paths[1]["cap_fp"], "0");
            assert_eq!(event.paths[1]["cap_fi"], "0");
            assert_eq!(event.paths[1]["cap_fe"], "0");
            assert_eq!(event.paths[1]["cap_fver"], "0");
            assert_eq!(event.paths[1]["cap_frootid"], "0");
            assert_eq!(event.cwd, "/tmp/test");
            assert_eq!(event.syscall, "257");
            assert_eq!(event.ppid, "161880");
            assert_eq!(event.comm, "sed");
            assert_eq!(event.fsuid, "0");
            assert_eq!(event.pid, "161937");
            assert_eq!(event.a0, "ffffff9c");
            assert_eq!(event.a1, "556150ee3c00");
            assert_eq!(event.a2, "c2");
            assert_eq!(event.a3, "180");
            assert_eq!(event.arch, "c000003e");
            assert_eq!(event.auid, "1000");
            assert_eq!(event.items, "2");
            assert_eq!(event.gid, "0");
            assert_eq!(event.euid, "0");
            assert_eq!(event.sgid, "0");
            assert_eq!(event.uid, "0");
            assert_eq!(event.tty, "pts0");
            assert_eq!(event.success, "yes");
            assert_eq!(event.exit, "4");
            assert_eq!(event.ses, "807");
            assert_eq!(event.key, "fim");
            assert_eq!(event.suid, "0");
            assert_eq!(event.egid, "0");
            assert_eq!(event.fsgid, "0");
            assert_eq!(event.exe, "/usr/bin/sed");
            assert_eq!(position, 850);
        }
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_extract_fields() {
        let mut data = Vec::<HashMap<String, String>>::new();
        data.push(HashMap::from([ (String::from("type"), String::from("SYSCALL")) ]));
        data.push(HashMap::from([ (String::from("type"), String::from("CWD")) ]));
        data.push(HashMap::from([ (String::from("type"), String::from("PROCTITLE")) ]));
        data.push(HashMap::from([ (String::from("type"), String::from("PATH")),
            (String::from("nametype"), String::from("CREATE")) ]));
        data.push(HashMap::from([ (String::from("type"), String::from("PATH")),
            (String::from("nametype"), String::from("PARENT")) ]));
        let (a, b, c, vd) = extract_fields(data);
        assert_eq!(a["type"], String::from("SYSCALL"));
        assert_eq!(b["type"], String::from("CWD"));
        assert_eq!(c["type"], String::from("PROCTITLE"));
        assert_eq!(vd[0]["type"], String::from("PATH"));
        assert_eq!(vd[0]["nametype"], String::from("CREATE"));
        assert_eq!(vd[1]["type"], String::from("PATH"));
        assert_eq!(vd[1]["nametype"], String::from("PARENT"));
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_parse_audit_log() {
        let audit_line = String::from("type=CWD msg=audit(1659026449.689:6434): cwd=\"/tmp/test\"");
        let map = parse_audit_log(audit_line);
        assert_eq!(map["type"], "CWD");
        assert_eq!(map["msg"], "audit(1659026449.689:6434):");
        assert_eq!(map["cwd"], "/tmp/test");
        assert_eq!(map.len(), 3);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_read_events() {
        if utils::get_os() == "linux" {
            let cfg = AppConfig::new("linux", Some("test/system/audit_config.yml"));
            let (events, position) = read_events("test/unit/audit.log", cfg, 0);
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].id.len(), 36);
            assert_eq!(position, 850);
        }
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_checkpoint_store_load() {
        let mut dir = env::temp_dir();
        dir.push("fim_test_checkpoint");
        let _ = fs::remove_dir_all(&dir);
        let file = dir.join("audit.position");
        let path = String::from(file.to_str().unwrap());
        let checkpoint = Checkpoint::new(1234, 850);

        // Missing state file loads nothing.
        assert_eq!(load_checkpoint(path.as_str()), None);

        // A stored checkpoint is loaded back identically.
        store_checkpoint(path.as_str(), checkpoint).unwrap();
        assert_eq!(load_checkpoint(path.as_str()), Some(checkpoint));

        // Invalid data loads nothing.
        fs::write(path.as_str(), "invalid data here").unwrap();
        assert_eq!(load_checkpoint(path.as_str()), None);

        let _ = fs::remove_file(path.as_str());
        let _ = fs::remove_dir(dir);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_rotated_shards() {
        let mut dir = env::temp_dir();
        dir.push("fim_test_get_rotated_shards");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let log = dir.join("audit.log");

        fs::File::create(&log).unwrap();
        fs::File::create(dir.join("audit.log.2")).unwrap();
        fs::File::create(dir.join("audit.log.1")).unwrap();
        // Files that are not old format shards are ignored.
        fs::File::create(dir.join("audit.log.position")).unwrap();
        fs::File::create(dir.join("audit.log.1.tmp")).unwrap();
        fs::File::create(dir.join("other.log.1")).unwrap();

        let shards = get_rotated_shards(log.to_str().unwrap());
        assert_eq!(shards.len(), 2);
        assert_eq!(shards[0], String::from(dir.join("audit.log.1").to_str().unwrap()));
        assert_eq!(shards[1], String::from(dir.join("audit.log.2").to_str().unwrap()));

        fs::remove_dir_all(&dir).unwrap();
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_recover_reading_variants() {
        let mut dir = env::temp_dir();
        dir.push("fim_test_recover_reading_variants");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let log = dir.join("audit.log");
        let log_path = String::from(log.to_str().unwrap());
        let shard1 = dir.join("audit.log.1");
        let shard2 = dir.join("audit.log.2");

        fs::write(&log, "current").unwrap();
        fs::write(&shard1, "newer").unwrap();
        fs::write(&shard2, "older").unwrap();
        let identity = get_file_identity(log_path.as_str());
        let end = utils::get_file_end(log_path.as_str(), 0);

        // No checkpoint: legacy behavior, jump to the end of the file.
        let plan = recover_reading(log_path.as_str(), None);
        assert_eq!(plan.pending, Vec::<(String, u64)>::new());
        assert_eq!(plan.position, end);
        assert_eq!(plan.identity, identity);

        // Checkpoint of the live file: resume at the stored offset.
        let plan = recover_reading(log_path.as_str(), Some(Checkpoint::new(identity, 3)));
        assert_eq!(plan.pending, Vec::<(String, u64)>::new());
        assert_eq!(plan.position, 3);

        // Checkpoint past the end (truncated file): restart from 0.
        let plan = recover_reading(log_path.as_str(), Some(Checkpoint::new(identity, 999999)));
        assert_eq!(plan.pending, Vec::<(String, u64)>::new());
        assert_eq!(plan.position, 0);

        // Checkpoint of a rotated shard: drain its unread tail and every
        // newer shard, then read the live file from the beginning.
        let shard2_identity = get_file_identity(shard2.to_str().unwrap());
        let plan = recover_reading(log_path.as_str(),
            Some(Checkpoint::new(shard2_identity, 2)));
        assert_eq!(plan.pending, vec![
            (String::from(shard2.to_str().unwrap()), 2),
            (String::from(shard1.to_str().unwrap()), 0)
        ]);
        assert_eq!(plan.position, 0);
        assert_eq!(plan.identity, identity);

        // Unknown checkpoint (shard removed): drain every shard, oldest
        // first, so no evidence is skipped.
        let plan = recover_reading(log_path.as_str(), Some(Checkpoint::new(u64::MAX, 2)));
        assert_eq!(plan.pending, vec![
            (String::from(shard2.to_str().unwrap()), 0),
            (String::from(shard1.to_str().unwrap()), 0)
        ]);
        assert_eq!(plan.position, 0);

        fs::remove_dir_all(&dir).unwrap();
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_recover_reading_after_restart() {
        if utils::get_os() == "linux" {
            let cfg = AppConfig::new("linux", Some("test/system/audit_config.yml"));
            let mut dir = env::temp_dir();
            dir.push("fim_test_recover_reading_after_restart");
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            let log = dir.join("audit.log");
            let log_path = String::from(log.to_str().unwrap());
            let position_file = dir.join("audit.position");
            let position_path = String::from(position_file.to_str().unwrap());
            // One complete event per block, taken from the unit test fixture.
            let block = fs::read_to_string("test/unit/audit.log").unwrap();

            // First run: two events are written and consumed, the reading
            // position is persisted as a checkpoint.
            fs::write(&log, format!("{}{}", block, block)).unwrap();
            let (events, position) = read_events(log_path.as_str(), cfg.clone(), 0);
            assert_eq!(events.len(), 2);
            store_checkpoint(position_path.as_str(),
                Checkpoint::new(get_file_identity(log_path.as_str()), position)).unwrap();

            // While stopped: one more event is written, the log rotates and
            // two more events are written into the new file.
            let mut file = fs::OpenOptions::new().append(true).open(&log).unwrap();
            file.write_all(block.as_bytes()).unwrap();
            drop(file);
            let shard = dir.join("audit.log.1");
            fs::rename(&log, &shard).unwrap();
            fs::write(&log, format!("{}{}", block, block)).unwrap();

            // Restart: the checkpoint is loaded and the recovery plan is
            // computed comparing the shard list with the stored position.
            let checkpoint = load_checkpoint(position_path.as_str()).unwrap();
            let plan = recover_reading(log_path.as_str(), Some(checkpoint));

            // The shard list holds the rotated shard only.
            let shards = get_rotated_shards(log_path.as_str());
            assert_eq!(shards, vec![String::from(shard.to_str().unwrap())]);

            // The plan drains the unread tail of the rotated shard and
            // restarts the live file from the beginning.
            assert_eq!(plan.pending, vec![(shards[0].clone(), position)]);
            assert_eq!(plan.position, 0);
            assert_eq!(plan.identity, get_file_identity(log_path.as_str()));

            // Draining the plan recovers every event written while stopped,
            // exactly once (no gap, no replay).
            let mut recovered = 0;
            for (shard_path, offset) in plan.pending.iter() {
                let (events, _) = read_events(shard_path.as_str(), cfg.clone(), *offset);
                recovered += events.len();
            }
            let (events, final_position) =
                read_events(log_path.as_str(), cfg.clone(), plan.position);
            recovered += events.len();
            assert_eq!(recovered, 3);
            assert_eq!(final_position, utils::get_file_end(log_path.as_str(), 0));

            fs::remove_dir_all(&dir).unwrap();
        }
    }
}
