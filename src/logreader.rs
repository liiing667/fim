// Copyright (C) 2022, Achiefs.

// Global constants definitions
pub const AUDIT_PATH: &str = "/var/log/audit";
pub const AUDIT_LOG_PATH: &str = "/var/log/audit/audit.log";

// To manage file reading
use std::io::{BufReader, SeekFrom};
use std::io::prelude::*;
// To manage readed data into collection
use std::collections::{HashMap, HashSet, VecDeque};
// To inspect the identity and state of the file being read
use std::fs::{self, File, Metadata};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
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

// Number of bytes kept immediately before the committed offset. They are used
// to detect a file which has been truncated and rewritten while FIM was not
// looking at it.
const ANCHOR_SIZE: usize = 256;

// Number of audit record identifiers remembered to avoid emitting the same
// record twice when a log is replayed (for example after a rotation).
const SEEN_CAPACITY: usize = 8192;

// ----------------------------------------------------------------------------

/// Identity of a log file. The pair device + inode changes when the log is
/// replaced or rotated, which is the only reliable way to distinguish a new
/// file from an append to the previous one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileIdentity {
    pub dev: u64,
    pub inode: u64,
}

impl FileIdentity {
    #[cfg(unix)]
    pub fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            inode: metadata.ino()
        }
    }

    // Audit logs are only consumed on Linux. Keep a stable value on the other
    // platforms so the rest of the code still compiles there.
    #[cfg(not(unix))]
    pub fn from_metadata(_metadata: &Metadata) -> Self {
        Self { dev: 0, inode: 0 }
    }
}

// ----------------------------------------------------------------------------

/// A checkpoint identifies the generation an event was read from. It is
/// captured when an event is parsed and checked again before the offset is
/// committed, so an event can never be committed into a different generation
/// of the log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitToken {
    pub generation: u64,
    pub identity: FileIdentity,
    pub offset: u64,
}

// ----------------------------------------------------------------------------

/// Result of trying to read the next audit record.
pub enum ReadOutcome {
    /// A complete, monitored event ready to be processed and committed.
    Event(Event),
    /// A complete record was consumed but it must not produce an alert
    /// (not monitored, duplicate, or an unrelated audit record).
    Skipped,
    /// No complete record is available yet. The offset must not advance.
    Pending,
    /// The file changed (rotation, replacement or truncation) and the reader
    /// was reset to the beginning of the new generation.
    Resync,
}

// ----------------------------------------------------------------------------

enum SyncResult {
    Ready,
    Pending,
    Resync,
}

// ----------------------------------------------------------------------------

/// Reader which keeps the identity, the committed offset and the last
/// committed record in one state. All of them belong to the same generation
/// and are updated together.
pub struct AuditCursor {
    path: String,
    identity: FileIdentity,
    offset: u64,
    generation: u64,
    anchor: Vec<u8>,
    pending_offset: Option<u64>,
    pending_key: Option<String>,
    pending_token: Option<CommitToken>,
    pending_raw: Vec<u8>,
    seen: HashSet<String>,
    seen_order: VecDeque<String>,
}

impl AuditCursor {
    /// Create a cursor positioned at the end of the current log. This keeps
    /// the historical startup behaviour: records already present when FIM
    /// starts are not replayed.
    pub fn new(path: &str) -> Self {
        let mut cursor = Self {
            path: String::from(path),
            identity: FileIdentity::default(),
            offset: 0,
            generation: 0,
            anchor: Vec::new(),
            pending_offset: None,
            pending_key: None,
            pending_token: None,
            pending_raw: Vec::new(),
            seen: HashSet::new(),
            seen_order: VecDeque::new(),
        };
        if let Ok(metadata) = fs::metadata(path) {
            cursor.identity = FileIdentity::from_metadata(&metadata);
            cursor.offset = metadata.len();
            cursor.update_anchor();
        }
        cursor
    }

    /// Create a cursor at an explicit offset. Used by the compatibility
    /// wrapper `read_log` and by tests.
    pub fn at(path: &str, position: u64) -> Self {
        let mut cursor = Self {
            path: String::from(path),
            identity: FileIdentity::default(),
            offset: position,
            generation: 0,
            anchor: Vec::new(),
            pending_offset: None,
            pending_key: None,
            pending_token: None,
            pending_raw: Vec::new(),
            seen: HashSet::new(),
            seen_order: VecDeque::new(),
        };
        if let Ok(metadata) = fs::metadata(path) {
            cursor.identity = FileIdentity::from_metadata(&metadata);
            // An offset inherited from a previous file is unlikely to land on
            // a record boundary in the new one. Treat such a position as a
            // stale generation instead of interpreting the middle of a record
            // as a new event.
            if cursor.offset > 0 && cursor.offset < metadata.len() {
                if let Ok(mut probe) = File::open(path) {
                    if probe.seek(SeekFrom::Start(cursor.offset)).is_ok() {
                        let mut prefix = [0u8; 5];
                        if probe.read_exact(&mut prefix).is_ok() &&
                            &prefix != b"type=" {
                            cursor.offset = 0;
                        }
                    }
                }
            }
            cursor.update_anchor();
        }
        cursor
    }

    pub fn position(&self) -> u64 { self.offset }

    pub fn generation(&self) -> u64 { self.generation }

    pub fn identity(&self) -> FileIdentity { self.identity }

    // ------------------------------------------------------------------------

    /// Discard all state that belongs to the current file generation and start
    /// again from byte zero. Records already emitted are deliberately kept so
    /// a replay cannot produce duplicate alerts.
    fn reset(&mut self, identity: FileIdentity) {
        self.identity = identity;
        self.offset = 0;
        self.generation = self.generation.wrapping_add(1);
        self.anchor.clear();
        self.pending_offset = None;
        self.pending_key = None;
        self.pending_token = None;
        self.pending_raw.clear();
    }

    // ------------------------------------------------------------------------

    fn update_anchor(&mut self) {
        self.anchor = read_anchor(&self.path, self.offset).unwrap_or_default();
    }

    // ------------------------------------------------------------------------

    fn anchor_matches(&self, path: &str, identity: FileIdentity, size: u64) -> bool {
        if self.offset == 0 {
            return true;
        }
        if size < self.offset {
            return false;
        }
        if self.anchor.is_empty() {
            return true;
        }
        let start = self.offset - self.anchor.len() as u64;
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(_) => return false,
        };
        match file.metadata() {
            Ok(metadata) => {
                if FileIdentity::from_metadata(&metadata) != identity {
                    return false;
                }
            },
            Err(_) => return false,
        }
        if file.seek(SeekFrom::Start(start)).is_err() {
            return false;
        }
        let mut buffer = vec![0u8; self.anchor.len()];
        match file.read_exact(&mut buffer) {
            Ok(_) => buffer == self.anchor,
            Err(_) => false,
        }
    }

    // ------------------------------------------------------------------------

    /// Check that the path still points to the same file generation and that
    /// the content before the committed offset has not been replaced.
    fn sync(&mut self) -> SyncResult {
        let metadata = match fs::metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(_) => {
                // The old file disappeared (it may be in the middle of a
                // rename based rotation). Do not reuse its offset for the
                // file which will be created next.
                if self.offset != 0 || self.identity != FileIdentity::default() {
                    self.reset(FileIdentity::default());
                }
                return SyncResult::Pending;
            }
        };

        let identity = FileIdentity::from_metadata(&metadata);
        if identity != self.identity ||
            metadata.len() < self.offset ||
            !self.anchor_matches(&self.path, identity, metadata.len()) {
            self.reset(identity);
            return SyncResult::Resync;
        }
        SyncResult::Ready
    }

    // ------------------------------------------------------------------------

    /// Read the next complete audit record. If the file changes while the
    /// record is being read, the read is discarded and the cursor reports
    /// `Resync`; the caller can immediately try again from the new generation.
    pub fn read_next(&mut self, cfg: AppConfig) -> ReadOutcome {
        self.pending_offset = None;
        self.pending_key = None;
        self.pending_token = None;
        self.pending_raw.clear();

        let mut attempts = 0;
        while attempts < 8 {
            attempts += 1;
            match self.sync() {
                SyncResult::Pending => return ReadOutcome::Pending,
                SyncResult::Resync => continue,
                SyncResult::Ready => {}
            }
            match self.attempt_read(&cfg) {
                ReadOutcome::Resync => continue,
                outcome => return outcome,
            }
        }
        ReadOutcome::Resync
    }

    // ------------------------------------------------------------------------

    fn attempt_read(&mut self, cfg: &AppConfig) -> ReadOutcome {
        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(_) => return ReadOutcome::Pending,
        };
        let metadata = match file.metadata() {
            Ok(metadata) => metadata,
            Err(_) => return ReadOutcome::Pending,
        };
        let identity = FileIdentity::from_metadata(&metadata);
        if identity != self.identity || metadata.len() < self.offset {
            self.reset(identity);
            return ReadOutcome::Resync;
        }
        // Re-check the committed prefix after opening the file. This closes
        // the gap between `sync` and the actual read.
        if !self.anchor_matches(&self.path, identity, metadata.len()) {
            self.reset(identity);
            return ReadOutcome::Resync;
        }

        let mut reader = BufReader::new(&file);
        if self.offset > 0 &&
            reader.seek(SeekFrom::Start(self.offset)).is_err() {
            return ReadOutcome::Pending;
        }

        let start = self.offset;
        let mut position = start;
        // Bytes before this offset contain no partial record and can be
        // consumed even when no complete event is available yet.
        let mut safe_offset = start;
        let mut record: Vec<SHashMap> = Vec::new();
        let mut raw: Vec<u8> = Vec::new();
        let mut record_key: Option<String> = None;
        let mut line_buffer: Vec<u8> = Vec::new();

        loop {
            line_buffer.clear();
            let line_start = position;
            let bytes_read = match reader.read_until(b'\n', &mut line_buffer) {
                Ok(0) => break,
                Ok(bytes_read) => bytes_read,
                Err(_) => break,
            };
            position += bytes_read as u64;
            raw.extend_from_slice(&line_buffer);

            let line = String::from_utf8_lossy(&line_buffer).to_string();
            let line_info = parse_audit_log(line);
            let field_type = match line_info.get("type") {
                Some(value) => value.clone(),
                None => continue,
            };
            let is_event_line = field_type == "SYSCALL" ||
                field_type == "CWD" ||
                field_type == "PATH" ||
                field_type == "PROCTITLE";
            if !is_event_line {
                if record.is_empty() {
                    safe_offset = position;
                }
                continue;
            }

            let line_key = match line_info.get("msg") {
                Some(value) => value.clone(),
                None => String::new(),
            };

            if field_type == "SYSCALL" {
                // A new syscall starts a new record. Anything left from a
                // previous, unfinished record is discarded, never emitted.
                if !record.is_empty() {
                    record.clear();
                }
                safe_offset = line_start;
                record_key = Some(line_key.clone());
            } else if record.is_empty() {
                // A fragment without a SYSCALL header is not a valid event.
                safe_offset = position;
                continue;
            } else if record_key.as_deref() != Some(line_key.as_str()) {
                // Records from different audit serials must never be mixed
                // together. Drop the incomplete one.
                record.clear();
                record_key = None;
                safe_offset = position;
                continue;
            }

            record.push(line_info);
            if field_type == "PROCTITLE" {
                let next = position;
                if !verify_region(&self.path, self.identity, start, next, &raw) {
                    // The log was rewritten while it was being read.
                    let identity = self.identity;
                    self.reset(identity);
                    return ReadOutcome::Resync;
                }

                let key = record_key.clone().unwrap_or_default();
                let event = build_event(&record, cfg);
                self.pending_offset = Some(next);
                self.pending_token = Some(CommitToken {
                    generation: self.generation,
                    identity: self.identity,
                    offset: self.offset,
                });
                self.pending_raw = raw;

                match event {
                    Some(event) => {
                        if !key.is_empty() && self.seen.contains(&key) {
                            debug!("Audit record {} already emitted, skipping replay", key);
                            self.pending_key = None;
                            return ReadOutcome::Skipped;
                        }
                        self.pending_key = if key.is_empty() { None } else { Some(key) };
                        return ReadOutcome::Event(event);
                    },
                    None => {
                        self.pending_key = None;
                        return ReadOutcome::Skipped;
                    }
                }
            }
        }

        // Consume records which can never become an event (other audit types
        // or malformed fragments) so the next notification does not scan them
        // again. An unfinished event still starts at or after safe_offset.
        if safe_offset > self.offset {
            let consumed = (safe_offset - self.offset) as usize;
            if verify_region(&self.path, self.identity, self.offset, safe_offset,
                &raw[..consumed]) {
                self.offset = safe_offset;
                self.update_anchor();
            }else{
                let identity = self.identity;
                self.reset(identity);
                return ReadOutcome::Resync;
            }
        }
        ReadOutcome::Pending
    }

    // ------------------------------------------------------------------------

    /// Commit the record returned by the last call to `read_next`. The commit
    /// is only applied when the file identity, generation and the exact bytes
    /// of the record are still the same as when the record was read.
    pub fn commit(&mut self) {
        let next = match self.pending_offset.take() {
            Some(next) => next,
            None => return,
        };
        let key = self.pending_key.take();
        let token = match self.pending_token.take() {
            Some(token) => token,
            None => return,
        };
        let raw = std::mem::take(&mut self.pending_raw);

        // Remember the record even if the generation became stale. Otherwise
        // a rotation during processing could make us emit it a second time
        // while replaying the new generation.
        if let Some(key) = key {
            self.mark_seen(key);
        }

        let same_generation = token.generation == self.generation &&
            token.identity == self.identity &&
            token.offset == self.offset;
        if !same_generation {
            return;
        }

        let stable = match fs::metadata(&self.path) {
            Ok(metadata) => {
                let identity = FileIdentity::from_metadata(&metadata);
                identity == token.identity &&
                    metadata.len() >= next &&
                    self.anchor_matches(&self.path, identity, metadata.len()) &&
                    verify_region(&self.path, token.identity, token.offset, next, &raw)
            },
            Err(_) => false,
        };

        if !stable {
            let identity = fs::metadata(&self.path)
                .map(|metadata| FileIdentity::from_metadata(&metadata))
                .unwrap_or_default();
            self.reset(identity);
            return;
        }

        self.offset = next;
        self.update_anchor();
    }

    // ------------------------------------------------------------------------

    fn mark_seen(&mut self, key: String) {
        if self.seen.insert(key.clone()) {
            self.seen_order.push_back(key);
            while self.seen_order.len() > SEEN_CAPACITY {
                if let Some(old) = self.seen_order.pop_front() {
                    self.seen.remove(&old);
                }
            }
        }
    }
}

// ----------------------------------------------------------------------------

fn read_anchor(path: &str, offset: u64) -> Option<Vec<u8>> {
    if offset == 0 {
        return Some(Vec::new());
    }
    let start = offset.saturating_sub(ANCHOR_SIZE as u64);
    let length = (offset - start) as usize;
    let mut file = File::open(path).ok()?;
    file.seek(SeekFrom::Start(start)).ok()?;
    let mut buffer = vec![0u8; length];
    file.read_exact(&mut buffer).ok()?;
    Some(buffer)
}

// ----------------------------------------------------------------------------

fn verify_region(path: &str, identity: FileIdentity, start: u64, end: u64,
    expected: &[u8]) -> bool {
    if end <= start {
        return true;
    }
    if expected.len() as u64 != end - start {
        return false;
    }
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return false,
    };
    match file.metadata() {
        Ok(metadata) => {
            if FileIdentity::from_metadata(&metadata) != identity ||
                metadata.len() < end {
                return false;
            }
        },
        Err(_) => return false,
    }
    if file.seek(SeekFrom::Start(start)).is_err() {
        return false;
    }
    let mut buffer = vec![0u8; expected.len()];
    match file.read_exact(&mut buffer) {
        Ok(_) => buffer == expected,
        Err(_) => false,
    }
}

// ----------------------------------------------------------------------------

fn build_event(record: &[SHashMap], cfg: &AppConfig) -> Option<Event> {
    let syscall = record.iter()
        .find(|line| line.get("type").map(|value| value.as_str() == "SYSCALL").unwrap_or(false))?;
    let cwd = record.iter()
        .find(|line| line.get("type").map(|value| value.as_str() == "CWD").unwrap_or(false))?;
    let proctitle = record.iter()
        .find(|line| line.get("type").map(|value| value.as_str() == "PROCTITLE").unwrap_or(false))?;
    let paths: Vec<SHashMap> = record.iter()
        .filter(|line| line.get("type").map(|value| value.as_str() == "PATH").unwrap_or(false))
        .cloned()
        .collect();

    if paths.is_empty() {
        return None;
    }

    let message = syscall.get("msg")?;
    if message.is_empty() {
        return None;
    }
    if record.iter().any(|line| line.get("msg") != Some(message)) {
        return None;
    }

    // Event::from accesses these fields directly, so only build an event from
    // a structurally complete audit record.
    const SYSCALL_FIELDS: [&str; 26] = [
        "syscall", "ppid", "comm", "fsuid", "pid", "a0", "a1", "a2", "a3",
        "arch", "auid", "items", "gid", "euid", "sgid", "uid", "tty",
        "success", "exit", "ses", "key", "suid", "egid", "fsgid", "exe", "msg"
    ];
    if SYSCALL_FIELDS.iter().any(|field| !syscall.contains_key(*field)) {
        return None;
    }
    if !cwd.contains_key("cwd") ||
        !proctitle.contains_key("proctitle") ||
        !proctitle.contains_key("msg") {
        return None;
    }
    if paths.iter().any(|path| !path.contains_key("name")) {
        return None;
    }

    let audit_vec = cfg.audit.to_vec();
    let cwd_path = cwd["cwd"].as_str();
    if !paths.iter().any(|path| {
        cfg.path_in(path["name"].as_str(), cwd_path, audit_vec.clone()) ||
            cfg.path_in(cwd_path, "", audit_vec.clone())
    }) {
        return None;
    }

    Some(Event::from(syscall.clone(), cwd.clone(), proctitle.clone(), paths,
        AppConfig::clone(cfg)))
}

// ----------------------------------------------------------------------------

// Read all complete events available in a file from the given offset. The
// returned offset is the position just after the last committed event; an
// incomplete record is left unread so a later call can finish it.
pub fn read_events(file: &str, cfg: AppConfig, position: u64) -> (Vec<Event>, u64) {
    let mut cursor = AuditCursor::at(file, position);
    let mut events: Vec<Event> = Vec::new();
    let mut resyncs = 0;
    loop {
        match cursor.read_next(AppConfig::clone(&cfg)) {
            ReadOutcome::Event(event) => {
                resyncs = 0;
                events.push(event);
                cursor.commit();
            },
            ReadOutcome::Skipped => {
                resyncs = 0;
                cursor.commit();
            },
            ReadOutcome::Pending => break,
            ReadOutcome::Resync => {
                resyncs += 1;
                if resyncs > 8 {
                    break;
                }
            }
        }
    }
    (events, cursor.position())
}

// ----------------------------------------------------------------------------

// Read file to extract last data until the Audit ID changes
pub fn read_log(file: String, cfg: AppConfig, position: u64, itx: u64) -> (Event, u64) {
    let mut event: Event = Event::new();
    // A rotated file starts again from zero. Do not keep seeking at an offset
    // which belongs to the previous file.
    let file_end = utils::get_file_end(&file, 0);
    let mut current_position = if position > file_end {
        0
    }else{
        position
    };
    // An offset from the previous file rarely falls on a record boundary in
    // the new one. Every audit record starts with "type=", so use that to
    // detect a stale position before interpreting the middle of a record as a
    // brand new event.
    if current_position > 0 && current_position < file_end {
        if let Ok(mut probe) = File::open(&file) {
            if probe.seek(SeekFrom::Start(current_position)).is_ok() {
                let mut prefix = [0u8; 5];
                if probe.read_exact(&mut prefix).is_ok() &&
                    &prefix != b"type=" {
                    current_position = 0;
                }
            }
        }
    }
    let log = utils::open_file(&file, 0);
    let mut buff = BufReader::new(log);
    match buff.seek(SeekFrom::Current(current_position as i64)) {
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
}
