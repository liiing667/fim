// Copyright (C) 2024, Achiefs.

// Audit rule lifecycle management.
//
// Linux keeps audit watch rules in the kernel across process restarts.  FIM
// therefore has to remember which rules it installed, so that:
//   * a restart can remove rules that belonged to an older configuration,
//   * rules written by an administrator (or another FIM instance) are never
//     removed just because they share a path or key with a FIM rule,
//   * a partially failed installation can be rolled back to the complete
//     previous rule set before the error is reported.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use yaml_rust::Yaml;

use crate::appconfig::AppConfig;
use crate::utils;

pub const DEFAULT_AUDIT_KEY: &str = "fim";
pub const DEFAULT_AUDIT_PERMISSIONS: &str = "wax";
pub const AUDIT_STATE_VERSION: u32 = 1;

const STATE_FILE_NAME: &str = "audit_rules.json";

// ----------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AuditRule {
    pub path: String,
    pub key: String,
    pub permissions: String,
}

impl AuditRule {
    pub fn new(path: &str, key: &str, permissions: &str) -> Self {
        AuditRule {
            path: canonical_rule_path(path),
            key: normalize_key(key),
            permissions: display_permissions(permissions),
        }
    }

    /// Build a rule from the `audit` section of config.yml.  A malformed or
    /// empty entry is rejected here, before anything is sent to auditctl.
    pub fn from_config(value: &Yaml) -> Option<Self> {
        let raw_path = value["path"].as_str()?.trim();
        if raw_path.is_empty() {
            warn!("[audit-rules] Ignoring audit rule without a path.");
            return None;
        }

        let raw_key = value["key"].as_str().unwrap_or(DEFAULT_AUDIT_KEY);
        let raw_permissions = value["rule"].as_str();
        Some(AuditRule::new(
            raw_path,
            raw_key,
            raw_permissions.unwrap_or(DEFAULT_AUDIT_PERMISSIONS),
        ))
    }

    /// Stable identity used for ownership and snapshot comparison.  Trailing
    /// slashes and permission order do not change the identity.
    pub fn identity(&self) -> String {
        format!(
            "{}|{}|{}",
            canonical_rule_path(&self.path),
            normalize_key(&self.key),
            normalize_permissions(&self.permissions)
        )
    }

    pub fn add_args(&self) -> Vec<String> {
        vec![
            String::from("-w"),
            self.path.clone(),
            String::from("-k"),
            self.key.clone(),
            String::from("-p"),
            self.permissions.clone(),
        ]
    }

    pub fn remove_args(&self) -> Vec<String> {
        vec![
            String::from("-W"),
            self.path.clone(),
            String::from("-k"),
            self.key.clone(),
            String::from("-p"),
            self.permissions.clone(),
        ]
    }
}

// ----------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OwnedAuditRule {
    pub path: String,
    pub key: String,
    pub permissions: String,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub generation: u64,
}

impl OwnedAuditRule {
    fn new(rule: &AuditRule, owner: &str, generation: u64) -> Self {
        OwnedAuditRule {
            path: rule.path.clone(),
            key: rule.key.clone(),
            permissions: rule.permissions.clone(),
            owner: String::from(owner),
            generation,
        }
    }

    fn rule(&self) -> AuditRule {
        AuditRule::new(&self.path, &self.key, &self.permissions)
    }
}

// ----------------------------------------------------------------------------

fn default_state_version() -> u32 {
    AUDIT_STATE_VERSION
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditRuleState {
    #[serde(default = "default_state_version")]
    pub version: u32,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub generation: u64,
    #[serde(default)]
    pub updated_at: String,
    #[serde(default)]
    pub rules: Vec<OwnedAuditRule>,
}

impl Default for AuditRuleState {
    fn default() -> Self {
        AuditRuleState {
            version: AUDIT_STATE_VERSION,
            owner: String::new(),
            generation: 0,
            updated_at: String::new(),
            rules: Vec::new(),
        }
    }
}

// ----------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
pub struct AuditRuleFailure {
    pub timestamp: String,
    pub stage: String,
    pub owner: String,
    pub generation: u64,
    pub rule_path: String,
    pub rule_key: String,
    pub rule_permissions: String,
    pub error: String,
    pub rollback: String,
}

// ----------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct AuditRuleError {
    pub stage: String,
    pub owner: String,
    pub generation: u64,
    pub rule: Option<AuditRule>,
    pub message: String,
    pub rollback: String,
}

impl AuditRuleError {
    fn new(
        stage: &str,
        owner: &str,
        generation: u64,
        rule: Option<&AuditRule>,
        message: String,
        rollback: String,
    ) -> Self {
        AuditRuleError {
            stage: String::from(stage),
            owner: String::from(owner),
            generation,
            rule: rule.cloned(),
            message,
            rollback,
        }
    }
}

impl fmt::Display for AuditRuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rule = match &self.rule {
            Some(rule) => format!(
                " rule_path='{}' rule_key='{}' rule_permissions='{}'",
                rule.path, rule.key, rule.permissions
            ),
            None => String::new(),
        };
        write!(
            f,
            "[audit-rules] stage='{}' owner='{}' generation='{}'{} error='{}' rollback='{}'",
            self.stage,
            self.owner,
            self.generation,
            rule,
            self.message,
            self.rollback
        )
    }
}

impl std::error::Error for AuditRuleError {}

// ----------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct AuditRuleReport {
    pub before: Vec<AuditRule>,
    pub after: Vec<AuditRule>,
    pub owned: Vec<AuditRule>,
    pub added: Vec<AuditRule>,
    pub removed: Vec<AuditRule>,
    pub generation: u64,
}

// ----------------------------------------------------------------------------

/// Small backend abstraction around auditctl.  Keeping the command boundary
/// explicit makes the ownership transaction testable without a live kernel
/// audit subsystem.
pub trait AuditCtl {
    fn list(&self) -> Result<Vec<AuditRule>, String>;
    fn add(&self, rule: &AuditRule) -> Result<(), String>;
    fn remove(&self, rule: &AuditRule) -> Result<(), String>;
}

// ----------------------------------------------------------------------------

pub struct SystemAuditCtl;

impl AuditCtl for SystemAuditCtl {
    fn list(&self) -> Result<Vec<AuditRule>, String> {
        let output = match utils::run_auditctl_output(&["-l"]) {
            Ok(output) => output,
            Err(first_error) => {
                // Some restricted environments only allow querying a key.
                match utils::run_auditctl_output(&["-l", "-k", DEFAULT_AUDIT_KEY]) {
                    Ok(output) => output,
                    Err(_) => return Err(first_error),
                }
            }
        };
        let rules = parse_auditctl_rules(&output);
        if rules.is_empty() {
            if let Ok(output) = utils::run_auditctl_output(&["-l", "-k", DEFAULT_AUDIT_KEY]) {
                return Ok(parse_auditctl_rules(&output));
            }
        }
        Ok(rules)
    }

    fn add(&self, rule: &AuditRule) -> Result<(), String> {
        let args: Vec<String> = rule.add_args();
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        utils::run_auditctl_output(&args).map(|_| ())
    }

    fn remove(&self, rule: &AuditRule) -> Result<(), String> {
        let args: Vec<String> = rule.remove_args();
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        utils::run_auditctl_output(&args).map(|_| ())
    }
}

// ----------------------------------------------------------------------------

/// Normalize the audit permission spelling without changing its meaning.
/// `rwxa`, `wax` and `xwa` all describe the same access set.
pub fn normalize_permissions(raw: &str) -> String {
    let flags = permission_flags(raw);
    if !flags.iter().any(|flag| *flag) {
        return String::from(DEFAULT_AUDIT_PERMISSIONS);
    }

    let mut normalized = String::new();
    for (index, character) in ['r', 'w', 'a', 'x'].iter().enumerate() {
        if flags[index] {
            normalized.push(*character);
        }
    }
    normalized
}

/// Keep the spelling used by the configuration/auditctl snapshot so command
/// arguments and snapshots do not change unnecessarily.  Identity comparison
/// still uses `normalize_permissions`.
pub fn display_permissions(raw: &str) -> String {
    let mut normalized = String::new();
    for character in raw.chars() {
        let character = character.to_ascii_lowercase();
        if ['r', 'w', 'a', 'x'].contains(&character) && !normalized.contains(character) {
            normalized.push(character);
        }
    }
    if normalized.is_empty() {
        String::from(DEFAULT_AUDIT_PERMISSIONS)
    } else {
        normalized
    }
}

fn permission_flags(raw: &str) -> [bool; 4] {
    let mut read = false;
    let mut write = false;
    let mut attribute = false;
    let mut execute = false;

    for character in raw.chars() {
        match character.to_ascii_lowercase() {
            'r' => read = true,
            'w' => write = true,
            'a' => attribute = true,
            'x' => execute = true,
            _ => {}
        }
    }
    [read, write, attribute, execute]
}

pub fn normalize_key(raw: &str) -> String {
    let key = raw.trim();
    if key.is_empty() {
        String::from(DEFAULT_AUDIT_KEY)
    } else {
        String::from(key)
    }
}

/// Lexically normalize a path, and resolve it when it exists.  This turns
/// `/tmp/` and `/tmp` into the same ownership object while still working for
/// directories that were removed by a later configuration.
pub fn canonical_rule_path(path: &str) -> String {
    let raw_path = Path::new(path);
    if let Ok(canonical) = fs::canonicalize(raw_path) {
        return canonical.to_string_lossy().into_owned();
    }

    let absolute = if raw_path.is_absolute() {
        raw_path.to_path_buf()
    } else {
        match env::current_dir() {
            Ok(current) => current.join(raw_path),
            Err(_) => raw_path.to_path_buf(),
        }
    };

    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if normalized.file_name().is_some() {
                    normalized.pop();
                } else if !normalized.has_root() {
                    normalized.push("..");
                }
            }
            Component::Normal(name) => normalized.push(name),
        }
    }

    let normalized = normalized.to_string_lossy().into_owned();
    if normalized.is_empty() {
        String::from(path.trim_end_matches(&['/', '\\'][..]))
    } else {
        normalized
    }
}

// ----------------------------------------------------------------------------

pub fn rules_from_config(cfg: &AppConfig) -> Vec<AuditRule> {
    rules_from_array(&cfg.audit)
}

pub fn rules_from_array(array: &yaml_rust::yaml::Array) -> Vec<AuditRule> {
    deduplicate_rules(
        array
            .iter()
            .filter_map(AuditRule::from_config)
            .collect::<Vec<AuditRule>>(),
    )
}

fn deduplicate_rules(rules: Vec<AuditRule>) -> Vec<AuditRule> {
    let mut by_identity: BTreeMap<String, AuditRule> = BTreeMap::new();
    for rule in rules {
        by_identity.entry(rule.identity()).or_insert(rule);
    }
    by_identity.into_values().collect()
}

// ----------------------------------------------------------------------------

fn split_auditctl_fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;

    for character in line.chars() {
        match quote {
            Some(active_quote) => {
                if character == active_quote {
                    quote = None;
                } else {
                    current.push(character);
                }
            }
            None => match character {
                '\'' | '"' => quote = Some(character),
                character if character.is_whitespace() => {
                    if !current.is_empty() {
                        fields.push(current.clone());
                        current.clear();
                    }
                }
                _ => current.push(character),
            },
        }
    }

    if !current.is_empty() {
        fields.push(current);
    }
    fields
}

fn field_after(fields: &[String], name: &str) -> Option<String> {
    fields
        .iter()
        .position(|field| field == name)
        .and_then(|index| fields.get(index + 1))
        .cloned()
}

fn prefixed_field(fields: &[String], name: &str) -> Option<String> {
    let prefix = format!("{}=", name);
    fields.iter().find_map(|field| {
        field
            .strip_prefix(&prefix)
            .map(|value| String::from(value.trim_matches('"')))
    })
}

fn parse_watch_rule(fields: &[String]) -> Option<AuditRule> {
    let path = field_after(fields, "-w").or_else(|| field_after(fields, "--watch"))?;
    let key = field_after(fields, "-k")
        .or_else(|| field_after(fields, "--key"))
        .unwrap_or_else(|| String::from(DEFAULT_AUDIT_KEY));
    let permissions = field_after(fields, "-p")
        .or_else(|| field_after(fields, "--perm"))
        .unwrap_or_else(|| String::from("rwxa"));
    Some(AuditRule::new(&path, &key, &permissions))
}

fn parse_field_rule(fields: &[String]) -> Option<AuditRule> {
    let path = prefixed_field(fields, "path")?;
    let key = prefixed_field(fields, "key")
        .unwrap_or_else(|| String::from(DEFAULT_AUDIT_KEY));
    let permissions = prefixed_field(fields, "perm")
        .unwrap_or_else(|| String::from("rwxa"));
    Some(AuditRule::new(&path, &key, &permissions))
}

/// Parse the output of `auditctl -l`.  Both watch rules (`-w ...`) and
/// syscall rules (`-a ... -F path=...`) are accepted, because administrators
/// may have either form in the kernel.
pub fn parse_auditctl_rules(output: &str) -> Vec<AuditRule> {
    let mut rules = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = split_auditctl_fields(line);
        if let Some(rule) = parse_watch_rule(&fields).or_else(|| parse_field_rule(&fields)) {
            rules.push(rule);
        }
    }
    deduplicate_rules(rules)
}

// ----------------------------------------------------------------------------

pub fn state_path(cfg: &AppConfig) -> PathBuf {
    for variable in [
        "FIM_AUDIT_RULES_FILE",
        "FIM_AUDIT_STATE_FILE",
        "FIM_AUDIT_STATE",
        "FIM_AUDIT_RULE_STATE",
        "FIM_AUDIT_STATE_PATH",
        "AUDIT_RULE_STATE",
    ] {
        if let Ok(value) = env::var(variable) {
            if !value.trim().is_empty() {
                return PathBuf::from(value);
            }
        }
    }

    let store = Path::new(&cfg.hashscanner_file);
    match store.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(STATE_FILE_NAME),
        _ => PathBuf::from(STATE_FILE_NAME),
    }
}

pub fn instance_owner(cfg: &AppConfig) -> String {
    for variable in ["FIM_AUDIT_OWNER", "FIM_AUDIT_RULE_OWNER"] {
        if let Ok(value) = env::var(variable) {
            if !value.trim().is_empty() {
                return value;
            }
        }
    }
    // The node identity is stable across restarts and independent of where
    // config.yml happens to live.  Deployments that run several FIM instances
    // under the same node can give each one an explicit owner override.
    format!("fim:{}", normalize_key(&cfg.node))
}

fn now_millis() -> String {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis().to_string(),
        Err(_) => String::from("0"),
    }
}

fn load_state(path: &Path) -> AuditRuleState {
    match fs::read_to_string(path) {
        Ok(contents) => match serde_json::from_str::<AuditRuleState>(&contents) {
            Ok(state) => state,
            Err(error) => {
                warn!(
                    "[audit-rules] Ignoring invalid ownership state '{}': {}",
                    path.display(),
                    error
                );
                AuditRuleState::default()
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => AuditRuleState::default(),
        Err(error) => {
            warn!(
                "[audit-rules] Cannot read ownership state '{}': {}",
                path.display(),
                error
            );
            AuditRuleState::default()
        }
    }
}

fn write_state_atomic(path: &Path, state: &AuditRuleState) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "Cannot create audit ownership directory '{}': {}",
                    parent.display(),
                    error
                )
            })?;
        }
    }

    let serialized = serde_json::to_string_pretty(state)
        .map_err(|error| format!("Cannot serialize audit ownership state: {}", error))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(STATE_FILE_NAME);
    let temporary = path.with_file_name(format!(
        ".{}.{}.tmp",
        file_name,
        std::process::id()
    ));

    let result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&temporary)
            .map_err(|error| {
                format!(
                    "Cannot create audit ownership state '{}': {}",
                    temporary.display(),
                    error
                )
            })?;
        file.write_all(serialized.as_bytes())
            .map_err(|error| format!("Cannot write audit ownership state: {}", error))?;
        file.sync_all()
            .map_err(|error| format!("Cannot sync audit ownership state: {}", error))?;
        if cfg!(windows) {
            // Windows does not replace an existing file with rename.
            let _ = fs::remove_file(path);
        }
        fs::rename(&temporary, path).map_err(|error| {
            format!(
                "Cannot commit audit ownership state '{}': {}",
                path.display(),
                error
            )
        })?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn write_failure_evidence(path: &Path, failure: &AuditRuleFailure) {
    let evidence_path = path.with_extension("failure.json");
    if let Ok(serialized) = serde_json::to_string_pretty(failure) {
        let _ = fs::write(evidence_path, serialized);
    }
}

// ----------------------------------------------------------------------------

pub fn sync_audit_rules(cfg: &AppConfig) -> Result<AuditRuleReport, AuditRuleError> {
    let desired = rules_from_config(cfg);
    reconcile_audit_rules_at(
        &SystemAuditCtl,
        &instance_owner(cfg),
        &state_path(cfg),
        desired,
    )
}

/// Current kernel watch snapshot.  Kept public so callers (and diagnostics)
/// can compare the rule set with the event source after a restart.
pub fn snapshot_audit_rules() -> Result<Vec<AuditRule>, String> {
    SystemAuditCtl.list()
}

pub fn owned_audit_rules(cfg: &AppConfig) -> Vec<AuditRule> {
    let state = load_state(&state_path(cfg));
    let owner = instance_owner(cfg);
    state
        .rules
        .iter()
        .filter(|rule| rule.owner == owner)
        .map(OwnedAuditRule::rule)
        .collect()
}

pub fn remove_owned_audit_rules(cfg: &AppConfig) -> Result<AuditRuleReport, AuditRuleError> {
    let desired = Vec::new();
    reconcile_audit_rules_at(
        &SystemAuditCtl,
        &instance_owner(cfg),
        &state_path(cfg),
        desired,
    )
}

pub fn has_owned_audit_rules(cfg: &AppConfig) -> bool {
    let state = load_state(&state_path(cfg));
    let owner = instance_owner(cfg);
    state.rules.iter().any(|rule| rule.owner == owner)
}

// ----------------------------------------------------------------------------

fn rollback<B: AuditCtl + ?Sized>(
    backend: &B,
    baseline: &[AuditRule],
    touched: &BTreeSet<String>,
    removed: &[AuditRule],
) -> String {
    let mut problems = Vec::new();
    let baseline_by_id: BTreeMap<String, AuditRule> = baseline
        .iter()
        .cloned()
        .map(|rule| (rule.identity(), rule))
        .collect();

    match backend.list() {
        Ok(current) => {
            let current_by_id: BTreeMap<String, AuditRule> = current
                .iter()
                .cloned()
                .map(|rule| (rule.identity(), rule))
                .collect();

            // Remove anything we may have introduced, including a rule that
            // auditctl created even though the command reported failure.
            for (identity, rule) in &current_by_id {
                if touched.contains(identity) && !baseline_by_id.contains_key(identity) {
                    if let Err(error) = backend.remove(rule) {
                        problems.push(format!(
                            "remove '{}' during rollback failed: {}",
                            identity, error
                        ));
                    }
                }
            }

            // Restore every rule from the complete previous snapshot, keeping
            // the original snapshot order.
            for rule in baseline {
                let identity = rule.identity();
                if !current_by_id.contains_key(&identity) {
                    if let Err(error) = backend.add(rule) {
                        problems.push(format!(
                            "restore '{}' during rollback failed: {}",
                            identity, error
                        ));
                    }
                }
            }
        }
        Err(error) => {
            // We could not inspect the kernel snapshot.  At least undo the
            // operations whose result we know about.
            for rule in removed {
                if let Err(restore_error) = backend.add(rule) {
                    problems.push(format!(
                        "restore '{}' during rollback failed: {}",
                        rule.identity(),
                        restore_error
                    ));
                }
            }
            problems.push(format!("cannot list rules during rollback: {}", error));
        }
    }

    if problems.is_empty() {
        String::from("complete")
    } else {
        format!("incomplete: {}", problems.join("; "))
    }
}

// ----------------------------------------------------------------------------

/// Reconcile the kernel watch set with one immutable desired configuration.
/// Ownership metadata is committed only after the whole transaction succeeds.
pub fn reconcile_audit_rules_at<B: AuditCtl + ?Sized>(
    backend: &B,
    owner: &str,
    state_path: &Path,
    desired: Vec<AuditRule>,
) -> Result<AuditRuleReport, AuditRuleError> {
    let state = load_state(state_path);
    let generation = state.generation.saturating_add(1);
    let desired = deduplicate_rules(desired);
    let desired_ids: BTreeSet<String> = desired.iter().map(AuditRule::identity).collect();
    let current_owned: Vec<OwnedAuditRule> = state
        .rules
        .iter()
        .filter(|rule| rule.owner == owner)
        .cloned()
        .collect();

    // With an empty configuration and nothing owned by this instance there is
    // no transaction to run.  This keeps an ordinary monitor-only startup from
    // depending on auditctl at all.
    if desired.is_empty() && current_owned.is_empty() {
        let before = match backend.list() {
            Ok(rules) => deduplicate_rules(rules),
            Err(_) => Vec::new(),
        };
        return Ok(AuditRuleReport {
            after: before.clone(),
            before,
            generation: state.generation,
            ..AuditRuleReport::default()
        });
    }

    let before = match backend.list() {
        Ok(rules) => deduplicate_rules(rules),
        Err(error) => {
            let failure = AuditRuleFailure {
                timestamp: now_millis(),
                stage: String::from("snapshot"),
                owner: String::from(owner),
                generation,
                rule_path: String::new(),
                rule_key: String::new(),
                rule_permissions: String::new(),
                error: error.clone(),
                rollback: String::from("complete"),
            };
            write_failure_evidence(state_path, &failure);
            return Err(AuditRuleError::new(
                "snapshot",
                owner,
                generation,
                None,
                error,
                String::from("complete"),
            ));
        }
    };

    let before_ids: BTreeSet<String> = before.iter().map(AuditRule::identity).collect();
    let mut current_ids = before_ids.clone();
    let mut removed = Vec::new();
    let mut added = Vec::new();

    let stale: Vec<AuditRule> = current_owned
        .iter()
        .map(OwnedAuditRule::rule)
        .filter(|rule| !desired_ids.contains(&rule.identity()))
        .collect();

    let mut touched: BTreeSet<String> = desired_ids.iter().cloned().collect();
    for rule in &stale {
        touched.insert(rule.identity());
    }

    for rule in stale {
        // A previous instance may already have removed the rule.  Only issue a
        // delete when the kernel snapshot confirms that it is present.
        if !current_ids.contains(&rule.identity()) {
            continue;
        }

        if let Err(error) = backend.remove(&rule) {
            let rollback = rollback(backend, &before, &touched, &removed);
            let failure = AuditRuleFailure {
                timestamp: now_millis(),
                stage: String::from("remove-stale"),
                owner: String::from(owner),
                generation,
                rule_path: rule.path.clone(),
                rule_key: rule.key.clone(),
                rule_permissions: rule.permissions.clone(),
                error: error.clone(),
                rollback: rollback.clone(),
            };
            write_failure_evidence(state_path, &failure);
            return Err(AuditRuleError::new(
                "remove-stale",
                owner,
                generation,
                Some(&rule),
                error,
                rollback,
            ));
        }
        current_ids.remove(&rule.identity());
        removed.push(rule);
    }

    for rule in &desired {
        let identity = rule.identity();
        if current_ids.contains(&identity) {
            continue;
        }

        if let Err(error) = backend.add(rule) {
            let rollback = rollback(backend, &before, &touched, &removed);
            let failure = AuditRuleFailure {
                timestamp: now_millis(),
                stage: String::from("install"),
                owner: String::from(owner),
                generation,
                rule_path: rule.path.clone(),
                rule_key: rule.key.clone(),
                rule_permissions: rule.permissions.clone(),
                error: error.clone(),
                rollback: rollback.clone(),
            };
            write_failure_evidence(state_path, &failure);
            return Err(AuditRuleError::new(
                "install",
                owner,
                generation,
                Some(rule),
                error,
                rollback,
            ));
        }
        current_ids.insert(identity);
        added.push(rule.clone());
    }

    let added_ids: BTreeSet<String> = added.iter().map(AuditRule::identity).collect();
    let previous_owned: BTreeMap<String, OwnedAuditRule> = current_owned
        .iter()
        .cloned()
        .map(|rule| (rule.rule().identity(), rule))
        .collect();

    let mut committed_rules: Vec<OwnedAuditRule> = state
        .rules
        .iter()
        .filter(|rule| rule.owner != owner)
        .cloned()
        .collect();

    for rule in &desired {
        let identity = rule.identity();
        if previous_owned.contains_key(&identity) || added_ids.contains(&identity) {
            committed_rules.push(OwnedAuditRule::new(rule, owner, generation));
        }
    }

    committed_rules.sort_by(|left, right| {
        let left_rule = left.rule();
        let right_rule = right.rule();
        match left_rule.cmp(&right_rule) {
            Ordering::Equal => left.owner.cmp(&right.owner),
            other => other,
        }
    });
    committed_rules.dedup_by(|left, right| {
        left.owner == right.owner && left.rule().identity() == right.rule().identity()
    });

    let committed = AuditRuleState {
        version: AUDIT_STATE_VERSION,
        owner: String::from(owner),
        generation,
        updated_at: now_millis(),
        rules: committed_rules,
    };

    if let Err(error) = write_state_atomic(state_path, &committed) {
        let rollback = rollback(backend, &before, &touched, &removed);
        let failure = AuditRuleFailure {
            timestamp: now_millis(),
            stage: String::from("state-write"),
            owner: String::from(owner),
            generation,
            rule_path: String::new(),
            rule_key: String::new(),
            rule_permissions: String::new(),
            error: error.clone(),
            rollback: rollback.clone(),
        };
        write_failure_evidence(state_path, &failure);
        return Err(AuditRuleError::new(
            "state-write",
            owner,
            generation,
            None,
            error,
            rollback,
        ));
    }

    let after = match backend.list() {
        Ok(rules) => deduplicate_rules(rules),
        Err(error) => {
            warn!(
                "[audit-rules] Rules committed but snapshot refresh failed: {}",
                error
            );
            before.clone()
        }
    };

    let owned = committed
        .rules
        .iter()
        .filter(|rule| rule.owner == owner)
        .map(OwnedAuditRule::rule)
        .collect();

    info!(
        "[audit-rules] generation={} owner='{}' added={} removed={} snapshot={}",
        generation,
        owner,
        added.len(),
        removed.len(),
        after.len()
    );
    debug!(
        "[audit-rules] before={:?} after={:?} owned={:?}",
        before, after, owned
    );

    Ok(AuditRuleReport {
        before,
        after,
        owned,
        added,
        removed,
        generation,
    })
}

// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct FakeAuditCtl {
        rules: RefCell<Vec<AuditRule>>,
        fail_add: RefCell<Option<String>>,
        fail_remove: RefCell<Option<String>>,
        partially_add_on_failure: bool,
    }

    impl FakeAuditCtl {
        fn new(rules: Vec<AuditRule>) -> Self {
            FakeAuditCtl {
                rules: RefCell::new(deduplicate_rules(rules)),
                fail_add: RefCell::new(None),
                fail_remove: RefCell::new(None),
                partially_add_on_failure: false,
            }
        }

        fn snapshot(&self) -> Vec<AuditRule> {
            let mut rules = self.rules.borrow().clone();
            rules.sort();
            rules
        }
    }

    impl AuditCtl for FakeAuditCtl {
        fn list(&self) -> Result<Vec<AuditRule>, String> {
            Ok(self.snapshot())
        }

        fn add(&self, rule: &AuditRule) -> Result<(), String> {
            if self.partially_add_on_failure {
                let mut rules = self.rules.borrow_mut();
                if !rules.iter().any(|item| item.identity() == rule.identity()) {
                    rules.push(rule.clone());
                }
            }

            if let Some(path) = self.fail_add.borrow().clone() {
                if path == rule.path {
                    return Err(format!("injected add failure for {}", path));
                }
            }

            let mut rules = self.rules.borrow_mut();
            if !rules.iter().any(|item| item.identity() == rule.identity()) {
                rules.push(rule.clone());
            }
            Ok(())
        }

        fn remove(&self, rule: &AuditRule) -> Result<(), String> {
            if let Some(path) = self.fail_remove.borrow().clone() {
                if path == rule.path {
                    return Err(format!("injected remove failure for {}", path));
                }
            }
            let identity = rule.identity();
            self.rules
                .borrow_mut()
                .retain(|item| item.identity() != identity);
            Ok(())
        }
    }

    fn temporary_state_path() -> PathBuf {
        let counter = TEST_COUNTER.fetch_add(1, AtomicOrdering::SeqCst);
        env::temp_dir().join(format!(
            "fim-audit-rules-test-{}-{}.json",
            std::process::id(),
            counter
        ))
    }

    fn rule(path: &str, permissions: &str) -> AuditRule {
        AuditRule::new(path, DEFAULT_AUDIT_KEY, permissions)
    }

    #[test]
    fn test_parse_auditctl_snapshot() {
        let output = concat!(
            "-w /tmp -p rwxa -k fim\n",
            "-w /var/log/audit -p wa -k admin\n",
            "-a always,exit -F path=/etc -F perm=rw -F key=etc-watch\n"
        );
        let rules = parse_auditctl_rules(output);
        assert_eq!(rules.len(), 3);
        assert!(rules.contains(&rule("/tmp", "rwxa")));
        assert!(rules.contains(&rule("/var/log/audit", "wa")));
        assert!(rules.contains(&AuditRule::new("/etc", "etc-watch", "rw")));
    }

    #[test]
    fn test_rule_identity_ignores_trailing_slash_and_permission_order() {
        let first = AuditRule::new("/tmp/", "fim", "wax");
        let second = AuditRule::new("/tmp", "fim", "xwa");
        assert_eq!(first.identity(), second.identity());
    }

    #[test]
    fn test_historical_directory_keeps_same_ownership_identity() {
        let historical = env::temp_dir().join("fim-audit-historical-directory");
        let with_slash = format!("{}/", historical.display());
        let first = AuditRule::new(&historical.to_string_lossy(), "fim", "wax");
        let second = AuditRule::new(&with_slash, "fim", "xwa");
        assert_eq!(first.identity(), second.identity());
    }

    #[test]
    fn test_reconcile_replaces_owned_rules_and_keeps_handwritten_rule() {
        let state_path = temporary_state_path();
        let handwritten = AuditRule::new("/admin", "admin", "wa");
        let backend = FakeAuditCtl::new(vec![handwritten.clone()]);
        let owner = "instance-a";

        let first = reconcile_audit_rules_at(
            &backend,
            owner,
            &state_path,
            vec![rule("/tmp", "wax")],
        )
        .unwrap();
        assert_eq!(first.added.len(), 1);
        assert!(backend.snapshot().contains(&rule("/tmp", "wax")));

        let second = reconcile_audit_rules_at(
            &backend,
            owner,
            &state_path,
            vec![rule("/var", "wax")],
        )
        .unwrap();
        assert_eq!(second.removed.len(), 1);
        let snapshot = backend.snapshot();
        assert!(snapshot.contains(&handwritten));
        assert!(!snapshot.contains(&rule("/tmp", "wax")));
        assert!(snapshot.contains(&rule("/var", "wax")));

        let _ = fs::remove_file(state_path);
    }

    #[test]
    fn test_empty_config_removes_only_owned_rules() {
        let state_path = temporary_state_path();
        let handwritten = AuditRule::new("/admin", "admin", "wa");
        let backend = FakeAuditCtl::new(vec![handwritten.clone()]);

        reconcile_audit_rules_at(
            &backend,
            "instance-a",
            &state_path,
            vec![rule("/tmp", "wax")],
        )
        .unwrap();
        reconcile_audit_rules_at(&backend, "instance-a", &state_path, Vec::new()).unwrap();

        let snapshot = backend.snapshot();
        assert_eq!(snapshot, vec![handwritten]);

        let _ = fs::remove_file(state_path);
    }

    #[test]
    fn test_install_failure_restores_complete_old_snapshot() {
        let state_path = temporary_state_path();
        let old = rule("/old", "wax");
        let new = rule("/new", "wax");
        let backend = FakeAuditCtl::new(vec![old.clone()]);
        *backend.fail_add.borrow_mut() = Some(String::from("/new"));

        let error = reconcile_audit_rules_at(
            &backend,
            "instance-a",
            &state_path,
            vec![old.clone(), new.clone()],
        )
        .unwrap_err();
        assert_eq!(error.stage, "install");
        assert_eq!(error.rollback, "complete");
        assert_eq!(backend.snapshot(), vec![old]);

        // The failed generation must not replace the previous ownership state.
        let state = load_state(&state_path);
        assert_eq!(state.generation, 0);

        let _ = fs::remove_file(state_path);
    }

    #[test]
    fn test_partial_install_failure_removes_partial_rule() {
        let state_path = temporary_state_path();
        let old = rule("/old", "wax");
        let first_new = rule("/new-a", "wax");
        let failing = rule("/new-b", "wax");
        let mut backend = FakeAuditCtl::new(vec![old.clone()]);
        backend.partially_add_on_failure = true;
        *backend.fail_add.borrow_mut() = Some(String::from("/new-b"));

        reconcile_audit_rules_at(
            &backend,
            "instance-a",
            &state_path,
            vec![first_new, failing],
        )
        .unwrap_err();

        assert_eq!(backend.snapshot(), vec![old]);
        let _ = fs::remove_file(state_path);
    }

    #[test]
    fn test_other_instance_rules_are_preserved() {
        let state_path = temporary_state_path();
        let other = AuditRule::new("/other", DEFAULT_AUDIT_KEY, "wax");
        let backend = FakeAuditCtl::new(vec![other.clone()]);
        let other_state = AuditRuleState {
            version: AUDIT_STATE_VERSION,
            owner: String::from("instance-b"),
            generation: 1,
            updated_at: String::from("0"),
            rules: vec![OwnedAuditRule::new(&other, "instance-b", 1)],
        };
        write_state_atomic(&state_path, &other_state).unwrap();

        reconcile_audit_rules_at(
            &backend,
            "instance-a",
            &state_path,
            vec![rule("/tmp", "wax")],
        )
        .unwrap();

        let snapshot = backend.snapshot();
        assert!(snapshot.contains(&other));
        assert!(snapshot.contains(&rule("/tmp", "wax")));
        let state = load_state(&state_path);
        assert!(state
            .rules
            .iter()
            .any(|rule| rule.owner == "instance-b"));

        let _ = fs::remove_file(state_path);
    }
}
