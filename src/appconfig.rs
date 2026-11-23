// Copyright (C) 2021, Achiefs.

// Global constants definitions
pub const VERSION: &str = "0.6.4";
pub const NETWORK_MODE: &str = "NETWORK";
pub const FILE_MODE: &str = "FILE";
pub const BOTH_MODE: &str = "BOTH";
pub const MACHINE_ID_PATH: &str = "/etc/machine-id";
const CONFIG_MACOS_PATH: &str = "/Applications/FileMonitor.app/config.yml";
const CONFIG_LINUX_PATH: &str = "/etc/fim/config.yml";
const CONFIG_WINDOWS_PATH: &str = "C:\\Program Files\\File Integrity Monitor\\config.yml";

// Required dependencies
use yaml_rust::yaml::{Yaml, YamlLoader, Array};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use simplelog::LevelFilter;
use std::sync::{Arc, Mutex};
use std::fmt;
use std::net::IpAddr;
use serde::ser::{Serialize, SerializeStruct, Serializer};

use crate::utils;
use crate::integration::Integration;
use crate::hash::ShaType;

// ----------------------------------------------------------------------------

pub const REDACTED: &str = "[REDACTED]";
pub const NOT_DEFINED: &str = "Not_defined";

// The authentication scheme that was accepted for an endpoint.  Keeping this
// decision in one place prevents the config loader and the request builders
// from making different assumptions about the same credentials.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointAuth {
    None,
    Token,
    Basic,
}

#[derive(Clone, Debug)]
pub struct ConfigTrustError {
    pub stage: &'static str,
    pub target: String,
    pub key: &'static str,
    pub reason: &'static str,
}

impl ConfigTrustError {
    fn new(stage: &'static str, target: &str, key: &'static str, reason: &'static str) -> Self {
        ConfigTrustError {
            stage,
            target: String::from(target),
            key,
            reason,
        }
    }
}

impl fmt::Display for ConfigTrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let legacy_key = self.key.replace('.', "->");
        write!(
            f,
            "config trust rejected [stage={}, target={}, key={} ({})]: {}; secret values are redacted",
            self.stage, self.target, self.key, legacy_key, self.reason
        )
    }
}

// Values computed by the single admission/trust decision.  The AppConfig is
// only populated after this succeeds, so a rejected config cannot leave a
// partially constructed network integration behind.
#[derive(Clone, Debug)]
struct EndpointTrust {
    destination: String,
    address: String,
    insecure: bool,
    auth: EndpointAuth,
    user: String,
    pass: String,
    token: String,
    endpoint_type: String,
}

fn yaml_field<'a>(yaml: &'a Yaml, path: &[&str]) -> Option<&'a Yaml> {
    let mut current = yaml;
    for key in path {
        current = current
            .as_hash()?
            .get(&Yaml::String((*key).to_string()))?;
    }
    Some(current)
}

fn optional_string(yaml: &Yaml, path: &[&str]) -> Result<Option<String>, ()> {
    match yaml_field(yaml, path) {
        None | Some(Yaml::Null) | Some(Yaml::BadValue) => Ok(None),
        Some(Yaml::String(value)) => Ok(Some(value.trim().to_string())),
        Some(_) => Err(()),
    }
}

fn optional_bool(yaml: &Yaml, path: &[&str]) -> Result<Option<bool>, ()> {
    match yaml_field(yaml, path) {
        None | Some(Yaml::Null) | Some(Yaml::BadValue) => Ok(None),
        Some(Yaml::Boolean(value)) => Ok(Some(*value)),
        Some(Yaml::String(value)) => match value.trim().to_ascii_lowercase().as_str() {
            "true" => Ok(Some(true)),
            "false" => Ok(Some(false)),
            _ => Err(()),
        },
        Some(_) => Err(()),
    }
}

fn explicit_development_mode(yaml: &Yaml) -> bool {
    let configured = matches!(optional_bool(yaml, &["development"]), Ok(Some(true)))
        || matches!(optional_bool(yaml, &["development_mode"]), Ok(Some(true)))
        || matches!(optional_bool(yaml, &["dev_mode"]), Ok(Some(true)))
        || matches!(
            optional_bool(yaml, &["events", "endpoint", "development"]),
            Ok(Some(true))
        )
        || matches!(
            optional_bool(yaml, &["events", "endpoint", "dev"]),
            Ok(Some(true))
        )
        || matches!(
            optional_bool(yaml, &["events", "endpoint", "dev_mode"]),
            Ok(Some(true))
        )
        || matches!(
            optional_bool(yaml, &["events", "endpoint", "allow_insecure"]),
            Ok(Some(true))
        );
    configured || environment_development_mode()
}

fn environment_development_mode() -> bool {
    ["FIM_DEV_MODE", "FIM_ALLOW_INSECURE", "FIM_INSECURE_DEV"]
        .iter()
        .any(|name| {
            std::env::var(*name)
                .map(|value| {
                    matches!(
                        value.trim().to_ascii_lowercase().as_str(),
                        "1" | "true" | "yes" | "on"
                    )
                })
                .unwrap_or(false)
        })
}

fn endpoint_host(address: &str) -> Option<String> {
    let value = address.trim();
    let rest = match value.find("://") {
        Some(position) => &value[position + 3..],
        None => value,
    };
    let authority = rest.trim_end_matches('/').split('/').next()?;
    let host = if authority.starts_with('[') {
        let end = authority.find(']')?;
        &authority[1..end]
    } else {
        authority.split(':').next()?
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

fn is_local_host(host: &str) -> bool {
    if host == "localhost" || host == "0.0.0.0" {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(address) => address.is_loopback() || address.is_unspecified(),
        Err(_) => false,
    }
}

fn is_defined_secret(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty() && value != NOT_DEFINED
}

fn redacted_secret(value: &str) -> &'static str {
    if is_defined_secret(value) {
        REDACTED
    } else {
        NOT_DEFINED
    }
}

fn redact_endpoint_address(address: &str) -> String {
    let address = address.trim();
    if address.is_empty() || address == NOT_DEFINED {
        return String::from(address);
    }

    let without_userinfo = match (address.find("://"), address.find('@')) {
        (Some(scheme), Some(at)) if at > scheme + 3 => {
            format!("{}{}@{}", &address[..scheme + 3], REDACTED, &address[at + 1..])
        },
        (_, Some(_)) => String::from(REDACTED),
        _ => String::from(address),
    };

    match without_userinfo.find('?') {
        Some(position) => format!("{}?{}", &without_userinfo[..position], REDACTED),
        None => without_userinfo,
    }
}

// Return a canonical base URL used by every network integration.  Host-only
// legacy addresses are treated as HTTPS, and a trailing slash never changes
// the trust decision.  Cleartext HTTP is only accepted when the operator has
// explicitly selected the insecure development option.
fn normalized_base_url(address: &str, insecure: bool) -> Result<String, &'static str> {
    let value = address.trim();
    if value.is_empty() {
        return Err("endpoint address is required");
    }
    if value.chars().any(|character| character.is_whitespace()) {
        return Err("endpoint address must not contain whitespace");
    }
    if value.contains('@') {
        return Err("credentials must not be embedded in the endpoint address");
    }
    if value.contains('?') || value.contains('#') {
        return Err("endpoint address must not contain a query or fragment");
    }

    let (scheme, rest) = match value.find("://") {
        Some(position) => (
            value[..position].to_ascii_lowercase(),
            &value[position + 3..],
        ),
        None => (
            String::from(if insecure { "http" } else { "https" }),
            value,
        ),
    };
    if scheme != "https" && scheme != "http" {
        return Err("endpoint address must use the http or https scheme");
    }
    if scheme == "http" && !insecure {
        return Err("cleartext HTTP endpoint requires the explicit insecure development option");
    }

    let rest = rest.trim_end_matches('/');
    if rest.is_empty() {
        return Err("endpoint host is required");
    }

    let authority = rest.split('/').next().unwrap_or("");
    let (host, port_suffix) = if authority.starts_with('[') {
        match authority.find(']') {
            Some(end) => {
                let port = &authority[end + 1..];
                if !port.is_empty() {
                    if !port.starts_with(':')
                        || port.len() == 1
                        || !port[1..].chars().all(|value| value.is_ascii_digit())
                    {
                        return Err("endpoint port is invalid");
                    }
                }
                (&authority[1..end], port)
            },
            None => return Err("endpoint host is invalid"),
        }
    } else {
        match authority.split_once(':') {
            Some((host, port)) => {
                if port.is_empty() || !port.chars().all(|value| value.is_ascii_digit()) {
                    return Err("endpoint port is invalid");
                }
                (host, &authority[host.len()..])
            },
            None => (authority, ""),
        }
    };
    if host.is_empty() {
        return Err("endpoint host is required");
    }

    let path = &rest[authority.len()..];
    Ok(format!(
        "{}://{}{}{}",
        scheme,
        host.to_ascii_lowercase(),
        port_suffix,
        path
    ))
}

fn evaluate_trust(yaml: &Yaml) -> Result<EndpointTrust, ConfigTrustError> {
    let target = match optional_string(yaml, &["events", "destination"]) {
        Ok(Some(destination)) => {
            match destination.trim().to_ascii_lowercase().as_str() {
                "" | "file" => String::from("file"),
                "network" => String::from("network"),
                "both" => String::from("both"),
                _ => {
                    return Err(ConfigTrustError::new(
                        "admission",
                        "unknown",
                        "events.destination",
                        "unsupported events destination",
                    ))
                }
            }
        },
        Ok(None) => String::from("file"),
        Err(_) => {
            return Err(ConfigTrustError::new(
                "admission",
                "unknown",
                "events.destination",
                "events destination must be a string",
            ))
        }
    };

    let configured_insecure = match optional_bool(yaml, &["events", "endpoint", "insecure"]) {
        Ok(Some(value)) => value,
        Ok(None) => false,
        Err(_) if target == "file" => false,
        Err(_) => {
            return Err(ConfigTrustError::new(
                "admission",
                &target,
                "events.endpoint.insecure",
                "insecure must be a boolean or true/false string",
            ))
        }
    };
    let dev_mode = target != "file" && explicit_development_mode(yaml);
    let insecure = configured_insecure || dev_mode;

    // Local logging remains a first-class destination.  Endpoint material is
    // ignored for trust purposes in file mode, which keeps legacy/local-only
    // configuration working even when it contains a stale endpoint block.
    if target == "file" {
        let address = optional_string(yaml, &["events", "endpoint", "address"])
            .ok()
            .flatten()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| String::from(NOT_DEFINED));
        let token = optional_string(yaml, &["events", "endpoint", "credentials", "token"])
            .ok()
            .flatten()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| String::from(NOT_DEFINED));
        let user = optional_string(yaml, &["events", "endpoint", "credentials", "user"])
            .ok()
            .flatten()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| String::from(NOT_DEFINED));
        let pass = optional_string(yaml, &["events", "endpoint", "credentials", "password"])
            .ok()
            .flatten()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| String::from(NOT_DEFINED));
        let endpoint_type = if token != NOT_DEFINED {
            String::from("Splunk")
        } else if user != NOT_DEFINED && pass != NOT_DEFINED {
            String::from("Elastic")
        } else {
            String::from(NOT_DEFINED)
        };
        return Ok(EndpointTrust {
            destination: target,
            address,
            insecure,
            auth: EndpointAuth::None,
            user,
            pass,
            token,
            endpoint_type,
        });
    }

    let address = match optional_string(yaml, &["events", "endpoint", "address"]) {
        Ok(Some(value)) if !value.is_empty() => value,
        Ok(_) => {
            return Err(ConfigTrustError::new(
                "admission",
                &target,
                "events.endpoint.address",
                "events->endpoint->address not found in config.yml. network target address is required",
            ))
        },
        Err(_) => {
            return Err(ConfigTrustError::new(
                "admission",
                &target,
                "events.endpoint.address",
                "endpoint address must be a string",
            ))
        }
    };
    if let Err(reason) = normalized_base_url(&address, insecure) {
        return Err(ConfigTrustError::new(
            "admission",
            &target,
            "events.endpoint.address",
            reason,
        ));
    }
    let address = address.trim_end_matches('/').to_string();

    let token = match optional_string(yaml, &["events", "endpoint", "credentials", "token"]) {
        Ok(value) => value,
        Err(_) => {
            return Err(ConfigTrustError::new(
                "admission",
                &target,
                "events.endpoint.credentials.token",
                "endpoint token must be a string",
            ))
        }
    };
    let user = match optional_string(yaml, &["events", "endpoint", "credentials", "user"]) {
        Ok(value) => value,
        Err(_) => {
            return Err(ConfigTrustError::new(
                "admission",
                &target,
                "events.endpoint.credentials.user",
                "endpoint user must be a string",
            ))
        }
    };
    let pass = match optional_string(yaml, &["events", "endpoint", "credentials", "password"]) {
        Ok(value) => value,
        Err(_) => {
            return Err(ConfigTrustError::new(
                "admission",
                &target,
                "events.endpoint.credentials.password",
                "endpoint password must be a string",
            ))
        }
    };

    let (auth, endpoint_type, user, pass, token) = match (token, user, pass) {
        (Some(token), None, None) => {
            if token.is_empty() {
                return Err(ConfigTrustError::new(
                    "admission",
                    &target,
                    "events.endpoint.credentials.token",
                    "endpoint token must not be empty",
                ));
            }
            if token == NOT_DEFINED {
                return Err(ConfigTrustError::new(
                    "admission",
                    &target,
                    "events.endpoint.credentials.token",
                    "endpoint token uses a reserved placeholder",
                ));
            }
            (
                EndpointAuth::Token,
                String::from("Splunk"),
                String::from(NOT_DEFINED),
                String::from(NOT_DEFINED),
                token,
            )
        },
        (Some(_), _, _) => {
            return Err(ConfigTrustError::new(
                "admission",
                &target,
                "events.endpoint.credentials",
                "token and user/password are mutually exclusive",
            ))
        },
        (None, Some(user), Some(pass)) => {
            if user.is_empty() {
                return Err(ConfigTrustError::new(
                    "admission",
                    &target,
                    "events.endpoint.credentials.user",
                    "endpoint user must not be empty",
                ));
            }
            if pass.is_empty() {
                return Err(ConfigTrustError::new(
                    "admission",
                    &target,
                    "events.endpoint.credentials.password",
                    "endpoint password must not be empty",
                ));
            }
            if user == NOT_DEFINED || pass == NOT_DEFINED {
                return Err(ConfigTrustError::new(
                    "admission",
                    &target,
                    "events.endpoint.credentials",
                    "endpoint credentials use a reserved placeholder",
                ));
            }
            (
                EndpointAuth::Basic,
                String::from("Elastic"),
                user,
                pass,
                String::from(NOT_DEFINED),
            )
        },
        (None, Some(user), None) => {
            return Err(ConfigTrustError::new(
                "admission",
                &target,
                if user.is_empty() {
                    "events.endpoint.credentials.user"
                } else {
                    "events.endpoint.credentials.password"
                },
                "events->endpoint->credentials->password not found in config.yml. No endpoint credentials provided in config.yml; user and password must be provided together",
            ))
        },
        (None, None, Some(pass)) => {
            return Err(ConfigTrustError::new(
                "admission",
                &target,
                if pass.is_empty() {
                    "events.endpoint.credentials.password"
                } else {
                    "events.endpoint.credentials.user"
                },
                "events->endpoint->credentials->user not found in config.yml. No endpoint credentials provided in config.yml; user and password must be provided together",
            ))
        },
        (None, None, None) => {
            return Err(ConfigTrustError::new(
                "admission",
                &target,
                "events.endpoint.credentials",
                "No endpoint credentials provided in config.yml; token or user/password is required for a network target",
            ))
        },
    };

    if insecure && !dev_mode {
        let local_target = endpoint_host(&address)
            .map(|host| is_local_host(&host))
            .unwrap_or(false);
        if !local_target {
            return Err(ConfigTrustError::new(
                "admission",
                &target,
                "events.endpoint.insecure",
                "insecure endpoint requires an explicit development mode for non-local targets",
            ));
        }
    }

    Ok(EndpointTrust {
        destination: target,
        address,
        insecure,
        auth,
        user,
        pass,
        token,
        endpoint_type,
    })
}

// ----------------------------------------------------------------------------

#[derive(Clone)]
pub struct AppConfig {
    pub version: String,
    pub path: String,
    pub events_watcher: String,
    pub events_destination: String,
    pub events_max_file_checksum: usize,
    pub events_max_file_size: usize,
    pub checksum_algorithm: ShaType,
    pub endpoint_type: String,
    pub endpoint_address: String,
    pub endpoint_user: String,
    pub endpoint_pass: String,
    pub endpoint_token: String,
    pub events_file: String,
    pub monitor: Array,
    pub audit: Array,
    pub node: String,
    pub log_file: String,
    pub log_level: String,
    pub log_max_file_size: usize,
    pub system: String,
    pub insecure: bool,
    pub events_lock: Arc<Mutex<String>>,
    pub log_lock: Arc<Mutex<String>>,
    pub hashscanner_file: String,
    pub hashscanner_enabled: bool,
    pub hashscanner_interval: usize,
    pub hashscanner_algorithm: ShaType,
    pub engine: String
}

impl AppConfig {

    pub fn clone(&self) -> Self {
        AppConfig {
            version: self.version.clone(),
            path: self.path.clone(),
            events_watcher: self.events_watcher.clone(),
            events_destination: self.events_destination.clone(),
            events_max_file_checksum: self.events_max_file_checksum,
            events_max_file_size: self.events_max_file_size,
            checksum_algorithm: self.checksum_algorithm.clone(),
            endpoint_type: self.endpoint_type.clone(),
            endpoint_address: self.endpoint_address.clone(),
            endpoint_user: self.endpoint_user.clone(),
            endpoint_pass: self.endpoint_pass.clone(),
            endpoint_token: self.endpoint_token.clone(),
            events_file: self.events_file.clone(),
            monitor: self.monitor.clone(),
            audit: self.audit.clone(),
            node: self.node.clone(),
            log_file: self.log_file.clone(),
            log_level: self.log_level.clone(),
            log_max_file_size: self.log_max_file_size,
            system: self.system.clone(),
            insecure: self.insecure,
            events_lock: self.events_lock.clone(),
            log_lock: self.log_lock.clone(),
            hashscanner_file: self.hashscanner_file.clone(),
            hashscanner_enabled: self.hashscanner_enabled,
            hashscanner_interval: self.hashscanner_interval,
            hashscanner_algorithm: self.hashscanner_algorithm.clone(),
            engine: self.engine.clone()
        }
    }

    pub fn new(system: &str, config_path: Option<&str>) -> Self {
        println!("[INFO] System detected '{}'", system);
        let cfg = match config_path {
            Some(path) => String::from(path),
            None => get_config_path(system)
        };
        println!("[INFO] Loaded config from: '{}'", cfg);
        let yaml = read_config(cfg.clone());

        // Admission and integration construction use this exact decision.
        let trust = match evaluate_trust(&yaml[0]) {
            Ok(trust) => trust,
            Err(error) => panic!("{}", error),
        };
        if trust.insecure && trust.destination != "file" {
            println!("[WARN] Insecure development endpoint mode enabled; TLS verification is disabled.");
        }

        // Manage null value on events->destination value
        let events_destination = trust.destination.clone();
        if yaml[0]["events"]["destination"].as_str().is_none() {
            println!("[WARN] events->destination not found in config.yml, using 'file'.");
        }

        // Manage value on events->watcher value
        let events_watcher = match yaml[0]["events"]["watcher"].as_str() {
            Some("poll"|"P"|"POLL"|"Poll") => String::from("Poll"),
            _ => String::from("Recommended")
        };

        // Manage null value on events->file value
        let events_file = match yaml[0]["events"]["file"].as_str() {
            Some(value) if !value.trim().is_empty() => String::from(value),
            _ => {
                if events_destination != *"network" {
                    println!("[ERROR] events->file not found in config.yml.");
                    panic!("events->file not found in config.yml.");
                }else{
                    String::from(NOT_DEFINED)
                }
            }
        };

        // Manage null value on events->max_file_checksum value
        let events_max_file_checksum = match yaml[0]["events"]["max_file_checksum"].as_i64() {
            Some(value) => usize::try_from(value).unwrap(),
            None => 64
        };

        // Manage null value on events->max_file_size value
        let events_max_file_size = match yaml[0]["events"]["max_file_size"].as_i64() {
            Some(value) => usize::try_from(value).unwrap(),
            None => 128
        };

        // Temporal value
        let checksum_algorithm = match yaml[0]["events"]["checksum_algorithm"].as_str() {
            Some(value) => {
                match value {
                    "sha224"|"224"|"SHA224"|"Sha224" => ShaType::Sha224,
                    "sha256"|"256"|"SHA256"|"Sha256" => ShaType::Sha256,
                    "sha384"|"384"|"SHA384"|"Sha384" => ShaType::Sha384,
                    "sha512"|"512"|"SHA512"|"Sha512" => ShaType::Sha512,
                    "keccak224"|"K224"|"KECCAK224"|"Keccak224" => ShaType::Keccak224,
                    "keccak256"|"K256"|"KECCAK256"|"Keccak256" => ShaType::Keccak256,
                    "keccak384"|"K384"|"KECCAK384"|"Keccak384" => ShaType::Keccak384,
                    "keccak512"|"K512"|"KECCAK512"|"Keccak512" => ShaType::Keccak512,
                    _ => ShaType::Sha512
                }
            },
            None => ShaType::Sha256
        };

        let hashscanner_algorithm = match yaml[0]["hashscanner"]["algorithm"].as_str() {
            Some(value) => {
                match value {
                    "sha224"|"224"|"SHA224"|"Sha224" => ShaType::Sha224,
                    "sha256"|"256"|"SHA256"|"Sha256" => ShaType::Sha256,
                    "sha384"|"384"|"SHA384"|"Sha384" => ShaType::Sha384,
                    "sha512"|"512"|"SHA512"|"Sha512" => ShaType::Sha512,
                    "keccak224"|"K224"|"KECCAK224"|"Keccak224" => ShaType::Keccak224,
                    "keccak256"|"K256"|"KECCAK256"|"Keccak256" => ShaType::Keccak256,
                    "keccak384"|"K384"|"KECCAK384"|"Keccak384" => ShaType::Keccak384,
                    "keccak512"|"K512"|"KECCAK512"|"Keccak512" => ShaType::Keccak512,
                    _ => ShaType::Sha256
                }
            },
            None => ShaType::Sha256
        };

        // Endpoint trust was resolved before any runtime integration exists.
        let insecure = trust.insecure;
        let endpoint_address = trust.address.clone();
        let endpoint_token = trust.token.clone();
        let endpoint_user = trust.user.clone();
        let endpoint_pass = trust.pass.clone();
        let endpoint_type = match trust.auth {
            EndpointAuth::Token => String::from("Splunk"),
            EndpointAuth::Basic => String::from("Elastic"),
            EndpointAuth::None => trust.endpoint_type.clone(),
        };


        // Manage null value on monitor value
        let monitor = match yaml[0]["monitor"].as_vec() {
            Some(value) => value.to_vec(),
            None => Vec::new()
        };

        // Manage null value on audit value
        let mut engine = String::from("monitor");
        let audit = match yaml[0]["audit"].as_vec() {
            Some(value) => {
                if utils::get_os() != "linux" {
                    panic!("Audit only supported in Linux systems.");
                }
                engine = String::from("audit");
                value.to_vec()
            },
            None => {
                if monitor.is_empty() {
                    panic!("Neither monitor or audit section found in config.yml.");
                };
                Vec::new()
            }
        };

        // Manage null value on node value
        let node = match yaml[0]["node"].as_str() {
            Some(value) => String::from(value),
            None => {
                match system {
                    "linux" => match utils::get_machine_id().is_empty() {
                        true => utils::get_hostname(),
                        false => utils::get_machine_id()
                    },
                    "macos" => match utils::get_machine_id().is_empty(){
                        true => utils::get_hostname(),
                        false => utils::get_machine_id()
                    }
                    _ => {
                        println!("[WARN] node not found in config.yml, using hostname.");
                        utils::get_hostname()
                    }
                }
            }
        };

        // Manage null value on log->file value
        let log_file = match yaml[0]["log"]["file"].as_str() {
            Some(value) => String::from(value),
            None => {
                println!("[ERROR] log->file not found in config.yml.");
                panic!("log->file not found in config.yml.");
            }
        };

        // Manage null value on log->level value
        let log_level = match yaml[0]["log"]["level"].as_str() {
            Some(value) => String::from(value),
            None => {
                println!("[WARN] log->level not found in config.yml, using 'info'.");
                String::from("info")
            }
        };

        // Manage null value on log->max_file_size value
        let log_max_file_size = match yaml[0]["log"]["max_file_size"].as_i64() {
            Some(value) => usize::try_from(value).unwrap(),
            None => 64
        };

        // Manage null value on hashscanner->file value
        let hashscanner_file = match yaml[0]["hashscanner"]["file"].as_str() {
            Some(value) => String::from(value),
            None => {
                println!("[ERROR] hashscanner->file not found in config.yml.");
                panic!("hashscanner->file not found in config.yml.");
            }
        };

        let hashscanner_interval = match yaml[0]["hashscanner"]["interval"].as_i64() {
            Some(value) => {
                let interval = usize::try_from(value).unwrap();
                if interval >= 5 { interval * 60 }else{ 300 } // Minimum of five minutes 
            },
            None => 3600 // Default one hour
        };

        let hashscanner_enabled = yaml[0]["hashscanner"]["enabled"].as_bool().unwrap_or(true);

        AppConfig {
            version: String::from(VERSION),
            path: cfg,
            events_watcher,
            events_destination,
            events_max_file_checksum,
            events_max_file_size,
            checksum_algorithm,
            endpoint_type,
            endpoint_address,
            endpoint_user,
            endpoint_pass,
            endpoint_token,
            events_file: events_file.clone(),
            monitor,
            audit,
            node,
            log_file: log_file.clone(),
            log_level,
            log_max_file_size,
            system: String::from(system),
            insecure,
            events_lock: Arc::new(Mutex::new(events_file)),
            log_lock: Arc::new(Mutex::new(log_file)),
            hashscanner_file,
            hashscanner_enabled,
            hashscanner_interval,
            hashscanner_algorithm,
            engine
        }
    }

    // ------------------------------------------------------------------------

    // To process log level set on config file
    pub fn get_level_filter(&self) -> LevelFilter {
        let mut log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.log_file.clone())
            .expect("(get_level_filter) Unable to open events log file.");

        match self.log_level.as_str() {
            "debug" | "Debug" | "DEBUG" | "D" | "d" => LevelFilter::Debug,
            "info" | "Info" | "INFO" | "I" | "i" => LevelFilter::Info,
            "error" | "Error" | "ERROR" | "E" | "e" => LevelFilter::Error,
            "warning" | "Warning" | "WARNING" | "W" | "w" | "warn" | "Warn" | "WARN" => LevelFilter::Warn,
            _ => {
                let msg = String::from("[ERROR] invalid log level from 'config.yml', using Info level.");
                println!("{}", msg);
                writeln!(log, "{}", msg).expect("[ERROR] cannot write in log file.");
                LevelFilter::Info
            }
        }
    }

    // ------------------------------------------------------------------------

    pub fn get_events_destination(&self) -> String {
        let destination = self.events_destination.trim().to_ascii_lowercase();
        match destination.as_str() {
            "both" => String::from(BOTH_MODE),
            "network" => String::from(NETWORK_MODE),
            // Default option is to log into file
            _ => String::from(FILE_MODE)
        }
    }

    // ------------------------------------------------------------------------

    pub fn get_index(&self, raw_path: &str, cwd: &str, array: Array) -> usize {
        // Iterate over monitoring paths to match ignore string and ignore event or not
        match array.iter().position(|it| {
            if !cwd.is_empty() && (raw_path.starts_with("./") || raw_path == "." || !raw_path.contains('/')) {
                utils::match_path(cwd, it["path"].as_str().unwrap())
            }else{
                utils::match_path(raw_path, it["path"].as_str().unwrap())
            }
        }){
            Some(pos) => pos,
            None => usize::MAX
        }
    }

    // ------------------------------------------------------------------------

    pub fn get_labels(&self, index: usize, array: Array) -> Vec<String> {
        array[index]["labels"].clone().into_vec().unwrap_or_default()
        .to_vec().iter().map(|element| String::from(element.as_str().unwrap()) ).collect()
    }

    // ------------------------------------------------------------------------

    pub fn match_ignore(&self, index: usize, filename: &str, array: Array) -> bool {
        match array[index]["ignore"].as_vec() {
            Some(igv) => igv.to_vec().iter().any(|ignore| filename.contains(ignore.as_str().unwrap()) ),
            None => false
        }
    }

    // ------------------------------------------------------------------------

    pub fn match_exclude(&self, index: usize, path: &str, array: Array) -> bool {
        match array[index]["exclude"].as_vec() {
            Some(igv) => igv.to_vec().iter().any(|exclude| path.contains(exclude.as_str().unwrap()) ),
            None => false
        }
    }

    // ------------------------------------------------------------------------

    pub fn match_allowed(&self, index: usize, filename: &str, array: Array) -> bool {
        match array[index]["allowed"].as_vec() {
            Some(allowed) => allowed.to_vec().iter().any(|allw| filename.contains(allw.as_str().unwrap())),
            None => true
        }
    }

    // ------------------------------------------------------------------------

    // Returns if a given path and filename is in the configuration paths
    pub fn path_in(&self, raw_path: &str, cwd: &str, vector: Vec<Yaml>) -> bool {
        // Iterate over monitoring paths to match ignore string and ignore event or not
        vector.iter().any(|it| {
            if raw_path.starts_with("./") || raw_path == "." || !raw_path.contains('/') {
                utils::match_path(cwd, it["path"].as_str().unwrap())
            }else{
                utils::match_path(raw_path, it["path"].as_str().unwrap())
            }
        })
    }

    // ------------------------------------------------------------------------

    pub fn get_integrations(&self, index: usize, array: Array) -> Vec<Integration> {
        let entry = match array.get(index) {
            Some(entry) => entry,
            None => return Vec::new(),
        };
        let default = entry["integrations"].clone().into_vec();
        let data = default.unwrap_or_default();
        data.iter()
            .filter_map(|info| {
                let name = info["name"].as_str()?.to_string();
                let condition = info["condition"]
                    .as_vec()?
                    .iter()
                    .map(|element| element.as_str().map(String::from))
                    .collect::<Option<Vec<String>>>()?;
                let binary = info["binary"].as_str()?.to_string();
                let script = info["script"].as_str()?.to_string();
                let parameters = info["parameters"].as_str().unwrap_or("").to_string();
                let integration = Integration::new(name, condition, binary, script, parameters);
                if integration.is_valid() {
                    Some(integration)
                } else {
                    None
                }
            })
            .collect()
    }

    // ------------------------------------------------------------------------

    pub fn is_network_destination(&self) -> bool {
        match self.get_events_destination().as_str() {
            NETWORK_MODE | BOTH_MODE => true,
            _ => false,
        }
    }

    // ------------------------------------------------------------------------

    // The single authentication decision that all request builders consume.
    pub fn endpoint_auth(&self) -> EndpointAuth {
        if !self.is_network_destination() {
            return EndpointAuth::None;
        }
        match self.endpoint_type.as_str() {
            "Splunk" if is_defined_secret(&self.endpoint_token) => EndpointAuth::Token,
            "Elastic" if is_defined_secret(&self.endpoint_user)
                && is_defined_secret(&self.endpoint_pass) => EndpointAuth::Basic,
            _ => EndpointAuth::None,
        }
    }

    // ------------------------------------------------------------------------

    pub fn endpoint_base_url(&self) -> Option<String> {
        if !self.is_network_destination() {
            return None;
        }
        normalized_base_url(&self.endpoint_address, self.insecure).ok()
    }

    // ------------------------------------------------------------------------

    // Defensive check for consumers that receive an AppConfig from another
    // path.  Config loading uses the same rules before this object exists.
    pub fn endpoint_is_trusted(&self) -> bool {
        if !self.is_network_destination() {
            return true;
        }
        if normalized_base_url(&self.endpoint_address, self.insecure).is_err() {
            return false;
        }
        match self.endpoint_auth() {
            EndpointAuth::Token => {
                !is_defined_secret(&self.endpoint_user)
                    && !is_defined_secret(&self.endpoint_pass)
            },
            EndpointAuth::Basic => !is_defined_secret(&self.endpoint_token),
            EndpointAuth::None => false,
        }
    }

    // ------------------------------------------------------------------------

    pub fn can_use_network(&self) -> bool {
        self.is_network_destination() && self.endpoint_is_trusted()
    }

    // ------------------------------------------------------------------------

    pub fn can_route_events(&self) -> bool {
        !self.is_network_destination() || self.endpoint_is_trusted()
    }

    // ------------------------------------------------------------------------

    pub fn redacted_endpoint_address(&self) -> String {
        redact_endpoint_address(&self.endpoint_address)
    }

    // ------------------------------------------------------------------------

    pub fn diagnostic_summary(&self) -> String {
        format!("{:?}", self)
    }

    // ------------------------------------------------------------------------

    pub fn redacted(&self) -> String {
        self.diagnostic_summary()
    }

    // ------------------------------------------------------------------------

    pub fn redacted_debug(&self) -> String {
        self.diagnostic_summary()
    }
}

// ----------------------------------------------------------------------------

impl fmt::Debug for AppConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let address = self.redacted_endpoint_address();
        f.debug_struct("AppConfig")
            .field("version", &self.version)
            .field("path", &self.path)
            .field("events_watcher", &self.events_watcher)
            .field("events_destination", &self.events_destination)
            .field("events_max_file_checksum", &self.events_max_file_checksum)
            .field("events_max_file_size", &self.events_max_file_size)
            .field("checksum_algorithm", &self.checksum_algorithm)
            .field("endpoint_type", &self.endpoint_type)
            .field("endpoint_address", &address)
            .field("endpoint_user", redacted_secret(&self.endpoint_user))
            .field("endpoint_pass", redacted_secret(&self.endpoint_pass))
            .field("endpoint_token", redacted_secret(&self.endpoint_token))
            .field("events_file", &self.events_file)
            .field("node", &self.node)
            .field("log_file", &self.log_file)
            .field("log_level", &self.log_level)
            .field("log_max_file_size", &self.log_max_file_size)
            .field("system", &self.system)
            .field("insecure", &self.insecure)
            .field("endpoint_trusted", &self.endpoint_is_trusted())
            .field("hashscanner_file", &self.hashscanner_file)
            .field("hashscanner_enabled", &self.hashscanner_enabled)
            .field("hashscanner_interval", &self.hashscanner_interval)
            .field("hashscanner_algorithm", &self.hashscanner_algorithm)
            .field("engine", &self.engine)
            .finish()
    }
}

// ----------------------------------------------------------------------------

impl fmt::Display for AppConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

// ----------------------------------------------------------------------------

// Diagnostic serialization intentionally mirrors Debug: authentication
// material is replaced before it can reach a log, console, or crash report.
impl Serialize for AppConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let address = self.redacted_endpoint_address();
        let checksum_algorithm = format!("{:?}", self.checksum_algorithm);
        let hashscanner_algorithm = format!("{:?}", self.hashscanner_algorithm);
        let mut state = serializer.serialize_struct("AppConfig", 27)?;
        state.serialize_field("version", &self.version)?;
        state.serialize_field("path", &self.path)?;
        state.serialize_field("events_watcher", &self.events_watcher)?;
        state.serialize_field("events_destination", &self.events_destination)?;
        state.serialize_field("events_max_file_checksum", &self.events_max_file_checksum)?;
        state.serialize_field("events_max_file_size", &self.events_max_file_size)?;
        state.serialize_field("checksum_algorithm", &checksum_algorithm)?;
        state.serialize_field("endpoint_type", &self.endpoint_type)?;
        state.serialize_field("endpoint_address", &address)?;
        state.serialize_field("endpoint_user", redacted_secret(&self.endpoint_user))?;
        state.serialize_field("endpoint_pass", redacted_secret(&self.endpoint_pass))?;
        state.serialize_field("endpoint_token", redacted_secret(&self.endpoint_token))?;
        state.serialize_field("events_file", &self.events_file)?;
        state.serialize_field("monitor_count", &self.monitor.len())?;
        state.serialize_field("audit_count", &self.audit.len())?;
        state.serialize_field("node", &self.node)?;
        state.serialize_field("log_file", &self.log_file)?;
        state.serialize_field("log_level", &self.log_level)?;
        state.serialize_field("log_max_file_size", &self.log_max_file_size)?;
        state.serialize_field("system", &self.system)?;
        state.serialize_field("insecure", &self.insecure)?;
        state.serialize_field("endpoint_trusted", &self.endpoint_is_trusted())?;
        state.serialize_field("hashscanner_file", &self.hashscanner_file)?;
        state.serialize_field("hashscanner_enabled", &self.hashscanner_enabled)?;
        state.serialize_field("hashscanner_interval", &self.hashscanner_interval)?;
        state.serialize_field("hashscanner_algorithm", &hashscanner_algorithm)?;
        state.serialize_field("engine", &self.engine)?;
        state.end()
    }
}

// ----------------------------------------------------------------------------

// To read the Yaml configuration file
pub fn read_config(path: String) -> Vec<Yaml> {
    let mut file: File = File::open(path.clone())
        .unwrap_or_else(|_| panic!("(read_config): Unable to open file '{}'", path));
    let mut contents: String = String::new();

    file.read_to_string(&mut contents)
        .expect("Unable to read file");
    let yaml = YamlLoader::load_from_str(&contents).unwrap();
    match yaml.get(0) {
        Some(document) => {
            if let Err(error) = evaluate_trust(document) {
                panic!("{}", error);
            }
        },
        None => panic!("(read_config): config file '{}' is empty", path),
    }
    yaml
}

// ----------------------------------------------------------------------------

pub fn get_config_path(system: &str) -> String {
    // Select directory where to load config.yml it depends on system
    let current_dir: String = utils::get_current_dir();
    if system == "windows" {
        let default_path: String = format!("{}\\config\\{}\\config.yml", current_dir, system);
        let relative_path: String = format!("{}\\..\\..\\config\\{}\\config.yml", current_dir, system);
        if Path::new(default_path.as_str()).exists() {
            default_path
        }else if Path::new(&format!("{}\\config.yml", current_dir)).exists() {
            format!("{}\\config.yml", current_dir)
        }else if Path::new(relative_path.as_str()).exists() {
            relative_path
        }else{
            String::from(CONFIG_WINDOWS_PATH)
        }
    }else{
        let default_path: String = format!("{}/config/{}/config.yml", current_dir, system);
        let relative_path: String = format!("{}/../../config/{}/config.yml", current_dir, system);
        if Path::new(default_path.as_str()).exists() {
            default_path
        }else if Path::new(&format!("{}/config.yml", current_dir)).exists() {
            format!("{}/config.yml", current_dir)
        }else if Path::new(relative_path.as_str()).exists() {
            relative_path
        }else if system == "macos" {
            String::from(CONFIG_MACOS_PATH)
        }else{
            String::from(CONFIG_LINUX_PATH)
        } 
    }
}

// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------------

    pub fn create_test_config(filter: &str, events_destination: &str) -> AppConfig {
        AppConfig {
            version: String::from(VERSION),
            path: String::from("test"),
            events_watcher: String::from("Recommended"),
            events_destination: String::from(events_destination),
            events_max_file_checksum: 64,
            events_max_file_size: 128,
            checksum_algorithm: ShaType::Sha512,
            endpoint_type: String::from("Elastic"),
            endpoint_address: String::from("test"),
            endpoint_user: String::from("test"),
            endpoint_pass: String::from("test"),
            endpoint_token: String::from("test"),
            events_file: String::from("test"),
            monitor: Array::new(),
            audit: Array::new(),
            node: String::from("test"),
            log_file: String::from("./test.log"),
            log_level: String::from(filter),
            log_max_file_size: 64,
            system: String::from("test"),
            insecure: true,
            events_lock: Arc::new(Mutex::new(String::from("test"))),
            log_lock: Arc::new(Mutex::new(String::from("test"))),
            hashscanner_file: String::from("test"),
            hashscanner_enabled: true,
            hashscanner_interval: 3600,
            hashscanner_algorithm: ShaType::Sha256,
            engine: String::from("monitor")
        }
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_clone() {
        let cfg = create_test_config("info", "");
        let cloned = cfg.clone();
        assert_eq!(cfg.version, cloned.version);
        assert_eq!(cfg.path, cloned.path);
        assert_eq!(cfg.events_destination, cloned.events_destination);
        assert_eq!(cfg.events_max_file_checksum, cloned.events_max_file_checksum);
        assert_eq!(cfg.events_max_file_size, cloned.events_max_file_size);
        assert_eq!(cfg.endpoint_type, cloned.endpoint_type);
        assert_eq!(cfg.endpoint_address, cloned.endpoint_address);
        assert_eq!(cfg.endpoint_user, cloned.endpoint_user);
        assert_eq!(cfg.endpoint_pass, cloned.endpoint_pass);
        assert_eq!(cfg.endpoint_token, cloned.endpoint_token);
        assert_eq!(cfg.events_file, cloned.events_file);
        assert_eq!(cfg.monitor, cloned.monitor);
        assert_eq!(cfg.audit, cloned.audit);
        assert_eq!(cfg.node, cloned.node);
        assert_eq!(cfg.log_file, cloned.log_file);
        assert_eq!(cfg.log_level, cloned.log_level);
        assert_eq!(cfg.log_max_file_size, cloned.log_max_file_size);
        assert_eq!(cfg.system, cloned.system);
        assert_eq!(cfg.insecure, cloned.insecure);
        assert_eq!(cfg.hashscanner_file, cloned.hashscanner_file);
        assert_eq!(cfg.hashscanner_enabled, cloned.hashscanner_enabled);
        assert_eq!(cfg.hashscanner_interval, cloned.hashscanner_interval);
        assert_eq!(cfg.hashscanner_algorithm, cloned.hashscanner_algorithm);
        assert_eq!(cfg.engine, cloned.engine);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_new_config_windows() {
        let dir = utils::get_current_dir();
        let disk = dir.get(0..1).unwrap();
        let cfg = AppConfig::new("windows", None);

        assert_eq!(cfg.version, String::from(VERSION));
        assert_eq!(cfg.events_destination, String::from("file"));
        assert_eq!(cfg.endpoint_address, String::from("Not_defined"));
        assert_eq!(cfg.endpoint_type, String::from("Not_defined"));
        assert_eq!(cfg.endpoint_user, String::from("Not_defined"));
        assert_eq!(cfg.endpoint_pass, String::from("Not_defined"));
        assert_eq!(cfg.endpoint_token, String::from("Not_defined"));
        assert_eq!(cfg.events_file, format!("{}:\\ProgramData\\fim\\events.json", disk) );
        // monitor
        // audit
        assert_eq!(cfg.node, String::from("FIM"));
        assert_eq!(cfg.log_file, format!("{}:\\ProgramData\\fim\\fim.log", disk) );
        assert_eq!(cfg.log_level, String::from("info"));
        assert_eq!(cfg.log_max_file_size, 64);
        assert_eq!(cfg.system, String::from("windows"));
        assert_eq!(cfg.insecure, false);
        assert_eq!(cfg.hashscanner_file, format!("{}:\\ProgramData\\fim\\fim.db", disk) );
        assert_eq!(cfg.hashscanner_enabled, true);
        assert_eq!(cfg.hashscanner_interval, 3600);
        assert_eq!(cfg.hashscanner_algorithm, ShaType::Sha256);
        assert_eq!(cfg.engine, String::from("monitor"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_new_config_windows_events_destination() {
        let cfg = AppConfig::new("windows", Some("test/unit/config/windows/events_destination_none.yml"));
        assert_eq!(cfg.events_destination, String::from("file"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    #[should_panic]
    fn test_new_config_windows_hashscanner_file() {
        AppConfig::new("windows", Some("test/unit/config/windows/hashscanner_file_none.yml"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    #[should_panic]
    fn test_new_config_windows_events_file() {
        AppConfig::new("windows", Some("test/unit/config/windows/events_file_none.yml"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_new_config_windows_events_destination_network() {
        let cfg = AppConfig::new("windows", Some("test/unit/config/windows/events_destination_network.yml"));
        assert_eq!(cfg.events_file, String::from("Not_defined"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_new_config_windows_events_max_file_checksum() {
        let cfg = AppConfig::new("windows", Some("test/unit/config/windows/events_max_file_checksum.yml"));
        assert_eq!(cfg.events_max_file_checksum, 128);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_new_config_windows_events_max_file_size() {
        let cfg = AppConfig::new("windows", Some("test/unit/config/windows/events_max_file_size.yml"));
        assert_eq!(cfg.events_max_file_size, 256);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_new_config_windows_events_endpoint_insecure() {
        let cfg = AppConfig::new("windows", Some("test/unit/config/windows/events_endpoint_insecure.yml"));
        assert_eq!(cfg.insecure, true);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_new_config_windows_events_endpoint_insecure_none() {
        let cfg = AppConfig::new("windows", Some("test/unit/config/windows/events_endpoint_insecure_none.yml"));
        assert_eq!(cfg.insecure, false);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_new_config_windows_events_destination_network_address() {
        let cfg = AppConfig::new("windows", Some("test/unit/config/windows/events_destination_network_address.yml"));
        assert_eq!(cfg.endpoint_address, "0.0.0.0");
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    #[should_panic]
    fn test_new_config_windows_events_destination_network_address_none() {
        AppConfig::new("windows", Some("test/unit/config/windows/events_destination_network_address_none.yml"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_new_config_windows_events_credentials_user() {
        let cfg = AppConfig::new("windows", Some("test/unit/config/windows/events_credentials_user.yml"));
        assert_eq!(cfg.endpoint_user, "test_user");
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    #[should_panic]
    fn test_new_config_windows_events_credentials_user_none() {
        AppConfig::new("windows", Some("test/unit/config/windows/events_credentials_user_none.yml"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_new_config_windows_events_credentials_password() {
        let cfg = AppConfig::new("windows", Some("test/unit/config/windows/events_credentials_password.yml"));
        assert_eq!(cfg.endpoint_pass, "test_password");
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_new_config_windows_events_credentials_token() {
        let cfg = AppConfig::new("windows", Some("test/unit/config/windows/events_credentials_token.yml"));
        assert_eq!(cfg.endpoint_token, "test_token");
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    #[should_panic]
    fn test_new_config_windows_events_credentials_password_none() {
        AppConfig::new("windows", Some("test/unit/config/windows/events_credentials_password_none.yml"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    #[should_panic]
    fn test_new_config_windows_monitor_none() {
        AppConfig::new("windows", Some("test/unit/config/windows/monitor_none.yml"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_new_config_windows_node_none() {
        let cfg = AppConfig::new("windows", Some("test/unit/config/windows/node_none.yml"));
        assert_eq!(cfg.node, utils::get_hostname());
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    #[should_panic]
    fn test_new_config_windows_log_file_none() {
        AppConfig::new("windows", Some("test/unit/config/windows/log_file_none.yml"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_new_config_windows_log_level_none() {
        let cfg = AppConfig::new("windows", Some("test/unit/config/windows/log_level_none.yml"));
        assert_eq!(cfg.log_level, "info");
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_new_config_windows_log_max_file_size_none() {
        let cfg = AppConfig::new("windows", Some("test/unit/config/windows/log_max_file_size_none.yml"));
        assert_eq!(cfg.log_max_file_size, 64);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_new_config_linux_events_destination() {
        let cfg = AppConfig::new("linux", Some("test/unit/config/linux/events_destination_none.yml"));
        assert_eq!(cfg.events_destination, String::from("file"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    #[should_panic]
    fn test_new_config_linux_hashscanner_file() {
        AppConfig::new("linux", Some("test/unit/config/linux/hashscanner_file_none.yml"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    #[should_panic]
    fn test_new_config_linux_events_file() {
        AppConfig::new("linux", Some("test/unit/config/linux/events_file_none.yml"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_new_config_linux_events_destination_network() {
        let cfg = AppConfig::new("linux", Some("test/unit/config/linux/events_destination_network.yml"));
        assert_eq!(cfg.events_file, String::from("Not_defined"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_new_config_linux_events_max_file_checksum() {
        let cfg = AppConfig::new("linux", Some("test/unit/config/linux/events_max_file_checksum.yml"));
        assert_eq!(cfg.events_max_file_checksum, 128);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_new_config_linux_events_max_file_size() {
        let cfg = AppConfig::new("linux", Some("test/unit/config/linux/events_max_file_size.yml"));
        assert_eq!(cfg.events_max_file_size, 256);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_new_config_linux_events_endpoint_insecure() {
        let cfg = AppConfig::new("linux", Some("test/unit/config/linux/events_endpoint_insecure.yml"));
        assert_eq!(cfg.insecure, true);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_new_config_linux_events_endpoint_insecure_none() {
        let cfg = AppConfig::new("linux", Some("test/unit/config/linux/events_endpoint_insecure_none.yml"));
        assert_eq!(cfg.insecure, false);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_new_config_linux_events_destination_network_address() {
        let cfg = AppConfig::new("linux", Some("test/unit/config/linux/events_destination_network_address.yml"));
        assert_eq!(cfg.endpoint_address, "0.0.0.0");
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    #[should_panic]
    fn test_new_config_linux_events_destination_network_address_none() {
        AppConfig::new("linux", Some("test/unit/config/linux/events_destination_network_address_none.yml"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_new_config_linux_events_credentials_user() {
        let cfg = AppConfig::new("linux", Some("test/unit/config/linux/events_credentials_user.yml"));
        assert_eq!(cfg.endpoint_user, "test_user");
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    #[should_panic]
    fn test_new_config_linux_events_credentials_user_none() {
        AppConfig::new("linux", Some("test/unit/config/linux/events_credentials_user_none.yml"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_new_config_linux_events_credentials_password() {
        let cfg = AppConfig::new("linux", Some("test/unit/config/linux/events_credentials_password.yml"));
        assert_eq!(cfg.endpoint_pass, "test_password");
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_new_config_linux_events_credentials_token() {
        let cfg = AppConfig::new("linux", Some("test/unit/config/linux/events_credentials_token.yml"));
        assert_eq!(cfg.endpoint_token, "test_token");
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    #[should_panic]
    fn test_new_config_linux_events_credentials_password_none() {
        AppConfig::new("linux", Some("test/unit/config/linux/events_credentials_password_none.yml"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_new_config_linux_monitor_none() {
        let cfg = AppConfig::new("linux", Some("test/unit/config/linux/monitor_none.yml"));
        assert_eq!(cfg.monitor, Vec::new());
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_new_config_linux_audit_none() {
        let cfg = AppConfig::new("linux", Some("test/unit/config/linux/audit_none.yml"));
        assert_eq!(cfg.audit, Vec::new());
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    #[should_panic]
    fn test_new_config_linux_audit_and_monitor_none() {
        AppConfig::new("linux", Some("test/unit/config/linux/audit_and_monitor_none.yml"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_new_config_linux_node_none() {
        let cfg = AppConfig::new("linux", Some("test/unit/config/linux/node_none.yml"));
        let machine_id = utils::get_machine_id();
        match machine_id.is_empty(){
            true => assert_eq!(cfg.node, utils::get_hostname()),
            false => assert_eq!(cfg.node, machine_id)
        }
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    #[should_panic]
    fn test_new_config_linux_log_file_none() {
        AppConfig::new("linux", Some("test/unit/config/linux/log_file_none.yml"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_new_config_linux_log_level_none() {
        let cfg = AppConfig::new("linux", Some("test/unit/config/linux/log_level_none.yml"));
        assert_eq!(cfg.log_level, "info");
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_new_config_linux_log_max_file_size_none() {
        let cfg = AppConfig::new("linux", Some("test/unit/config/linux/log_max_file_size_none.yml"));
        assert_eq!(cfg.log_max_file_size, 64);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_new_config_linux() {
        if utils::get_os() == "linux" {
            let cfg = AppConfig::new("linux", None);
            assert_eq!(cfg.version, String::from(VERSION));
            assert_eq!(cfg.events_destination, String::from("file"));
            assert_eq!(cfg.endpoint_type, String::from("Not_defined"));
            assert_eq!(cfg.endpoint_address, String::from("Not_defined"));
            assert_eq!(cfg.endpoint_user, String::from("Not_defined"));
            assert_eq!(cfg.endpoint_pass, String::from("Not_defined"));
            assert_eq!(cfg.endpoint_token, String::from("Not_defined"));
            assert_eq!(cfg.events_file, String::from("/var/lib/fim/events.json"));
            // monitor
            // audit
            assert_eq!(cfg.node, String::from("FIM"));
            assert_eq!(cfg.log_file, String::from("/var/log/fim/fim.log"));
            assert_eq!(cfg.log_level, String::from("info"));
            assert_eq!(cfg.log_max_file_size, 64);
            assert_eq!(cfg.system, String::from("linux"));
            assert_eq!(cfg.insecure, false);
            assert_eq!(cfg.hashscanner_file, String::from("/var/lib/fim/fim.db"));
            assert_eq!(cfg.hashscanner_enabled, true);
            assert_eq!(cfg.hashscanner_interval, 3600);
            assert_eq!(cfg.hashscanner_algorithm, ShaType::Sha256);
            assert_eq!(cfg.engine, String::from("monitor"));
        }
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "macos")]
    #[test]
    fn test_new_config_macos() {
        let cfg = AppConfig::new("macos", None);
        assert_eq!(cfg.version, String::from(VERSION));
        assert_eq!(cfg.events_destination, String::from("file"));
        assert_eq!(cfg.endpoint_type, String::from("Not_defined"));
        assert_eq!(cfg.endpoint_address, String::from("Not_defined"));
        assert_eq!(cfg.endpoint_user, String::from("Not_defined"));
        assert_eq!(cfg.endpoint_pass, String::from("Not_defined"));
        assert_eq!(cfg.endpoint_token, String::from("Not_defined"));
        assert_eq!(cfg.events_file, String::from("/var/lib/fim/events.json"));
        // monitor
        // audit
        assert_eq!(cfg.node, String::from("FIM"));
        assert_eq!(cfg.log_file, String::from("/var/log/fim/fim.log"));
        assert_eq!(cfg.log_level, String::from("info"));
        assert_eq!(cfg.log_max_file_size, 64);
        assert_eq!(cfg.system, String::from("macos"));
        assert_eq!(cfg.insecure, false);
        assert_eq!(cfg.hashscanner_file, String::from("/var/lib/fim/fim.db"));
        assert_eq!(cfg.hashscanner_enabled, true);
        assert_eq!(cfg.hashscanner_interval, 3600);
        assert_eq!(cfg.hashscanner_algorithm, ShaType::Sha256);
        assert_eq!(cfg.engine, String::from("monitor"));
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_level_filter_info() {
        let filter = LevelFilter::Info;
        assert_eq!(create_test_config("info", "").get_level_filter(), filter);
        assert_eq!(create_test_config("Info", "").get_level_filter(), filter);
        assert_eq!(create_test_config("INFO", "").get_level_filter(), filter);
        assert_eq!(create_test_config("I", "").get_level_filter(), filter);
        assert_eq!(create_test_config("i", "").get_level_filter(), filter);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_level_filter_debug() {
        let filter = LevelFilter::Debug;
        assert_eq!(create_test_config("debug", "").get_level_filter(), filter);
        assert_eq!(create_test_config("Debug", "").get_level_filter(), filter);
        assert_eq!(create_test_config("DEBUG", "").get_level_filter(), filter);
        assert_eq!(create_test_config("D", "").get_level_filter(), filter);
        assert_eq!(create_test_config("d", "").get_level_filter(), filter);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_level_filter_error() {
        let filter = LevelFilter::Error;
        assert_eq!(create_test_config("error", "").get_level_filter(), filter);
        assert_eq!(create_test_config("Error", "").get_level_filter(), filter);
        assert_eq!(create_test_config("ERROR", "").get_level_filter(), filter);
        assert_eq!(create_test_config("E", "").get_level_filter(), filter);
        assert_eq!(create_test_config("e", "").get_level_filter(), filter);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_level_filter_warning() {
        let filter = LevelFilter::Warn;
        assert_eq!(create_test_config("warning", "").get_level_filter(), filter);
        assert_eq!(create_test_config("Warning", "").get_level_filter(), filter);
        assert_eq!(create_test_config("WARNING", "").get_level_filter(), filter);
        assert_eq!(create_test_config("W", "").get_level_filter(), filter);
        assert_eq!(create_test_config("w", "").get_level_filter(), filter);
        assert_eq!(create_test_config("warn", "").get_level_filter(), filter);
        assert_eq!(create_test_config("Warn", "").get_level_filter(), filter);
        assert_eq!(create_test_config("WARN", "").get_level_filter(), filter);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_level_filter_bad() {
        let filter = LevelFilter::Info;
        assert_eq!(create_test_config("bad", "").get_level_filter(), filter);
        assert_eq!(create_test_config("BAD", "").get_level_filter(), filter);
        assert_eq!(create_test_config("B", "").get_level_filter(), filter);
        assert_eq!(create_test_config("b", "").get_level_filter(), filter);
        assert_eq!(create_test_config("test", "").get_level_filter(), filter);
        assert_eq!(create_test_config("", "").get_level_filter(), filter);
        assert_eq!(create_test_config("_", "").get_level_filter(), filter);
        assert_eq!(create_test_config("?", "").get_level_filter(), filter);
        assert_eq!(create_test_config("=", "").get_level_filter(), filter);
        assert_eq!(create_test_config("/", "").get_level_filter(), filter);
        assert_eq!(create_test_config(".", "").get_level_filter(), filter);
        assert_eq!(create_test_config(":", "").get_level_filter(), filter);
        assert_eq!(create_test_config(";", "").get_level_filter(), filter);
        assert_eq!(create_test_config("!", "").get_level_filter(), filter);
        assert_eq!(create_test_config("''", "").get_level_filter(), filter);
        assert_eq!(create_test_config("[]", "").get_level_filter(), filter);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_events_destination() {
        assert_eq!(create_test_config("info", "both").get_events_destination(), String::from(BOTH_MODE));
        assert_eq!(create_test_config("info", "network").get_events_destination(), String::from(NETWORK_MODE));
        assert_eq!(create_test_config("info", "file").get_events_destination(), String::from(FILE_MODE));
        assert_eq!(create_test_config("info", "").get_events_destination(), String::from(FILE_MODE));
        assert_eq!(create_test_config("info", "?").get_events_destination(), String::from(FILE_MODE));
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_read_config_unix() {
        let yaml = read_config(String::from("config/linux/config.yml"));

        assert_eq!(yaml[0]["node"].as_str().unwrap(), "FIM");
        assert_eq!(yaml[0]["events"]["destination"].as_str().unwrap(), "file");
        assert_eq!(yaml[0]["events"]["file"].as_str().unwrap(), "/var/lib/fim/events.json");

        assert_eq!(yaml[0]["monitor"][0]["path"].as_str().unwrap(), "/bin/");
        assert_eq!(yaml[0]["monitor"][1]["path"].as_str().unwrap(), "/usr/bin/");
        assert_eq!(yaml[0]["monitor"][1]["labels"][0].as_str().unwrap(), "usr/bin");
        assert_eq!(yaml[0]["monitor"][1]["labels"][1].as_str().unwrap(), "linux");
        assert_eq!(yaml[0]["monitor"][2]["path"].as_str().unwrap(), "/etc");
        assert_eq!(yaml[0]["monitor"][2]["labels"][0].as_str().unwrap(), "etc");
        assert_eq!(yaml[0]["monitor"][2]["labels"][1].as_str().unwrap(), "linux");

        assert_eq!(yaml[0]["log"]["file"].as_str().unwrap(), "/var/log/fim/fim.log");
        assert_eq!(yaml[0]["log"]["level"].as_str().unwrap(), "info");
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_read_config_windows() {
        let dir = utils::get_current_dir();
        let disk = dir.get(0..1).unwrap();
        let yaml = read_config(String::from("config/windows/config.yml"));

        assert_eq!(yaml[0]["node"].as_str().unwrap(), "FIM");
        assert_eq!(yaml[0]["events"]["destination"].as_str().unwrap(), "file");
        assert_eq!(yaml[0]["events"]["file"].as_str().unwrap(), format!("{}:\\ProgramData\\fim\\events.json", disk) );

        assert_eq!(yaml[0]["monitor"][0]["path"].as_str().unwrap(), "C:\\Program Files\\");
        assert_eq!(yaml[0]["monitor"][0]["labels"][0].as_str().unwrap(), "Program Files");
        assert_eq!(yaml[0]["monitor"][0]["labels"][1].as_str().unwrap(), "windows");
        assert_eq!(yaml[0]["monitor"][1]["path"].as_str().unwrap(), "C:\\Users\\" );
        assert_eq!(yaml[0]["monitor"][1]["labels"][0].as_str().unwrap(), "Users");
        assert_eq!(yaml[0]["monitor"][1]["labels"][1].as_str().unwrap(), "windows");

        assert_eq!(yaml[0]["log"]["file"].as_str().unwrap(), format!("{}:\\ProgramData\\fim\\fim.log", disk) );
        assert_eq!(yaml[0]["log"]["level"].as_str().unwrap(), "info");
    }

    // ------------------------------------------------------------------------

    #[test]
    #[should_panic(expected = "NotFound")]
    fn test_read_config_panic() {
        read_config(String::from("NotFound"));
    }

    // ------------------------------------------------------------------------

    #[test]
    #[should_panic(expected = "ScanError")]
    fn test_read_config_panic_not_config() {
        read_config(String::from("README.md"));
    }

    // ------------------------------------------------------------------------

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_get_config_path_unix() {
        let current_dir = utils::get_current_dir();
        let default_path_linux = format!("{}/config/linux/config.yml", current_dir);
        let default_path_macos = format!("{}/config/macos/config.yml", current_dir);
        assert_eq!(get_config_path("linux"), default_path_linux);
        assert_eq!(get_config_path("macos"), default_path_macos);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_get_config_path_windows() {
        let current_dir = utils::get_current_dir();
        let default_path_windows = format!("{}\\config\\windows\\config.yml", current_dir);
        assert_eq!(get_config_path("windows"), default_path_windows);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_path_in_monitor() {
        let cfg = AppConfig::new(&utils::get_os(), None);
        assert!(cfg.path_in("/bin/", "", cfg.monitor.clone()));
        assert!(cfg.path_in("/bin", "", cfg.monitor.clone()));
        assert!(cfg.path_in("/bin/test", "", cfg.monitor.clone()));
        assert!(!cfg.path_in("/test", "", cfg.monitor.clone()));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_path_in_audit() {
        let cfg = AppConfig::new(&utils::get_os(), Some("test/unit/config/linux/audit_allowed.yml"));
        assert!(cfg.path_in("/tmp", "", cfg.audit.clone()));
        assert!(cfg.path_in("/tmp/", "", cfg.audit.clone()));
        assert!(cfg.path_in("./", "/tmp", cfg.audit.clone()));
        assert!(cfg.path_in("./", "/tmp/", cfg.audit.clone()));
        assert!(!cfg.path_in("./", "/test", cfg.audit.clone()));
        assert!(cfg.path_in("./", "/tmp/test", cfg.audit.clone()));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_get_index_monitor() {
        let cfg = AppConfig::new(&utils::get_os(), None);
        assert_eq!(cfg.get_index("/bin/", "", cfg.monitor.clone()), 0);
        assert_eq!(cfg.get_index("./", "/bin", cfg.monitor.clone()), 0);
        assert_eq!(cfg.get_index("/usr/bin/", "", cfg.monitor.clone()), 1);
        assert_eq!(cfg.get_index("/etc", "", cfg.monitor.clone()), 2);
        assert_eq!(cfg.get_index("/test", "", cfg.monitor.clone()), usize::MAX);
        assert_eq!(cfg.get_index("./", "/test", cfg.monitor.clone()), usize::MAX);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_get_index_audit() {
        let cfg = AppConfig::new(&utils::get_os(), Some("test/unit/config/linux/audit_allowed.yml"));
        assert_eq!(cfg.get_index("/tmp", "", cfg.audit.clone()), 0);
        assert_eq!(cfg.get_index("/test", "", cfg.audit.clone()), usize::MAX);
        assert_eq!(cfg.get_index("./", "/tmp", cfg.audit.clone()), 0);
        assert_eq!(cfg.get_index("./", "/test", cfg.audit.clone()), usize::MAX);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_labels() {
        let cfg = AppConfig::new(&utils::get_os(), None);
        if utils::get_os() == "windows" {
            let labels = cfg.get_labels(0, cfg.monitor.clone());
            assert_eq!(labels[0], "Program Files");
            assert_eq!(labels[1], "windows");
        }else if utils::get_os() == "macos"{
            let labels = cfg.get_labels(2, cfg.monitor.clone());
            assert_eq!(labels[0], "usr/bin");
            assert_eq!(labels[1], "macos");
        }else{
            let labels = cfg.get_labels(1, cfg.monitor.clone());
            assert_eq!(labels[0], "usr/bin");
            assert_eq!(labels[1], "linux");
        }
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_match_ignore_monitor() {
        let cfg = AppConfig::new(&utils::get_os(), None);
        assert!(cfg.match_ignore(3, "file.swp", cfg.monitor.clone()));
        assert!(!cfg.match_ignore(0, "file.txt", cfg.monitor.clone()));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_match_ignore_audit() {
        let cfg = AppConfig::new(&utils::get_os(), Some("test/unit/config/linux/audit_exclude.yml"));
        assert!(cfg.match_ignore(0, "file.swp", cfg.audit.clone()));
        assert!(!cfg.match_ignore(0, "file.txt", cfg.audit.clone()));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_match_exclude() {
        let cfg = AppConfig::new(&utils::get_os(), Some("test/unit/config/linux/audit_exclude.yml"));
        assert!(cfg.match_exclude(0, "/tmp/test", cfg.audit.clone()));
        assert!(!cfg.match_exclude(0, "/tmp/another", cfg.audit.clone()));
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_match_allowed() {
        if utils::get_os() == "windows" {
            let cfg = AppConfig::new(&utils::get_os(), Some("test/unit/config/windows/monitor_allowed.yml"));
            assert!(!cfg.match_allowed(1, "file.swp", cfg.monitor.clone()));
            assert!(cfg.match_allowed(1, "file.txt", cfg.monitor.clone()));
        } else if utils::get_os() == "linux" {
            let cfg = AppConfig::new(&utils::get_os(), Some("test/unit/config/linux/monitor_allowed.yml"));
            assert!(!cfg.match_allowed(2, "file.swp", cfg.monitor.clone()));
            assert!(cfg.match_allowed(2, "file.txt", cfg.monitor.clone()));

            let cfg_audit = AppConfig::new(&utils::get_os(), Some("test/unit/config/linux/audit_allowed.yml"));
            assert!(!cfg_audit.match_allowed(0, "file.swp", cfg_audit.audit.clone()));
            assert!(cfg_audit.match_allowed(0, "file.txt", cfg_audit.audit.clone()));
        }
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_integrations() {
        let os = utils::get_os();
        let cfg = AppConfig::new(&os,
            Some(format!("test/unit/config/{}/monitor_integration.yml", os)
                .as_str())
        );
        if os == "windows" {
            let integrations = cfg.get_integrations(2, cfg.monitor.clone());
            assert_eq!(integrations.len(), 1);
        }else if os == "macos"{
            let integrations = cfg.get_integrations(2, cfg.monitor.clone());
            assert_eq!(integrations.len(), 1);
        }else{
            let integrations_monitor = cfg.get_integrations(2, cfg.monitor.clone());
            assert_eq!(integrations_monitor.len(), 1);

            // Not implemented yet
            //let integrations_audit = cfg.get_integrations(2, cfg.audit.clone());
            //assert_eq!(integrations_audit.len(), 1);
        }
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_new_config_watcher() {
        let cfg = AppConfig::new("windows", Some("test/unit/config/windows/events_watcher.yml"));
        assert_eq!(cfg.events_watcher, "Poll");
    }

    // ------------------------------------------------------------------------

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_config_trust_rejects_missing_network_credentials() {
        let result = std::panic::catch_unwind(|| {
            AppConfig::new("linux", Some("test/unit/config/linux/trust_missing_credentials.yml"))
        });
        let panic = result.unwrap_err();
        let message = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .unwrap_or("");
        assert!(message.contains("events.endpoint.credentials"));
        assert!(message.contains("stage=admission"));
        assert!(message.contains("target=network"));
    }

    // ------------------------------------------------------------------------

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_config_trust_rejects_mixed_credentials() {
        let result = std::panic::catch_unwind(|| {
            AppConfig::new("linux", Some("test/unit/config/linux/trust_mixed_credentials.yml"))
        });
        let panic = result.unwrap_err();
        let message = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .unwrap_or("");
        assert!(message.contains("events.endpoint.credentials"));
        assert!(message.contains("mutually exclusive"));
        assert!(!message.contains("super-secret"));
    }

    // ------------------------------------------------------------------------

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_config_trust_rejects_default_cleartext_target() {
        let result = std::panic::catch_unwind(|| {
            AppConfig::new("linux", Some("test/unit/config/linux/trust_cleartext.yml"))
        });
        let panic = result.unwrap_err();
        let message = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .unwrap_or("");
        assert!(message.contains("events.endpoint.address"));
        assert!(message.contains("cleartext HTTP"));
    }

    // ------------------------------------------------------------------------

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_config_trust_accepts_explicit_dev_target() {
        let cfg = AppConfig::new(
            "linux",
            Some("test/unit/config/linux/trust_cleartext_dev.yml"),
        );
        assert!(cfg.can_use_network());
        assert_eq!(
            cfg.endpoint_base_url().unwrap(),
            String::from("http://127.0.0.1:9200")
        );
    }

    // ------------------------------------------------------------------------

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_config_trust_diagnostics_are_redacted() {
        let cfg = AppConfig::new(
            "linux",
            Some("test/unit/config/linux/trust_valid_elastic.yml"),
        );
        assert!(cfg.can_use_network());

        let debug = format!("{:?}", cfg);
        assert!(!debug.contains("super-secret-password"));
        assert!(debug.contains(REDACTED));

        let json = serde_json::to_string(&cfg).unwrap();
        assert!(!json.contains("super-secret-password"));
        assert!(json.contains(REDACTED));
    }

    // ------------------------------------------------------------------------

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_config_trust_restart_after_rejection_uses_complete_config() {
        let rejected = std::panic::catch_unwind(|| {
            AppConfig::new("linux", Some("test/unit/config/linux/trust_missing_credentials.yml"))
        });
        assert!(rejected.is_err());

        let corrected = AppConfig::new(
            "linux",
            Some("test/unit/config/linux/trust_valid_splunk.yml"),
        );
        assert_eq!(corrected.events_destination, String::from("network"));
        assert_eq!(corrected.endpoint_type, String::from("Splunk"));
        assert!(corrected.can_use_network());
    }

    // ------------------------------------------------------------------------

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_config_trust_normalizes_target_presentation() {
        let cfg = AppConfig::new(
            "linux",
            Some("test/unit/config/linux/trust_valid_elastic.yml"),
        );
        assert_eq!(
            cfg.endpoint_base_url().unwrap(),
            String::from("https://fim.example.test")
        );

        let splunk = AppConfig::new(
            "linux",
            Some("test/unit/config/linux/trust_valid_splunk.yml"),
        );
        assert_eq!(splunk.events_destination, String::from("network"));
        assert_eq!(
            splunk.endpoint_base_url().unwrap(),
            String::from("https://fim.example.test")
        );
    }

    // ------------------------------------------------------------------------

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_config_trust_rejects_insecure_remote_target() {
        let result = std::panic::catch_unwind(|| {
            AppConfig::new("linux", Some("test/unit/config/linux/trust_insecure_remote.yml"))
        });
        let panic = result.unwrap_err();
        let message = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .unwrap_or("");
        assert!(message.contains("events.endpoint.insecure"));
        assert!(message.contains("explicit development mode"));
    }

    // ------------------------------------------------------------------------

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_config_trust_allows_remote_insecure_in_explicit_development() {
        let cfg = AppConfig::new(
            "linux",
            Some("test/unit/config/linux/trust_insecure_remote_dev.yml"),
        );
        assert!(cfg.can_use_network());
        assert!(cfg.insecure);
    }

}
