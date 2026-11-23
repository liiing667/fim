// Copyright (C) 2024, Achiefs.

// Global constants definitions
pub const REMOVE: &str = "REMOVE";
pub const CREATE: &str = "CREATE";
pub const WRITE: &str = "WRITE";

use crate::appconfig;
use crate::appconfig::*;
use crate::dbfile::*;

use log::*;
use std::fs::OpenOptions;
use serde_json::{json, to_string};
use std::io::Write;
use reqwest::Client;
use std::time::Duration;

pub struct HashEvent {
    previous_dbfile: Option<DBFile>,
    dbfile: DBFile,
    operation: String,
}

#[cfg(test)]
mod test;

impl HashEvent {
    pub fn new(previous_dbfile: Option<DBFile>, dbfile: DBFile, operation: String) -> Self {
        HashEvent {
            previous_dbfile,
            dbfile,
            operation,
        }
    }

    // ------------------------------------------------------------------------

    fn log(&self, cfg: AppConfig) {
        let file = cfg.events_lock.lock().unwrap();
        let mut events_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(file.as_str())
            .expect("(hashevent::log) Unable to open events log file.");

            match writeln!(events_file, "{}", self.format_json()) {
                Ok(_d) => debug!("Hash event log written"),
                Err(e) => error!("Hash event could not be written, Err: [{}]", e)
            };
    }

    // ------------------------------------------------------------------------

    // The target endpoint, its credentials and the batch identity are pinned
    // by the caller before this point, so the event cannot leak into another
    // receiver configured in the same process.
    async fn send(&self, endpoint: Endpoint, batch: String, node: String) {
        let event = self.get_json();
        debug!("Sending event '{}' to endpoint '{}' as {}, batch '{}'",
            self.dbfile.id, endpoint.address, endpoint.principal(), batch);

        // Splunk endpoint integration
        if endpoint.etype == "Splunk" {
            let data = json!({
                "source": node,
                "sourcetype": "_json",
                "event": event,
                "index": "fim_events"
            });
            debug!("Sending received event to Splunk integration, event: {}", data);
            let request_url = format!("{}/services/collector/event", endpoint.address);
            let client = Client::builder()
                .danger_accept_invalid_certs(endpoint.insecure)
                .timeout(Duration::from_secs(30))
                .build().unwrap();
            match client
                .post(request_url)
                .header("Authorization", format!("Splunk {}", endpoint.token))
                .json(&data)
                .send()
                .await {
                    Ok(response) => debug!("Response received: {:?}",
                        response.text().await.unwrap()),
                    Err(e) => error!("Event '{}' could not be sent to endpoint '{}' (batch '{}'), Err: {:?}",
                        self.dbfile.id, endpoint.address, batch, e)
            }
        // Elastic endpoint integration
        } else {
            let request_url = format!("{}/{}/_doc/{}", endpoint.address, batch, self.dbfile.id);
            let client = Client::builder()
                .danger_accept_invalid_certs(endpoint.insecure)
                .timeout(Duration::from_secs(30))
                .build().unwrap();
            match client
                .post(request_url)
                .basic_auth(endpoint.user, Some(endpoint.pass))
                .json(&event)
                .send()
                .await {
                    Ok(response) => debug!("Response received: {:?}",
                        response.text().await.unwrap()),
                    Err(e) => error!("Event '{}' could not be sent to endpoint '{}' (batch '{}'), Err: {:?}",
                        self.dbfile.id, endpoint.address, batch, e)
            }
        }
    }

    // ------------------------------------------------------------------------

    pub async fn process(&self, cfg: AppConfig) {
        // Pin the target endpoint, its credentials and the batch identity
        // before sending, so the event keeps its original destination on
        // retries and cannot be rerouted to another receiver.
        let endpoint = cfg.get_endpoint();
        let batch = appconfig::events_batch();
        let node = cfg.node.clone();
        match cfg.get_events_destination().as_str() {
            appconfig::BOTH_MODE => {
                self.log(cfg.clone());
                self.send(endpoint, batch, node).await;
            },
            appconfig::NETWORK_MODE => {
                self.send(endpoint, batch, node).await;
            },
            _ => self.log(cfg.clone())
        }
    }

    // ------------------------------------------------------------------------

    fn format_json(&self) -> String { to_string(&self.get_json()).unwrap() }

    // ------------------------------------------------------------------------

    fn get_json(&self) -> serde_json::Value {
        match &self.previous_dbfile {
            Some(data) => {
                json!({
                    "previous_dbfile.id": data.id.clone(),
                    "previous_dbfile.timestamp": data.timestamp.clone(),
                    "previous_dbfile.hash": data.hash.clone(),
                    "previous_dbfile.path": data.path.clone(),
                    "previous_dbfile.size": data.size.clone(),
                    "previous_dbfile.permissions": data.permissions.clone(),
                    "dbfile.id": self.dbfile.id.clone(),
                    "dbfile.timestamp": self.dbfile.timestamp.clone(),
                    "dbfile.hash": self.dbfile.hash.clone(),
                    "dbfile.path": self.dbfile.path.clone(),
                    "dbfile.size": self.dbfile.size.clone(),
                    "dbfile.permissions": self.dbfile.permissions.clone(),
                    "operation": self.operation.clone(),
                })
            },
            None => json!({
                "dbfile.id": self.dbfile.id.clone(),
                "dbfile.timestamp": self.dbfile.timestamp.clone(),
                "dbfile.hash": self.dbfile.hash.clone(),
                "dbfile.path": self.dbfile.path.clone(),
                "dbfile.size": self.dbfile.size.clone(),
                "dbfile.permissions": self.dbfile.permissions.clone(),
                "operation": self.operation.clone(),
            })
        }

    }
}
