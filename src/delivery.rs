// Copyright (C) 2024, Achiefs.

// Persistent delivery queue (batch) management.
// Keeps event identity, pending delivery state, acknowledgements and retries
// tied to the same batch, so events are not lost on network failures or
// restarts and replays are not seen as new events by the receiver.

use crate::appconfig::*;

use log::*;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

// Interval between delivery retries of pending batches
pub const RETRY_INTERVAL_SECS: u64 = 10;

// ----------------------------------------------------------------------------

// One pending delivery record. Every retry of the same event keeps the same
// batch number, event id and payload, so the receiver can detect replays.
#[derive(Clone, Serialize, Deserialize)]
pub struct PendingBatch {
    pub batch: u64,
    pub id: String,
    pub attempts: u32,
    pub splunk: bool,
    pub url: String,
    pub body: Value,
}

// ----------------------------------------------------------------------------

// Lock to serialize spool file access between the monitor loop and the
// retry task.
fn spool_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

// ----------------------------------------------------------------------------

fn with_lock<F, T>(f: F) -> T where F: FnOnce() -> T {
    let _guard = spool_lock().lock().unwrap();
    f()
}

// ----------------------------------------------------------------------------

// Path of the file that stores the pending delivery batches
pub fn spool_path(cfg: &AppConfig) -> String {
    format!("{}.pending", cfg.events_file)
}

// ----------------------------------------------------------------------------

// Path of the file that stores the last used batch number
pub fn state_path(cfg: &AppConfig) -> String {
    format!("{}.pending.state", cfg.events_file)
}

// ----------------------------------------------------------------------------

// Get the next batch number, the counter is persisted on disk so it is not
// reset to zero on restart.
fn next_batch(state_path: &str) -> u64 {
    let current = fs::read_to_string(state_path)
        .ok()
        .and_then(|content| content.trim().parse::<u64>().ok())
        .unwrap_or(0);
    let next = current + 1;
    if let Some(parent) = Path::new(state_path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    match fs::write(state_path, next.to_string()) {
        Ok(_) => debug!("Batch counter updated to {}", next),
        Err(e) => error!("Could not persist batch counter, error: {}", e)
    }
    next
}

// ----------------------------------------------------------------------------

// Load pending delivery batches from disk
pub fn load_pending(spool_path: &str) -> Vec<PendingBatch> {
    match fs::read_to_string(spool_path) {
        Ok(content) => content.lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| match serde_json::from_str::<PendingBatch>(line) {
                Ok(batch) => Some(batch),
                Err(e) => {
                    warn!("Discarding corrupted pending batch line, error: {}", e);
                    None
                }
            })
            .collect(),
        Err(_) => Vec::new()
    }
}

// ----------------------------------------------------------------------------

// Save pending delivery batches to disk (atomic write through a tmp file)
fn save_pending(spool_path: &str, pending: &[PendingBatch]) {
    if let Some(parent) = Path::new(spool_path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    let tmp_path = format!("{}.tmp", spool_path);
    let lines: Vec<String> = pending.iter()
        .map(|batch| serde_json::to_string(batch).unwrap())
        .collect();
    let data = match lines.is_empty() {
        true => String::new(),
        false => format!("{}\n", lines.join("\n"))
    };
    match fs::write(&tmp_path, data) {
        Ok(_) => {
            if let Err(e) = fs::rename(&tmp_path, spool_path) {
                error!("Could not update pending batches file, error: {}", e);
            }
        },
        Err(e) => error!("Could not write pending batches file, error: {}", e)
    }
}

// ----------------------------------------------------------------------------

// Enqueue an event that could not be delivered. If the event is already
// pending it is not duplicated, the same batch is kept.
fn enqueue_at(spool_path: &str, state_path: &str, id: &str, splunk: bool,
    url: String, body: Value) -> u64 {
    let mut pending = load_pending(spool_path);
    match pending.iter().find(|batch| batch.id == id) {
        Some(existing) => {
            debug!("Event '{}' already pending in batch {}, not duplicated",
                id, existing.batch);
            existing.batch
        },
        None => {
            let batch = next_batch(state_path);
            pending.push(PendingBatch {
                batch,
                id: id.to_string(),
                attempts: 0,
                splunk,
                url,
                body,
            });
            save_pending(spool_path, &pending);
            batch
        }
    }
}

// ----------------------------------------------------------------------------

// Public wrapper of enqueue_at using the paths derived from the configuration
pub fn enqueue(cfg: &AppConfig, id: &str, url: String, body: Value) -> u64 {
    let spool = spool_path(cfg);
    let state = state_path(cfg);
    let splunk = cfg.endpoint_type == "Splunk";
    with_lock(|| enqueue_at(&spool, &state, id, splunk, url, body))
}

// ----------------------------------------------------------------------------

// Perform a single delivery attempt, returns true only when the endpoint
// acknowledges the event with a success (2xx) status.
async fn post(cfg: &AppConfig, splunk: bool, url: &str, body: &Value) -> bool {
    let client = Client::builder()
        .danger_accept_invalid_certs(cfg.insecure)
        .timeout(Duration::from_secs(30))
        .build().unwrap();
    let request = match splunk {
        true => client.post(url)
            .header("Authorization", format!("Splunk {}", cfg.endpoint_token)),
        false => client.post(url)
            .basic_auth(cfg.endpoint_user.clone(), Some(cfg.endpoint_pass.clone()))
    };
    match request.json(body).send().await {
        Ok(response) => {
            let status = response.status();
            debug!("Response received: {:?}", response.text().await.unwrap());
            if status.is_success() {
                true
            } else {
                warn!("Endpoint did not acknowledge delivery, status: {}", status);
                false
            }
        },
        Err(e) => {
            debug!("Error on request: {:?}", e);
            false
        }
    }
}

// ----------------------------------------------------------------------------

// Deliver an event to the configured endpoint. On success nothing else is
// done (single success path). On failure the event is kept in a persistent
// batch with its identity to be retried later, it is never dropped.
pub async fn deliver(cfg: &AppConfig, id: &str, url: String, body: Value) -> bool {
    let splunk = cfg.endpoint_type == "Splunk";
    if post(cfg, splunk, &url, &body).await {
        true
    } else {
        let batch = enqueue(cfg, id, url, body);
        warn!("Event '{}' could not be delivered, kept in batch {} for retry",
            id, batch);
        false
    }
}

// ----------------------------------------------------------------------------

// Remove acknowledged events from the spool and update retry counters of the
// events still pending. The spool is reloaded under the lock so events
// enqueued while retrying are not lost.
fn apply_results(spool_path: &str, acked: &[String], attempts: &HashMap<String, u32>) {
    with_lock(|| {
        let current = load_pending(spool_path);
        let remaining: Vec<PendingBatch> = current.into_iter()
            .filter(|batch| !acked.iter().any(|id| id == &batch.id))
            .map(|mut batch| {
                if let Some(value) = attempts.get(&batch.id) {
                    batch.attempts = *value;
                }
                batch
            })
            .collect();
        save_pending(spool_path, &remaining);
    });
}

// ----------------------------------------------------------------------------

// Retry delivery of all pending batches. Each event is resent with the same
// identity (id, url and payload) it had on the first attempt, so the receiver
// does not account replays as new events.
pub async fn retry_pending(cfg: &AppConfig) {
    let spool = spool_path(cfg);
    let pending = with_lock(|| load_pending(&spool));
    if pending.is_empty() {
        return;
    }
    info!("Retrying delivery of {} pending event(s)", pending.len());

    let mut acked: Vec<String> = Vec::new();
    let mut attempts: HashMap<String, u32> = HashMap::new();
    for batch in pending {
        if post(cfg, batch.splunk, &batch.url, &batch.body).await {
            debug!("Event '{}' of batch {} acknowledged by endpoint",
                batch.id, batch.batch);
            acked.push(batch.id);
        } else {
            attempts.insert(batch.id, batch.attempts + 1);
        }
    }
    apply_results(&spool, &acked, &attempts);
    info!("Delivery retry done, {} event(s) acknowledged, {} still pending",
        acked.len(), attempts.len());
}

// ----------------------------------------------------------------------------

// Spawn the background task that retries pending deliveries periodically.
// Pending batches are loaded from disk, so they survive restarts.
pub fn spawn_retry_loop(cfg: AppConfig) {
    tokio::spawn(async move {
        retry_pending(&cfg).await;
        loop {
            tokio::time::sleep(Duration::from_secs(RETRY_INTERVAL_SECS)).await;
            retry_pending(&cfg).await;
        }
    });
}

// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ------------------------------------------------------------------------

    fn test_paths(tag: &str) -> (String, String) {
        let dir = std::env::temp_dir();
        (format!("{}/fim_delivery_test_{}.pending", dir.display(), tag),
         format!("{}/fim_delivery_test_{}.pending.state", dir.display(), tag))
    }

    // ------------------------------------------------------------------------

    fn cleanup(spool: &str, state: &str) {
        let _ = fs::remove_file(spool);
        let _ = fs::remove_file(state);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_enqueue_and_load_keeps_identity() {
        let (spool, state) = test_paths("identity");
        cleanup(&spool, &state);

        let first = enqueue_at(&spool, &state, "id-1", false,
            "http://endpoint/fim/_doc/id-1".to_string(), json!({"file": "/tmp/a"}));
        let second = enqueue_at(&spool, &state, "id-2", false,
            "http://endpoint/fim/_doc/id-2".to_string(), json!({"file": "/tmp/b"}));

        assert_eq!(first, 1);
        assert_eq!(second, 2);

        let pending = load_pending(&spool);
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].id, "id-1");
        assert_eq!(pending[0].batch, 1);
        assert_eq!(pending[0].attempts, 0);
        assert_eq!(pending[0].url, "http://endpoint/fim/_doc/id-1");
        assert_eq!(pending[0].body, json!({"file": "/tmp/a"}));
        assert_eq!(pending[1].id, "id-2");
        assert_eq!(pending[1].batch, 2);
        cleanup(&spool, &state);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_enqueue_dedupes_same_event() {
        let (spool, state) = test_paths("dedupe");
        cleanup(&spool, &state);

        let first = enqueue_at(&spool, &state, "id-1", false,
            "http://endpoint/fim/_doc/id-1".to_string(), json!({"file": "/tmp/a"}));
        let second = enqueue_at(&spool, &state, "id-1", false,
            "http://endpoint/fim/_doc/id-1".to_string(), json!({"file": "/tmp/a"}));

        assert_eq!(first, second);
        assert_eq!(load_pending(&spool).len(), 1);
        cleanup(&spool, &state);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_batch_counter_survives_restart() {
        let (spool, state) = test_paths("restart");
        cleanup(&spool, &state);

        let first = enqueue_at(&spool, &state, "id-1", false,
            "http://endpoint/fim/_doc/id-1".to_string(), json!({}));
        // Simulate a restart, the spool and state files are read again from
        // disk and the batch number continues instead of starting from zero.
        let second = enqueue_at(&spool, &state, "id-2", false,
            "http://endpoint/fim/_doc/id-2".to_string(), json!({}));

        assert_eq!(first, 1);
        assert_eq!(second, 2);
        assert_eq!(load_pending(&spool).len(), 2);
        cleanup(&spool, &state);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_apply_results_removes_acked_and_counts_attempts() {
        let (spool, state) = test_paths("results");
        cleanup(&spool, &state);

        enqueue_at(&spool, &state, "id-1", false,
            "http://endpoint/fim/_doc/id-1".to_string(), json!({}));
        enqueue_at(&spool, &state, "id-2", false,
            "http://endpoint/fim/_doc/id-2".to_string(), json!({}));

        let acked = vec![String::from("id-1")];
        let mut attempts = HashMap::new();
        attempts.insert(String::from("id-2"), 1);
        apply_results(&spool, &acked, &attempts);

        let pending = load_pending(&spool);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, "id-2");
        assert_eq!(pending[0].batch, 2);
        assert_eq!(pending[0].attempts, 1);
        cleanup(&spool, &state);
    }
}
