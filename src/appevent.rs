// Copyright (C) 2024, Achiefs.

use crate::appconfig;
use crate::appconfig::*;
use crate::ruleset::*;

use log::*;
use serde::Serialize;
use serde_json::json;
use reqwest::Client;
use std::fs::OpenOptions;
use std::time::Duration;
use std::io::Write;

#[derive(Clone, Serialize, Debug)]
pub struct AppEvent {
  pub id: String,
  pub timestamp: String,
  pub hostname: String,
  pub node: String,
  pub version: String,
  pub message: String,
  pub fpid: u32,
  pub system: String
}



impl AppEvent {

  fn to_json(&self) -> String { serde_json::to_string(self).unwrap() }

  // ------------------------------------------------------------------------

  // Function to write the received events to file
  fn log(&self, cfg: AppConfig) {
    let file = cfg.events_lock.lock().unwrap();
    let mut events_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(file.as_str())
        .expect("(log) Unable to open events log file.");

    match writeln!(events_file, "{}", self.to_json() ) {
        Ok(_d) => debug!("Event log written"),
        Err(e) => error!("Event could not be written, Err: [{}]", e)
    }
  }

  // ------------------------------------------------------------------------

  // Function to send events through network
  // The target endpoint, its credentials and the batch identity are pinned
  // by the caller before this point, so the event cannot leak into another
  // receiver configured in the same process.
  async fn send(&self, endpoint: Endpoint, batch: String) {
        debug!("Sending event '{}' to endpoint '{}' as {}, batch '{}'",
            self.id, endpoint.address, endpoint.principal(), batch);

        // Splunk endpoint integration
        if endpoint.etype == "Splunk" {
            let data = json!({
                "source": self.node.clone(),
                "sourcetype": "_json",
                "event": json!({
                    "timestamp": self.timestamp.clone(),
                    "hostname": self.hostname.clone(),
                    "node": self.node.clone(),
                    "fpid": self.fpid.clone(),
                    "version": self.version.clone(),
                    "message": self.message.clone(),
                    "system": self.system.clone()
                }),
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
                        self.id, endpoint.address, batch, e)
            }
        // Elastic endpoint integration
        } else {
            let data = json!({
                "timestamp": self.timestamp.clone(),
                "hostname": self.hostname.clone(),
                "node": self.node.clone(),
                "fpid": self.fpid.clone(),
                "version": self.version.clone(),
                "message": self.message.clone(),
                "system": self.system.clone()
            });
            let request_url = format!("{}/{}/_doc/{}", endpoint.address, batch, self.id);
            let client = Client::builder()
                .danger_accept_invalid_certs(endpoint.insecure)
                .timeout(Duration::from_secs(30))
                .build().unwrap();
            match client
                .post(request_url)
                .basic_auth(endpoint.user, Some(endpoint.pass))
                .json(&data)
                .send()
                .await {
                    Ok(response) => debug!("Response received: {:?}",
                        response.text().await.unwrap()),
                    Err(e) => error!("Event '{}' could not be sent to endpoint '{}' (batch '{}'), Err: {:?}",
                        self.id, endpoint.address, batch, e)
            }
        }

    }

    // ------------------------------------------------------------------------

    // Function to manage event destination
    pub async fn process(&self, cfg: AppConfig, _ruleset: Ruleset) {
        route(self, cfg.clone()).await;
    }
}

// ----------------------------------------------------------------------------

pub async fn route(event: &AppEvent, cfg: AppConfig) {
  // Pin the target endpoint, its credentials and the batch identity before
  // sending, so the event keeps its original destination on retries and
  // cannot be rerouted to another receiver configured in the same process.
  let endpoint = cfg.get_endpoint();
  let batch = appconfig::events_batch();
  match cfg.get_events_destination().as_str() {
      appconfig::BOTH_MODE => {
          event.log(cfg.clone());
          event.send(endpoint, batch).await;
      },
      appconfig::NETWORK_MODE => {
          event.send(endpoint, batch).await;
      },
      _ => event.log(cfg.clone())
  }
}

// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::appevent::AppEvent;
    use crate::utils;
    use tokio_test::block_on;
    use std::fs;

    // ------------------------------------------------------------------------

    fn remove_test_file(filename: String) {
        fs::remove_file(filename).unwrap()
    }

    fn create_test_event() -> AppEvent {
        AppEvent {
            id: "Test_id".to_string(),
            timestamp: "Timestamp".to_string(),
            hostname: "Hostname".to_string(),
            node: "FIM".to_string(),
            version: "x.x.x".to_string(),
            message: "TEST".to_string(),
            fpid: 0,
            system: "test".to_string()
        }
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_create_event() {
        let evt = create_test_event();
        assert_eq!(evt.id, "Test_id".to_string());
        assert_eq!(evt.timestamp, "Timestamp".to_string());
        assert_eq!(evt.hostname, "Hostname".to_string());
        assert_eq!(evt.node, "FIM".to_string());
        assert_eq!(evt.version, "x.x.x".to_string());
        assert_eq!(evt.message, String::from("TEST"));
        assert_eq!(evt.fpid, 0);
        assert_eq!(evt.system, String::from("test"));
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_send() {
        let evt = create_test_event();
        let cfg = AppConfig::new(&utils::get_os(), None);
        block_on( evt.send(cfg.get_endpoint(), appconfig::events_batch()) );
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_send_splunk() {
        let evt = create_test_event();
        let cfg = AppConfig::new(&utils::get_os(), Some("test/unit/config/common/test_send_splunk.yml"));
        block_on( evt.send(cfg.get_endpoint(), appconfig::events_batch()) );
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_process() {
        let event = create_test_event();
        let cfg = AppConfig::new(&utils::get_os(), None);
        let ruleset = Ruleset::new(&utils::get_os(), None);  

        block_on(event.process(cfg, ruleset));
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_to_json() {
        let expected = "{\
            \"id\":\"Test_id\",\
            \"timestamp\":\"Timestamp\",\
            \"hostname\":\"Hostname\",\
            \"node\":\"FIM\",\
            \"version\":\"x.x.x\",\
            \"message\":\"TEST\",\
            \"fpid\":0,\
            \"system\":\"test\"\
        }";
        assert_eq!(create_test_event().to_json(), expected);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_log() {
        let cfg = AppConfig::new(&utils::get_os(), Some("test/unit/config/common/test_log.yml"));
        let filename = String::from("test_log.json");
        let evt = create_test_event();

        evt.log(cfg.clone());
        let contents = fs::read_to_string(filename.clone());
        let expected = "{\
            \"id\":\"Test_id\",\
            \"timestamp\":\"Timestamp\",\
            \"hostname\":\"Hostname\",\
            \"node\":\"FIM\",\
            \"version\":\"x.x.x\",\
            \"message\":\"TEST\",\
            \"fpid\":0,\
            \"system\":\"test\"\
        }\n";
        assert_eq!(contents.unwrap(), expected);
        remove_test_file(filename.clone());
    }
}
