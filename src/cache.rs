use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use trust_dns_proto::rr::Record;
use trust_dns_proto::rr::RecordType;

struct Entry(Vec<Record>, DateTime<Utc>);

#[derive(Clone)]
pub struct Cache {
    db: Arc<Mutex<HashMap<(RecordType, String), Entry>>>,
}

impl Cache {
    fn new() -> Self {
        Self {
            db: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn clean(&self) {
        let db_arc = self.db.clone();
        let mut db = db_arc.lock().await;
        let mut to_delete = vec![];
        for (k, entry) in db.iter() {
            if entry.1.timestamp_millis() < Utc::now().timestamp_millis() {
                to_delete.push(k.clone());
            }
        }
        for item in &to_delete {
            db.remove(&item);
        }
        log::info!("{} record(s) removed", to_delete.len());
    }

    pub async fn get(&self, rt: &RecordType, domain: &str) -> Option<Vec<Record>> {
        let key = (rt.clone(), domain.to_string());
        if let Some(entry) = self.db.clone().lock().await.get(&key) {
            // if the entry has expired then do not return it.
            if entry.1.timestamp_millis() >= Utc::now().timestamp_millis() {
                return Some(entry.0.clone());
            }
        }
        None
    }

    pub async fn insert(&self, rt: &RecordType, domain: &str, answers: &[Record]) {
        let ttl = answers.iter().map(|r| r.ttl()).max().unwrap_or(3600);
        let expires_at = Utc::now() + chrono::Duration::seconds(ttl as i64);
        let entry = Entry(answers.to_vec().clone(), expires_at);
        let key = (rt.clone(), domain.to_string());
        self.db.clone().lock_owned().await.insert(key, entry);
    }

    pub fn cleanup(&self) {
        let cache = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                log::info!("cleaning records ...");
                cache.clean().await;
            }
        });
    }
}

pub fn new() -> Cache {
    return Cache::new();
}
