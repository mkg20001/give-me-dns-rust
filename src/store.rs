use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::Ipv6Addr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::idprov::ProviderManager;

const DNS_TREE: &str = "dns";
const DNS4IP_TREE: &str = "dns4ip";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub expires: DateTime<Utc>,
    pub value: Ipv6Addr,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolvedEntry {
    pub id: String,
    pub dns_name: String,
    pub entry: Entry,
}

pub struct Store {
    db: sled::Db,
    dns_tree: sled::Tree,
    dns4ip_tree: sled::Tree,
    domain: String,
    ttl: Duration,
    provider: Arc<ProviderManager>,
    cleanup_handle: RwLock<Option<tokio::task::JoinHandle<()>>>,
}

impl Store {
    pub fn open<P: AsRef<Path>>(
        path: P,
        domain: String,
        ttl: Duration,
        provider: Arc<ProviderManager>,
    ) -> Result<Arc<Self>> {
        let db = sled::open(path).context("Failed to open database")?;
        let dns_tree = db.open_tree(DNS_TREE)?;
        let dns4ip_tree = db.open_tree(DNS4IP_TREE)?;

        let store = Arc::new(Self {
            db,
            dns_tree,
            dns4ip_tree,
            domain,
            ttl,
            provider,
            cleanup_handle: RwLock::new(None),
        });

        // Initial cleanup of expired entries
        store.cleanup_expired()?;

        Ok(store)
    }

    pub async fn start_cleanup_task(self: &Arc<Self>) {
        let store = Arc::clone(self);
        let handle = tokio::spawn(async move {
            let cleanup_interval = Duration::from_secs(60 * 3600); // 60 hours
            loop {
                tokio::time::sleep(cleanup_interval).await;
                if let Err(e) = store.cleanup_expired() {
                    tracing::error!("Cleanup task error: {}", e);
                }
            }
        });

        *self.cleanup_handle.write().await = Some(handle);
    }

    fn cleanup_expired(&self) -> Result<()> {
        let now = Utc::now();
        let mut to_remove = Vec::new();

        for result in self.dns_tree.iter() {
            let (key, value) = result?;
            let entry: Entry = serde_json::from_slice(&value)?;

            if entry.expires < now {
                to_remove.push((key.to_vec(), entry.value));
            }
        }

        for (id, ip) in to_remove {
            self.dns_tree.remove(&id)?;
            self.dns4ip_tree.remove(ip.octets().as_slice())?;
            tracing::debug!("Cleaned up expired entry: {:?}", String::from_utf8_lossy(&id));
        }

        self.db.flush()?;
        Ok(())
    }

    pub fn add_entry(&self, ip: Ipv6Addr) -> Result<ResolvedEntry> {
        // Check if IP already has an entry
        if let Some(existing) = self.resolve_ip(ip)? {
            return Ok(existing);
        }

        // Generate new ID with retry logic
        let max_attempts = 100;
        for _ in 0..max_attempts {
            let id = self.provider.generate();

            // Check if ID is already taken
            if self.dns_tree.contains_key(id.as_bytes())? {
                continue;
            }

            let entry = Entry {
                expires: Utc::now() + chrono::Duration::from_std(self.ttl)?,
                value: ip,
            };

            let entry_json = serde_json::to_vec(&entry)?;

            // Insert into both trees atomically using a batch
            let mut batch = sled::Batch::default();
            batch.insert(id.as_bytes(), entry_json);

            self.dns_tree.apply_batch(batch)?;
            self.dns4ip_tree.insert(ip.octets().as_slice(), id.as_bytes())?;
            self.db.flush()?;

            let dns_name = format!("{}.{}", id, self.domain);

            return Ok(ResolvedEntry { id, dns_name, entry });
        }

        anyhow::bail!("Failed to generate unique ID after {} attempts", max_attempts)
    }

    pub fn resolve_entry(&self, id: &str) -> Result<Option<Entry>> {
        match self.dns_tree.get(id.as_bytes())? {
            Some(value) => {
                let entry: Entry = serde_json::from_slice(&value)?;

                // Check if expired
                if entry.expires < Utc::now() {
                    // Cleanup expired entry
                    self.dns_tree.remove(id.as_bytes())?;
                    self.dns4ip_tree.remove(entry.value.octets().as_slice())?;
                    Ok(None)
                } else {
                    Ok(Some(entry))
                }
            }
            None => Ok(None),
        }
    }

    pub fn resolve_ip(&self, ip: Ipv6Addr) -> Result<Option<ResolvedEntry>> {
        match self.dns4ip_tree.get(ip.octets().as_slice())? {
            Some(id_bytes) => {
                let id = String::from_utf8(id_bytes.to_vec())?;
                match self.resolve_entry(&id)? {
                    Some(entry) => {
                        let dns_name = format!("{}.{}", id, self.domain);
                        Ok(Some(ResolvedEntry { id, dns_name, entry }))
                    }
                    None => Ok(None),
                }
            }
            None => Ok(None),
        }
    }

    pub fn get_latest_expiration(&self) -> Result<Option<DateTime<Utc>>> {
        let mut latest: Option<DateTime<Utc>> = None;

        for result in self.dns_tree.iter() {
            let (_, value) = result?;
            let entry: Entry = serde_json::from_slice(&value)?;

            match latest {
                Some(l) if entry.expires > l => latest = Some(entry.expires),
                None => latest = Some(entry.expires),
                _ => {}
            }
        }

        Ok(latest)
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        let _ = self.db.flush();
    }
}
