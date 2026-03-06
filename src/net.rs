use anyhow::Result;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use crate::config::NetConfig;
use crate::store::Store;

pub struct NetServer {
    config: NetConfig,
    store: Arc<Store>,
}

impl NetServer {
    pub fn new(config: NetConfig, store: Arc<Store>) -> Self {
        Self { config, store }
    }

    async fn handle_connection(&self, mut stream: TcpStream, peer_addr: SocketAddr) -> Result<()> {
        let ip = peer_addr.ip();

        let ipv6 = match ip {
            IpAddr::V6(v6) => v6,
            IpAddr::V4(_) => {
                stream.write_all(b"IPv4 not supported\n").await?;
                return Ok(());
            }
        };

        match self.store.add_entry(ipv6) {
            Ok(entry) => {
                let response = format!(
                    "Address: {}\nDNS Name: {}\nValid for {}\nExpires {}\n",
                    entry.entry.value,
                    entry.dns_name,
                    humanize_duration(self.store.ttl()),
                    entry.entry.expires.to_rfc3339()
                );
                stream.write_all(response.as_bytes()).await?;
                tracing::info!(
                    "Registered {} -> {}",
                    ipv6,
                    entry.dns_name
                );
            }
            Err(e) => {
                let response = format!("Error: {}\n", e);
                stream.write_all(response.as_bytes()).await?;
                tracing::error!("Failed to register {}: {}", ipv6, e);
            }
        }

        Ok(())
    }

    pub async fn run(
        self: Arc<Self>,
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) -> Result<()> {
        let addr: SocketAddr = format!(
            "[{}]:{}",
            self.config.address.as_deref().unwrap_or("::"),
            self.config.port
        )
        .parse()?;

        let listener = TcpListener::bind(addr).await?;
        tracing::info!("TCP server listening on {}", addr);

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            let server = Arc::clone(&self);
                            tokio::spawn(async move {
                                if let Err(e) = server.handle_connection(stream, peer_addr).await {
                                    tracing::error!("Connection error from {}: {}", peer_addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!("Accept error: {}", e);
                        }
                    }
                }
                _ = shutdown.recv() => {
                    tracing::info!("TCP server shutting down");
                    break;
                }
            }
        }

        Ok(())
    }
}

fn humanize_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    let hours = secs / 3600;
    let mins = (secs % 3600) / 60;
    let secs = secs % 60;

    if hours > 0 && mins > 0 && secs > 0 {
        format!("{}h{}m{}s", hours, mins, secs)
    } else if hours > 0 && mins > 0 {
        format!("{}h{}m0s", hours, mins)
    } else if hours > 0 {
        format!("{}h0m0s", hours)
    } else if mins > 0 {
        format!("{}m{}s", mins, secs)
    } else {
        format!("{}s", secs)
    }
}
