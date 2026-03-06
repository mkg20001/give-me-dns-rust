mod config;
mod dns;
mod http;
mod idprov;
mod net;
mod store;

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::signal;

use config::Config;
use dns::DnsServer;
use idprov::{IdProvider, ProviderManager, RandomProvider, WordlistProvider};
use net::NetServer;
use store::Store;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    let config_path = args.get(1).context("Usage: give-me-dns <config.yaml>")?;

    // Load configuration
    let config = Config::load(config_path).context("Failed to load configuration")?;
    tracing::info!("Loaded configuration from {}", config_path);

    // Initialize ID providers
    let mut providers: Vec<Arc<dyn IdProvider>> = Vec::new();

    if config.provider.wordlist.enable {
        providers.push(Arc::new(WordlistProvider::new()));
        tracing::info!("Enabled wordlist ID provider");
    }

    if config.provider.random.enable {
        providers.push(Arc::new(RandomProvider::new(config.provider.random.id_len)));
        tracing::info!(
            "Enabled random ID provider with length {}",
            config.provider.random.id_len
        );
    }

    if providers.is_empty() {
        anyhow::bail!("No ID providers enabled. Enable at least one provider in config.");
    }

    let provider_manager = Arc::new(ProviderManager::new(providers));

    // Initialize store
    let store = Store::open(
        &config.store.file,
        config.store.domain.clone(),
        config.store.ttl,
        Arc::clone(&provider_manager),
    )
    .context("Failed to open store")?;

    // Start cleanup task
    store.start_cleanup_task().await;

    // Create shutdown broadcast channel
    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);

    // Start DNS server
    let dns_server = Arc::new(
        DnsServer::new(config.dns.clone(), Arc::clone(&store))
            .context("Failed to create DNS server")?,
    );
    let dns_shutdown = shutdown_tx.subscribe();
    let dns_handle = tokio::spawn({
        let dns_server = Arc::clone(&dns_server);
        async move {
            if let Err(e) = dns_server.run(dns_shutdown).await {
                tracing::error!("DNS server error: {}", e);
            }
        }
    });

    // Start TCP server
    let net_server = Arc::new(NetServer::new(config.net.clone(), Arc::clone(&store)));
    let net_shutdown = shutdown_tx.subscribe();
    let net_handle = tokio::spawn({
        let net_server = Arc::clone(&net_server);
        async move {
            if let Err(e) = net_server.run(net_shutdown).await {
                tracing::error!("TCP server error: {}", e);
            }
        }
    });

    // Start HTTP server
    let http_shutdown = shutdown_tx.subscribe();
    let http_handle = tokio::spawn({
        let store = Arc::clone(&store);
        let http_config = config.http.clone();
        async move {
            if let Err(e) = http::run_http_server(http_config, store, http_shutdown).await {
                tracing::error!("HTTP server error: {}", e);
            }
        }
    });

    tracing::info!("All services started. Press Ctrl+C to shutdown.");

    // Wait for shutdown signal
    signal::ctrl_c().await?;
    tracing::info!("Shutdown signal received");

    // Notify all services to shutdown
    let _ = shutdown_tx.send(());

    // Wait for all services to complete
    let _ = tokio::join!(dns_handle, net_handle, http_handle);

    tracing::info!("Shutdown complete");
    Ok(())
}
