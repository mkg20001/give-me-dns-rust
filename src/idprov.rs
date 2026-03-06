use rand::seq::IndexedRandom;
use std::sync::Arc;
use uuid::Uuid;

/// Trait for ID providers that generate DNS name IDs
pub trait IdProvider: Send + Sync {
    fn generate(&self) -> String;
    #[allow(dead_code)]
    fn name(&self) -> &'static str;
}

/// Wordlist-based ID provider using embedded dictionary
pub struct WordlistProvider {
    words: Vec<&'static str>,
}

const WORDS: &str = include_str!("../lib/idprov/wordlist/words.txt");

impl WordlistProvider {
    pub fn new() -> Self {
        let words: Vec<&'static str> = WORDS.lines().filter(|s| !s.is_empty()).collect();
        tracing::info!("Loaded {} words for wordlist provider", words.len());
        Self { words }
    }
}

impl IdProvider for WordlistProvider {
    fn generate(&self) -> String {
        let mut rng = rand::rng();
        self.words
            .choose(&mut rng)
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }

    fn name(&self) -> &'static str {
        "wordlist"
    }
}

/// Random UUID-based ID provider
pub struct RandomProvider {
    id_len: usize,
}

impl RandomProvider {
    pub fn new(id_len: usize) -> Self {
        Self { id_len }
    }
}

impl IdProvider for RandomProvider {
    fn generate(&self) -> String {
        let uuid = Uuid::new_v4();
        let hex = uuid.simple().to_string();
        hex[..self.id_len.min(hex.len())].to_string()
    }

    fn name(&self) -> &'static str {
        "random"
    }
}

/// Provider manager that cycles through available providers
pub struct ProviderManager {
    providers: Vec<Arc<dyn IdProvider>>,
    current: std::sync::atomic::AtomicUsize,
}

impl ProviderManager {
    pub fn new(providers: Vec<Arc<dyn IdProvider>>) -> Self {
        Self {
            providers,
            current: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub fn generate(&self) -> String {
        if self.providers.is_empty() {
            return "fallback".to_string();
        }

        let idx = self
            .current
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % self.providers.len();
        self.providers[idx].generate()
    }
}
