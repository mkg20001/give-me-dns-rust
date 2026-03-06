use serde::Deserialize;
use std::path::Path;
use std::time::Duration;

fn default_ttl() -> Duration {
    Duration::from_secs(48 * 3600)
}

fn default_dns_port() -> u16 {
    5354
}

fn default_net_port() -> u16 {
    9999
}

fn default_http_port() -> u16 {
    8053
}

fn default_id_len() -> usize {
    3
}

fn deserialize_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    parse_duration(&s).map_err(serde::de::Error::custom)
}

fn parse_duration(s: &str) -> Result<Duration, String> {
    let mut total_secs: u64 = 0;
    let mut current_num = String::new();

    for c in s.chars() {
        if c.is_ascii_digit() {
            current_num.push(c);
        } else {
            let num: u64 = current_num
                .parse()
                .map_err(|_| format!("Invalid number in duration: {}", s))?;
            current_num.clear();

            match c {
                'h' => total_secs += num * 3600,
                'm' => total_secs += num * 60,
                's' => total_secs += num,
                _ => return Err(format!("Unknown duration unit: {}", c)),
            }
        }
    }

    Ok(Duration::from_secs(total_secs))
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    #[allow(dead_code)]
    pub sentry_dsn: Option<String>,
    pub store: StoreConfig,
    pub dns: DnsConfig,
    pub net: NetConfig,
    pub http: HttpConfig,
    pub provider: ProviderConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StoreConfig {
    pub domain: String,
    #[serde(deserialize_with = "deserialize_duration", default = "default_ttl")]
    pub ttl: Duration,
    pub file: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsConfig {
    #[serde(default = "default_dns_port")]
    pub port: u16,
    #[serde(default)]
    pub address: Option<String>,
    pub ns: Vec<String>,
    pub mname: String,
    #[serde(default)]
    pub dnssec_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NetConfig {
    #[serde(default = "default_net_port")]
    pub port: u16,
    #[serde(default)]
    pub address: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HttpConfig {
    #[serde(default = "default_http_port")]
    pub port: u16,
    #[serde(default)]
    pub address: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProviderConfig {
    #[serde(default)]
    pub wordlist: WordlistProviderConfig,
    #[serde(default)]
    pub random: RandomProviderConfig,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct WordlistProviderConfig {
    #[serde(default)]
    pub enable: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RandomProviderConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default = "default_id_len")]
    pub id_len: usize,
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("48h").unwrap(), Duration::from_secs(48 * 3600));
        assert_eq!(parse_duration("1h30m").unwrap(), Duration::from_secs(90 * 60));
        assert_eq!(
            parse_duration("1h30m45s").unwrap(),
            Duration::from_secs(3600 + 30 * 60 + 45)
        );
    }
}
