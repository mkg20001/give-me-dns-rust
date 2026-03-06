use anyhow::Result;
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use rocket::response::content::RawHtml;
use rocket::serde::json::Json;
use rocket::{get, post, routes, State};
use serde::Serialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use crate::config::HttpConfig;
use crate::store::Store;

const TEMPLATE: &str = include_str!("../lib/index.html");

#[derive(Debug, Serialize)]
pub struct DnsInfo {
    pub has_dns: bool,
    pub ttl: String,
    pub dns_name: Option<String>,
    pub expires: Option<String>,
    pub address: String,
}

#[derive(Debug, Serialize)]
pub struct ApiResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub err: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub res: Option<DnsInfo>,
}

/// Client IP address extractor
pub struct ClientIp(pub IpAddr);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ClientIp {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        // Check X-Forwarded-For header first
        if let Some(forwarded) = req.headers().get_one("X-Forwarded-For") {
            // Take the first IP in the chain
            if let Some(ip_str) = forwarded.split(',').next() {
                if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
                    return Outcome::Success(ClientIp(ip));
                }
            }
        }

        // Fall back to remote address
        match req.client_ip() {
            Some(ip) => Outcome::Success(ClientIp(ip)),
            None => Outcome::Error((Status::BadRequest, ())),
        }
    }
}

fn get_info(store: &Store, ip: IpAddr) -> Result<DnsInfo, String> {
    let ipv6 = match ip {
        IpAddr::V6(v6) => v6,
        IpAddr::V4(_) => return Err("IPv4 not supported".to_string()),
    };

    let ttl = humanize_duration(store.ttl());

    match store.resolve_ip(ipv6) {
        Ok(Some(entry)) => Ok(DnsInfo {
            has_dns: true,
            ttl,
            dns_name: Some(entry.dns_name),
            expires: Some(entry.entry.expires.to_rfc3339()),
            address: ipv6.to_string(),
        }),
        Ok(None) => Ok(DnsInfo {
            has_dns: false,
            ttl,
            dns_name: None,
            expires: None,
            address: ipv6.to_string(),
        }),
        Err(e) => Err(e.to_string()),
    }
}

fn register_dns(store: &Store, ip: IpAddr) -> Result<DnsInfo, String> {
    let ipv6 = match ip {
        IpAddr::V6(v6) => v6,
        IpAddr::V4(_) => return Err("IPv4 not supported".to_string()),
    };

    let ttl = humanize_duration(store.ttl());

    match store.add_entry(ipv6) {
        Ok(entry) => Ok(DnsInfo {
            has_dns: true,
            ttl,
            dns_name: Some(entry.dns_name),
            expires: Some(entry.entry.expires.to_rfc3339()),
            address: ipv6.to_string(),
        }),
        Err(e) => Err(e.to_string()),
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

fn render_template(ok: bool, err: Option<&str>, res: Option<&DnsInfo>) -> String {
    let template = mustache::compile_str(TEMPLATE).expect("Failed to compile template");

    let mut data: HashMap<String, mustache::Data> = HashMap::new();
    data.insert("OK".to_string(), mustache::Data::Bool(ok));

    if let Some(e) = err {
        data.insert("Err".to_string(), mustache::Data::String(e.to_string()));
    }

    if let Some(r) = res {
        let mut res_map: HashMap<String, mustache::Data> = HashMap::new();
        res_map.insert("HasDNS".to_string(), mustache::Data::Bool(r.has_dns));
        res_map.insert("TTL".to_string(), mustache::Data::String(r.ttl.clone()));
        res_map.insert("Address".to_string(), mustache::Data::String(r.address.clone()));

        if let Some(ref dns_name) = r.dns_name {
            res_map.insert("DNSName".to_string(), mustache::Data::String(dns_name.clone()));
        }
        if let Some(ref expires) = r.expires {
            res_map.insert("Expires".to_string(), mustache::Data::String(expires.clone()));
        }

        data.insert("Res".to_string(), mustache::Data::Map(res_map));
    }

    template
        .render_data_to_string(&mustache::Data::Map(data))
        .unwrap_or_else(|e| format!("Template error: {}", e))
}

#[get("/")]
fn index_get(client_ip: ClientIp, store: &State<Arc<Store>>) -> RawHtml<String> {
    match get_info(store.inner(), client_ip.0) {
        Ok(info) => RawHtml(render_template(true, None, Some(&info))),
        Err(e) => RawHtml(render_template(false, Some(&e), None)),
    }
}

#[post("/")]
fn index_post(client_ip: ClientIp, store: &State<Arc<Store>>) -> RawHtml<String> {
    match register_dns(store.inner(), client_ip.0) {
        Ok(info) => RawHtml(render_template(true, None, Some(&info))),
        Err(e) => RawHtml(render_template(false, Some(&e), None)),
    }
}

#[get("/json")]
fn json_get(client_ip: ClientIp, store: &State<Arc<Store>>) -> Json<ApiResponse> {
    match get_info(store.inner(), client_ip.0) {
        Ok(info) => Json(ApiResponse {
            ok: true,
            err: None,
            res: Some(info),
        }),
        Err(e) => Json(ApiResponse {
            ok: false,
            err: Some(e),
            res: None,
        }),
    }
}

#[post("/json")]
fn json_post(client_ip: ClientIp, store: &State<Arc<Store>>) -> Json<ApiResponse> {
    match register_dns(store.inner(), client_ip.0) {
        Ok(info) => Json(ApiResponse {
            ok: true,
            err: None,
            res: Some(info),
        }),
        Err(e) => Json(ApiResponse {
            ok: false,
            err: Some(e),
            res: None,
        }),
    }
}

pub async fn run_http_server(
    config: HttpConfig,
    store: Arc<Store>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) -> Result<()> {
    let addr = config.address.as_deref().unwrap_or("0.0.0.0");
    let port = config.port;

    let figment = rocket::Config::figment()
        .merge(("address", addr))
        .merge(("port", port))
        .merge(("log_level", "normal"));

    let rocket = rocket::custom(figment)
        .manage(store)
        .mount("/", routes![index_get, index_post, json_get, json_post]);

    tracing::info!("HTTP server listening on {}:{}", addr, port);

    let ignite = rocket.ignite().await?;
    let shutdown_handle = ignite.shutdown();

    tokio::spawn(async move {
        let _ = shutdown.recv().await;
        shutdown_handle.notify();
    });

    ignite.launch().await?;

    Ok(())
}
