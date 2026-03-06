use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hickory_proto::op::{MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{AAAA, NS, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use std::net::{Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::config::DnsConfig;
use crate::store::Store;

pub struct DnsServer {
    config: DnsConfig,
    store: Arc<Store>,
    dnssec_key: Option<DnssecKey>,
    domain: Name,
}

#[allow(dead_code)]
struct DnssecKey {
    public_key: Vec<u8>,
    private_key: PKey<openssl::pkey::Private>,
    key_tag: u16,
}

impl DnsServer {
    pub fn new(config: DnsConfig, store: Arc<Store>) -> Result<Self> {
        let domain = Name::from_ascii(&store.domain())
            .with_context(|| format!("Invalid domain: {}", store.domain()))?;

        let dnssec_key = if let Some(ref key_str) = config.dnssec_key {
            Some(Self::load_dnssec_key(key_str)?)
        } else {
            tracing::warn!("No DNSSEC key provided. Generating a new one...");
            let (key, key_export) = Self::generate_dnssec_key()?;
            tracing::info!(
                "Generated new DNSSEC key. Add this to your config:\n  dnssec_key: \"{}\"",
                key_export
            );
            Some(key)
        };

        if let Some(ref key) = dnssec_key {
            tracing::info!("DNSSEC enabled with key tag: {}", key.key_tag);
        }

        Ok(Self {
            config,
            store,
            dnssec_key,
            domain,
        })
    }

    fn generate_dnssec_key() -> Result<(DnssecKey, String)> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let ec_key = EcKey::generate(&group)?;
        let private_key = PKey::from_ec_key(ec_key.clone())?;

        // Get the public key in uncompressed format
        let mut ctx = openssl::bn::BigNumContext::new()?;
        let public_key_bytes = ec_key.public_key().to_bytes(
            &group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        )?;

        // DNSKEY public key format: skip the 0x04 prefix for uncompressed point
        let dnskey_pubkey = public_key_bytes[1..].to_vec();

        // Calculate key tag (simplified)
        let key_tag = Self::calculate_key_tag(&dnskey_pubkey);

        // Serialize for export
        let public_b64 = BASE64.encode(&dnskey_pubkey);
        let export_data = format!(
            "Private-key-format: v1.3\nAlgorithm: 13 (ECDSAP256SHA256)\nPrivateKey: {}\nPublicKey: {}\n",
            BASE64.encode(ec_key.private_key().to_vec()),
            public_b64
        );

        let key = DnssecKey {
            public_key: dnskey_pubkey,
            private_key,
            key_tag,
        };

        Ok((key, BASE64.encode(export_data.as_bytes())))
    }

    fn load_dnssec_key(key_str: &str) -> Result<DnssecKey> {
        let decoded = BASE64.decode(key_str)?;
        let key_data = String::from_utf8(decoded)?;

        // Parse the key data
        let mut private_key_b64 = None;
        let mut public_key_b64 = None;

        for line in key_data.lines() {
            if line.starts_with("PrivateKey:") {
                private_key_b64 = Some(line.trim_start_matches("PrivateKey:").trim());
            } else if line.starts_with("PublicKey:") {
                public_key_b64 = Some(line.trim_start_matches("PublicKey:").trim());
            }
        }

        let private_key_bytes = BASE64
            .decode(private_key_b64.ok_or_else(|| anyhow::anyhow!("Missing PrivateKey"))?)?;
        let public_key_bytes = BASE64
            .decode(public_key_b64.ok_or_else(|| anyhow::anyhow!("Missing PublicKey"))?)?;

        // Reconstruct the EC key
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let private_bn = openssl::bn::BigNum::from_slice(&private_key_bytes)?;

        // Reconstruct public key point (add 0x04 prefix for uncompressed)
        let mut public_uncompressed = vec![0x04];
        public_uncompressed.extend_from_slice(&public_key_bytes);

        let mut ctx = openssl::bn::BigNumContext::new()?;
        let public_point =
            openssl::ec::EcPoint::from_bytes(&group, &public_uncompressed, &mut ctx)?;

        let ec_key = EcKey::from_private_components(&group, &private_bn, &public_point)?;
        ec_key.check_key()?;

        let private_key = PKey::from_ec_key(ec_key)?;
        let key_tag = Self::calculate_key_tag(&public_key_bytes);

        Ok(DnssecKey {
            public_key: public_key_bytes,
            private_key,
            key_tag,
        })
    }

    fn calculate_key_tag(public_key: &[u8]) -> u16 {
        // Simplified DNSKEY key tag calculation for algorithm 13 (ECDSAP256SHA256)
        // This is a simplified version - in production you'd use the full RFC 4034 algorithm
        let mut ac: u32 = 0;

        // Flags (257 = ZONE + SEP)
        ac += 257 << 8;
        ac += 257 & 0xFF;
        // Protocol (3)
        ac += 3 << 8;
        // Algorithm (13 = ECDSAP256SHA256)
        ac += 13;

        // Add public key bytes
        for (i, &byte) in public_key.iter().enumerate() {
            if i % 2 == 0 {
                ac += (byte as u32) << 8;
            } else {
                ac += byte as u32;
            }
        }

        ac += (ac >> 16) & 0xFFFF;
        (ac & 0xFFFF) as u16
    }

    fn get_soa(&self) -> Record {
        let serial = self
            .store
            .get_latest_expiration()
            .ok()
            .flatten()
            .map(|dt| dt.timestamp() as u32)
            .unwrap_or(1);

        let ns = Name::from_ascii(&self.config.ns[0]).unwrap_or_else(|_| self.domain.clone());
        let mbox = Name::from_ascii(&self.config.mname).unwrap_or_else(|_| self.domain.clone());

        let soa = SOA::new(ns, mbox, serial, 1, 1, 1, 3600);

        Record::from_rdata(self.domain.clone(), 3600, RData::SOA(soa))
    }

    fn get_dnskey(&self) -> Option<Record> {
        let key = self.dnssec_key.as_ref()?;

        // Build DNSKEY record manually
        // Flags: 257 (ZONE + SEP), Protocol: 3, Algorithm: 13 (ECDSAP256SHA256)
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&257u16.to_be_bytes()); // Flags
        rdata.push(3); // Protocol
        rdata.push(13); // Algorithm (ECDSAP256SHA256)
        rdata.extend_from_slice(&key.public_key); // Public key

        // Return as unknown record type for now (we'd need proper DNSKEY support)
        Some(Record::from_rdata(
            self.domain.clone(),
            3600,
            RData::Unknown {
                code: RecordType::DNSKEY,
                rdata: hickory_proto::rr::rdata::NULL::with(rdata),
            },
        ))
    }

    fn resolve_aaaa(&self, name: &Name) -> Option<Ipv6Addr> {
        // Extract the subdomain (first label)
        let labels: Vec<_> = name.iter().collect();
        if labels.len() < 2 {
            return None;
        }

        let subdomain = std::str::from_utf8(labels[0]).ok()?.to_lowercase();

        self.store
            .resolve_entry(&subdomain)
            .ok()
            .flatten()
            .map(|e| e.value)
    }

    fn handle_query(&self, request: &hickory_proto::op::Message) -> hickory_proto::op::Message {
        let mut response = hickory_proto::op::Message::new();
        response.set_id(request.id());
        response.set_message_type(MessageType::Response);
        response.set_op_code(OpCode::Query);
        response.set_authoritative(true);
        response.set_recursion_desired(request.recursion_desired());
        response.set_recursion_available(false);

        // Copy questions
        for q in request.queries() {
            response.add_query(q.clone());
        }

        // Check if DNSSEC is requested
        let do_dnssec = request
            .extensions()
            .as_ref()
            .map(|e| e.flags().dnssec_ok)
            .unwrap_or(false);

        if do_dnssec {
            let mut edns = hickory_proto::op::Edns::new();
            edns.set_dnssec_ok(true);
            edns.set_max_payload(4096);
            response.set_edns(edns);
        }

        let main_domain = format!("{}.", self.store.domain());

        for query in request.queries() {
            let qname = query.name();
            let qtype = query.query_type();
            let is_main = qname.to_lowercase().to_string() == main_domain.to_lowercase();

            tracing::debug!("Query: {} {}", qname, qtype);

            match qtype {
                RecordType::DNSKEY if is_main => {
                    if let Some(dnskey) = self.get_dnskey() {
                        response.add_answer(dnskey);
                    }
                }

                RecordType::NS if is_main => {
                    for ns_str in &self.config.ns {
                        if let Ok(ns_name) = Name::from_ascii(ns_str) {
                            let ns = NS(ns_name);
                            let record =
                                Record::from_rdata(self.domain.clone(), 3600, RData::NS(ns));
                            response.add_answer(record);
                        }
                    }
                }

                RecordType::SOA if is_main => {
                    response.add_answer(self.get_soa());
                }

                RecordType::AAAA => {
                    if let Some(ip) = self.resolve_aaaa(qname) {
                        let aaaa = AAAA(ip);
                        let record = Record::from_rdata(
                            qname.clone(),
                            self.store.ttl().as_secs() as u32,
                            RData::AAAA(aaaa),
                        );
                        response.add_answer(record);
                        tracing::info!("Resolved {} -> {}", qname, ip);
                    }
                }

                _ => {}
            }

            // If no answers, add SOA to authority section
            if response.answers().is_empty() {
                response.add_name_server(self.get_soa());

                // Set NXDOMAIN if not main domain and no AAAA found
                if !is_main && self.resolve_aaaa(qname).is_none() {
                    response.set_response_code(ResponseCode::NXDomain);
                }
            }
        }

        response
    }

    async fn handle_tcp_connection(self: Arc<Self>, mut stream: TcpStream) -> Result<()> {
        loop {
            // Read length prefix (2 bytes)
            let mut len_buf = [0u8; 2];
            match stream.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            }
            let len = u16::from_be_bytes(len_buf) as usize;

            // Read message
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await?;

            let request = hickory_proto::op::Message::from_bytes(&buf)?;
            let response = self.handle_query(&request);
            let response_bytes = response.to_bytes()?;

            // Write length prefix and response
            let len_bytes = (response_bytes.len() as u16).to_be_bytes();
            stream.write_all(&len_bytes).await?;
            stream.write_all(&response_bytes).await?;
        }

        Ok(())
    }

    pub async fn run(
        self: Arc<Self>,
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) -> Result<()> {
        let addr: SocketAddr = format!(
            "{}:{}",
            self.config.address.as_deref().unwrap_or("0.0.0.0"),
            self.config.port
        )
        .parse()?;

        // UDP server
        let udp_socket = UdpSocket::bind(addr)?;
        udp_socket.set_nonblocking(true)?;
        let udp_socket = tokio::net::UdpSocket::from_std(udp_socket)?;
        let udp_socket = Arc::new(udp_socket);

        // TCP server
        let tcp_listener = TcpListener::bind(addr).await?;

        tracing::info!("DNS server listening on {} (TCP+UDP)", addr);

        let server = Arc::clone(&self);
        let udp_socket_clone = Arc::clone(&udp_socket);
        let mut shutdown_udp = shutdown.resubscribe();

        // UDP handler
        let udp_handle = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                tokio::select! {
                    result = udp_socket_clone.recv_from(&mut buf) => {
                        match result {
                            Ok((len, src)) => {
                                if let Ok(request) = hickory_proto::op::Message::from_bytes(&buf[..len]) {
                                    let response = server.handle_query(&request);
                                    if let Ok(response_bytes) = response.to_bytes() {
                                        let _ = udp_socket_clone.send_to(&response_bytes, src).await;
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::error!("UDP receive error: {}", e);
                            }
                        }
                    }
                    _ = shutdown_udp.recv() => {
                        tracing::info!("DNS UDP server shutting down");
                        break;
                    }
                }
            }
        });

        let server = Arc::clone(&self);

        // TCP handler
        let tcp_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = tcp_listener.accept() => {
                        match result {
                            Ok((stream, _)) => {
                                let server = Arc::clone(&server);
                                tokio::spawn(async move {
                                    if let Err(e) = server.handle_tcp_connection(stream).await {
                                        tracing::error!("TCP connection error: {}", e);
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::error!("TCP accept error: {}", e);
                            }
                        }
                    }
                    _ = shutdown.recv() => {
                        tracing::info!("DNS TCP server shutting down");
                        break;
                    }
                }
            }
        });

        let _ = tokio::join!(udp_handle, tcp_handle);
        Ok(())
    }
}
