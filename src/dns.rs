use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hickory_proto::op::{Edns, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{AAAA, NS, SOA};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use ring::digest::{digest, SHA256};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use std::net::{Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::config::DnsConfig;
use crate::store::Store;

// DNSSEC Algorithm numbers
const ALGORITHM_ECDSAP256SHA256: u8 = 13;
// DS Digest types
const DS_DIGEST_SHA256: u8 = 2;

// DNSKEY flags
const DNSKEY_FLAG_ZONE: u16 = 256;
const DNSKEY_FLAG_SEP: u16 = 1; // Secure Entry Point

pub struct DnsServer {
    config: DnsConfig,
    store: Arc<Store>,
    dnssec: Option<DnssecSigner>,
    domain: Name,
}

#[allow(dead_code)]
struct DnssecSigner {
    public_key: Vec<u8>,
    key_pair: EcdsaKeyPair,
    key_tag: u16,
    dnskey_rdata: Vec<u8>,
}

impl DnssecSigner {
    fn new(public_key: Vec<u8>, key_pair: EcdsaKeyPair) -> Self {
        // Build DNSKEY RDATA: Flags (2) + Protocol (1) + Algorithm (1) + Public Key
        let flags: u16 = DNSKEY_FLAG_ZONE | DNSKEY_FLAG_SEP; // 257
        let mut dnskey_rdata = Vec::new();
        dnskey_rdata.extend_from_slice(&flags.to_be_bytes());
        dnskey_rdata.push(3); // Protocol: always 3 for DNSSEC
        dnskey_rdata.push(ALGORITHM_ECDSAP256SHA256);
        dnskey_rdata.extend_from_slice(&public_key);

        // Calculate key tag per RFC 4034 Appendix B
        let key_tag = Self::calculate_key_tag(&dnskey_rdata);

        Self {
            public_key,
            key_pair,
            key_tag,
            dnskey_rdata,
        }
    }

    /// Generate DS record string for zone delegation
    /// DS record format: keytag algorithm digest_type digest
    fn get_ds_record(&self, domain: &Name) -> String {
        // DS digest is SHA-256 hash of: owner name (wire format) + DNSKEY RDATA
        let mut ds_data = Vec::new();
        ds_data.extend_from_slice(&name_to_wire_lowercase(domain));
        ds_data.extend_from_slice(&self.dnskey_rdata);

        let hash = digest(&SHA256, &ds_data);
        let digest_hex = hash
            .as_ref()
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<String>();

        format!(
            "{} {} {} {}",
            self.key_tag,
            ALGORITHM_ECDSAP256SHA256,
            DS_DIGEST_SHA256,
            digest_hex
        )
    }

    /// Calculate key tag per RFC 4034 Appendix B
    fn calculate_key_tag(dnskey_rdata: &[u8]) -> u16 {
        let mut ac: u32 = 0;
        for (i, &byte) in dnskey_rdata.iter().enumerate() {
            if i % 2 == 0 {
                ac += (byte as u32) << 8;
            } else {
                ac += byte as u32;
            }
        }
        ac += (ac >> 16) & 0xFFFF;
        (ac & 0xFFFF) as u16
    }

    /// Sign an RRset and return RRSIG RDATA
    fn sign_rrset(
        &self,
        rrset: &[Record],
        signer_name: &Name,
        original_ttl: u32,
    ) -> Result<Vec<u8>> {
        if rrset.is_empty() {
            anyhow::bail!("Cannot sign empty RRset");
        }

        let rr_type = rrset[0].record_type();
        let rr_class = rrset[0].dns_class();
        let owner_name = rrset[0].name();

        // RRSIG timing - use longer validity to handle clock skew
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;
        let inception = now - 86400; // 1 day ago (handles clock skew)
        let expiration = now + 86400 * 7; // 7 days from now

        // Build RRSIG RDATA (without signature)
        let mut rrsig_rdata = Vec::new();
        rrsig_rdata.extend_from_slice(&u16::from(rr_type).to_be_bytes()); // Type Covered
        rrsig_rdata.push(ALGORITHM_ECDSAP256SHA256); // Algorithm
        // Labels: count of labels in owner name, excluding root label (RFC 4034 Section 3.1.3)
        rrsig_rdata.push(owner_name.num_labels());
        rrsig_rdata.extend_from_slice(&original_ttl.to_be_bytes()); // Original TTL
        rrsig_rdata.extend_from_slice(&expiration.to_be_bytes()); // Signature Expiration
        rrsig_rdata.extend_from_slice(&inception.to_be_bytes()); // Signature Inception
        rrsig_rdata.extend_from_slice(&self.key_tag.to_be_bytes()); // Key Tag

        // Signer's Name in wire format
        let signer_wire = name_to_wire(signer_name);
        rrsig_rdata.extend_from_slice(&signer_wire);

        // Build the data to sign: RRSIG RDATA (without signature) + RRset in canonical form
        let mut sign_data = rrsig_rdata.clone();

        // Add RRset in canonical order (sorted by RDATA)
        let mut canonical_rrs: Vec<Vec<u8>> = Vec::new();
        for rr in rrset {
            let mut rr_wire = Vec::new();
            // Owner name (lowercase wire format)
            rr_wire.extend_from_slice(&name_to_wire_lowercase(rr.name()));
            // Type
            rr_wire.extend_from_slice(&u16::from(rr.record_type()).to_be_bytes());
            // Class
            rr_wire.extend_from_slice(&u16::from(rr_class).to_be_bytes());
            // TTL (use original TTL)
            rr_wire.extend_from_slice(&original_ttl.to_be_bytes());
            // RDATA
            let rdata = rdata_to_wire(rr)?;
            rr_wire.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            rr_wire.extend_from_slice(&rdata);
            canonical_rrs.push(rr_wire);
        }
        canonical_rrs.sort();
        for rr_wire in canonical_rrs {
            sign_data.extend_from_slice(&rr_wire);
        }

        // Sign with ECDSA P-256 SHA-256 using ring
        let rng = SystemRandom::new();
        let signature = self
            .key_pair
            .sign(&rng, &sign_data)
            .map_err(|_| anyhow::anyhow!("Signing failed"))?;

        // ring's ECDSA_P256_SHA256_FIXED produces R || S directly (64 bytes)
        rrsig_rdata.extend_from_slice(signature.as_ref());

        Ok(rrsig_rdata)
    }
}

/// Convert DNS name to wire format
fn name_to_wire(name: &Name) -> Vec<u8> {
    let mut wire = Vec::new();
    for label in name.iter() {
        wire.push(label.len() as u8);
        wire.extend_from_slice(label);
    }
    wire.push(0); // Root label
    wire
}

/// Convert DNS name to lowercase wire format (for canonical ordering)
fn name_to_wire_lowercase(name: &Name) -> Vec<u8> {
    let mut wire = Vec::new();
    for label in name.iter() {
        wire.push(label.len() as u8);
        for &b in label {
            wire.push(b.to_ascii_lowercase());
        }
    }
    wire.push(0);
    wire
}

/// Convert RDATA to wire format
fn rdata_to_wire(record: &Record) -> Result<Vec<u8>> {
    match record.data() {
        RData::AAAA(aaaa) => Ok(aaaa.0.octets().to_vec()),
        RData::NS(ns) => Ok(name_to_wire(&ns.0)),
        RData::SOA(soa) => {
            let mut wire = Vec::new();
            wire.extend_from_slice(&name_to_wire(soa.mname()));
            wire.extend_from_slice(&name_to_wire(soa.rname()));
            wire.extend_from_slice(&soa.serial().to_be_bytes());
            wire.extend_from_slice(&soa.refresh().to_be_bytes());
            wire.extend_from_slice(&soa.retry().to_be_bytes());
            wire.extend_from_slice(&soa.expire().to_be_bytes());
            wire.extend_from_slice(&soa.minimum().to_be_bytes());
            Ok(wire)
        }
        RData::Unknown { rdata, .. } => Ok(rdata.anything().to_vec()),
        _ => anyhow::bail!("Unsupported record type for wire format"),
    }
}

impl DnsServer {
    pub fn new(config: DnsConfig, store: Arc<Store>) -> Result<Self> {
        let domain = Name::from_ascii(&store.domain())
            .with_context(|| format!("Invalid domain: {}", store.domain()))?;

        let dnssec = if let Some(ref key_str) = config.dnssec_key {
            Some(Self::load_dnssec_key(key_str)?)
        } else {
            tracing::warn!("No DNSSEC key provided. Generating a new one...");
            let (signer, key_export) = Self::generate_dnssec_key()?;
            tracing::info!(
                "Generated new DNSSEC key. Add this to your config:\n  dnssec_key: \"{}\"",
                key_export
            );
            Some(signer)
        };

        if let Some(ref signer) = dnssec {
            tracing::info!("DNSSEC enabled with key tag: {}", signer.key_tag);
            tracing::info!("DS Record: {}", signer.get_ds_record(&domain));
        }

        Ok(Self {
            config,
            store,
            dnssec,
            domain,
        })
    }

    fn generate_dnssec_key() -> Result<(DnssecSigner, String)> {
        let rng = SystemRandom::new();
        let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| anyhow::anyhow!("Key generation failed"))?;

        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8_bytes.as_ref(), &rng)
                .map_err(|_| anyhow::anyhow!("Failed to parse generated key"))?;

        // Get public key - ring returns it in uncompressed format (0x04 || X || Y)
        let public_key_uncompressed = key_pair.public_key().as_ref();

        // DNSKEY public key format: skip the 0x04 prefix for uncompressed point
        let dnskey_pubkey = public_key_uncompressed[1..].to_vec();

        let signer = DnssecSigner::new(dnskey_pubkey.clone(), key_pair);

        // Serialize for export (store PKCS#8 and public key)
        let public_b64 = BASE64.encode(&dnskey_pubkey);
        let export_data = format!(
            "Private-key-format: v1.3\nAlgorithm: 13 (ECDSAP256SHA256)\nPrivateKey: {}\nPublicKey: {}\n",
            BASE64.encode(pkcs8_bytes.as_ref()),
            public_b64
        );

        Ok((signer, BASE64.encode(export_data.as_bytes())))
    }

    fn load_dnssec_key(key_str: &str) -> Result<DnssecSigner> {
        let decoded = BASE64.decode(key_str)?;
        let key_data = String::from_utf8(decoded)?;

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

        let rng = SystemRandom::new();

        // Try PKCS#8 format first (new format), fall back to raw scalar (old format)
        let key_pair = if private_key_bytes.len() == 32 {
            // Old format: raw 32-byte private key scalar
            // Public key needs 0x04 prefix for uncompressed point format
            let mut public_uncompressed = vec![0x04];
            public_uncompressed.extend_from_slice(&public_key_bytes);

            EcdsaKeyPair::from_private_key_and_public_key(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                &private_key_bytes,
                &public_uncompressed,
                &rng,
            )
            .map_err(|_| anyhow::anyhow!("Failed to load raw EC key"))?
        } else {
            // New format: PKCS#8 encoded key
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &private_key_bytes, &rng)
                .map_err(|_| anyhow::anyhow!("Failed to load PKCS#8 key"))?
        };

        Ok(DnssecSigner::new(public_key_bytes, key_pair))
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

        let soa = SOA::new(ns, mbox, serial, 3600, 600, 604800, 3600);

        Record::from_rdata(self.domain.clone(), 3600, RData::SOA(soa))
    }

    fn get_dnskey(&self) -> Option<Record> {
        let signer = self.dnssec.as_ref()?;

        Some(Record::from_rdata(
            self.domain.clone(),
            3600,
            RData::Unknown {
                code: RecordType::DNSKEY,
                rdata: hickory_proto::rr::rdata::NULL::with(signer.dnskey_rdata.clone()),
            },
        ))
    }

    fn get_ns_records(&self) -> Vec<Record> {
        self.config
            .ns
            .iter()
            .filter_map(|ns_str| {
                Name::from_ascii(ns_str).ok().map(|ns_name| {
                    Record::from_rdata(self.domain.clone(), 3600, RData::NS(NS(ns_name)))
                })
            })
            .collect()
    }

    /// Create RRSIG record from RDATA
    fn make_rrsig(&self, name: &Name, ttl: u32, rrsig_rdata: Vec<u8>) -> Record {
        Record::from_rdata(
            name.clone(),
            ttl,
            RData::Unknown {
                code: RecordType::RRSIG,
                rdata: hickory_proto::rr::rdata::NULL::with(rrsig_rdata),
            },
        )
    }

    /// Create NSEC record for denial of existence
    fn make_nsec(&self, name: &Name, next_name: &Name, types: &[RecordType]) -> Record {
        let mut rdata = Vec::new();

        // Next domain name
        rdata.extend_from_slice(&name_to_wire(next_name));

        // Type bit maps (simplified - just encode the types we need)
        // Window block 0 covers types 0-255
        let mut bitmap = [0u8; 32]; // 256 bits
        for &rtype in types {
            let type_num: u16 = rtype.into();
            if type_num < 256 {
                let byte_idx = (type_num / 8) as usize;
                let bit_idx = 7 - (type_num % 8);
                bitmap[byte_idx] |= 1 << bit_idx;
            }
        }
        // Find the last non-zero byte
        let last_nonzero = bitmap.iter().rposition(|&b| b != 0).unwrap_or(0);
        rdata.push(0); // Window block 0
        rdata.push((last_nonzero + 1) as u8); // Bitmap length
        rdata.extend_from_slice(&bitmap[..=last_nonzero]);

        Record::from_rdata(
            name.clone(),
            3600,
            RData::Unknown {
                code: RecordType::NSEC,
                rdata: hickory_proto::rr::rdata::NULL::with(rdata),
            },
        )
    }

    /// Create "black lies" next name: \000.<name>
    /// This is a synthesized name that sorts immediately after the queried name
    fn make_black_lies_next_name(name: &Name) -> Name {
        // Prepend a null byte label to the name
        let mut labels: Vec<&[u8]> = vec![&[0u8]]; // null byte label
        labels.extend(name.iter());

        // Build the name from labels
        let mut result = Name::root();
        for label in labels.into_iter().rev() {
            if !label.is_empty() || result.is_root() {
                if let Ok(new_name) = result.prepend_label(label) {
                    result = new_name;
                }
            }
        }
        result
    }

    fn resolve_aaaa(&self, name: &Name) -> Option<Ipv6Addr> {
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

        // Check if DNSSEC is requested (DO bit in EDNS)
        let do_dnssec = request
            .extensions()
            .as_ref()
            .map(|e| e.flags().dnssec_ok)
            .unwrap_or(false);

        // Get EDNS max payload size
        let max_payload = request
            .extensions()
            .as_ref()
            .map(|e| e.max_payload())
            .unwrap_or(512);

        if do_dnssec {
            let mut edns = Edns::new();
            edns.set_dnssec_ok(true);
            edns.set_max_payload(4096);
            response.set_edns(edns);
        }

        // Only handle single question (standard behavior)
        let query = match request.queries().first() {
            Some(q) => q,
            None => return response,
        };

        response.add_query(query.clone());

        // Check query class
        if query.query_class() != DNSClass::IN {
            response.set_response_code(ResponseCode::NotImp);
            return response;
        }

        let qname = query.name();
        let qtype = query.query_type();
        let main_domain = format!("{}.", self.store.domain());
        let is_main = qname.to_lowercase().to_string() == main_domain.to_lowercase();

        // Check if query is within our zone (must be domain or subdomain of it)
        // zone_of checks if self is a zone of the argument, so we check if our domain is a zone of qname
        let is_in_zone = is_main || self.domain.zone_of(qname);
        if !is_in_zone {
            // Not our zone - return REFUSED
            response.set_authoritative(false);
            response.set_response_code(ResponseCode::Refused);
            return response;
        }

        tracing::debug!("Query: {} {} (DNSSEC: {})", qname, qtype, do_dnssec);

        match qtype {
            RecordType::DNSKEY if is_main => {
                if let Some(dnskey) = self.get_dnskey() {
                    response.add_answer(dnskey.clone());

                    // Sign DNSKEY RRset
                    if do_dnssec {
                        if let Some(ref signer) = self.dnssec {
                            if let Ok(rrsig) = signer.sign_rrset(&[dnskey], &self.domain, 3600) {
                                response.add_answer(self.make_rrsig(&self.domain, 3600, rrsig));
                            }
                        }
                    }
                }
            }

            RecordType::NS if is_main => {
                let ns_records = self.get_ns_records();
                for ns in &ns_records {
                    response.add_answer(ns.clone());
                }

                // Sign NS RRset
                if do_dnssec && !ns_records.is_empty() {
                    if let Some(ref signer) = self.dnssec {
                        if let Ok(rrsig) = signer.sign_rrset(&ns_records, &self.domain, 3600) {
                            response.add_answer(self.make_rrsig(&self.domain, 3600, rrsig));
                        }
                    }
                }
            }

            RecordType::SOA if is_main => {
                let soa = self.get_soa();
                response.add_answer(soa.clone());

                // Sign SOA RRset
                if do_dnssec {
                    if let Some(ref signer) = self.dnssec {
                        if let Ok(rrsig) = signer.sign_rrset(&[soa], &self.domain, 3600) {
                            response.add_answer(self.make_rrsig(&self.domain, 3600, rrsig));
                        }
                    }
                }
            }

            RecordType::AAAA => {
                if let Some(ip) = self.resolve_aaaa(qname) {
                    let ttl = self.store.ttl().as_secs() as u32;
                    let aaaa = AAAA(ip);
                    let record = Record::from_rdata(qname.clone(), ttl, RData::AAAA(aaaa));
                    response.add_answer(record.clone());

                    // Sign AAAA RRset
                    if do_dnssec {
                        if let Some(ref signer) = self.dnssec {
                            if let Ok(rrsig) = signer.sign_rrset(&[record], &self.domain, ttl) {
                                response.add_answer(self.make_rrsig(qname, ttl, rrsig));
                            }
                        }
                    }

                    tracing::info!("Resolved {} -> {}", qname, ip);
                }
            }

            _ => {}
        }

        // Handle no answers (negative response)
        if response.answers().is_empty() {
            let soa = self.get_soa();
            response.add_name_server(soa.clone());

            // Sign SOA in authority
            if do_dnssec {
                if let Some(ref signer) = self.dnssec {
                    if let Ok(rrsig) = signer.sign_rrset(&[soa], &self.domain, 3600) {
                        response.add_name_server(self.make_rrsig(&self.domain, 3600, rrsig));
                    }
                }
            }

            // Determine if name exists (NODATA) or doesn't exist (NXDOMAIN)
            let name_exists = is_main || self.resolve_aaaa(qname).is_some();

            if name_exists {
                // NODATA: Name exists but requested type doesn't
                // Add NSEC proving which types DO exist at this name
                if do_dnssec {
                    let next_name = Self::make_black_lies_next_name(qname);

                    // Type bitmap includes types that exist at this name
                    let existing_types = if is_main {
                        // Apex has SOA, NS, DNSKEY
                        vec![
                            RecordType::SOA,
                            RecordType::NS,
                            RecordType::DNSKEY,
                            RecordType::RRSIG,
                            RecordType::NSEC,
                        ]
                    } else {
                        // Subdomains have AAAA
                        vec![RecordType::AAAA, RecordType::RRSIG, RecordType::NSEC]
                    };

                    let nsec = self.make_nsec(qname, &next_name, &existing_types);
                    response.add_name_server(nsec.clone());

                    if let Some(ref signer) = self.dnssec {
                        if let Ok(rrsig) = signer.sign_rrset(&[nsec], &self.domain, 3600) {
                            response.add_name_server(self.make_rrsig(qname, 3600, rrsig));
                        }
                    }
                }
            } else {
                // NXDOMAIN: Name does not exist
                response.set_response_code(ResponseCode::NXDomain);

                // Add NSEC for denial of existence using "black lies" approach
                if do_dnssec {
                    let next_name = Self::make_black_lies_next_name(qname);

                    // NSEC with minimal type bitmap (only RRSIG + NSEC)
                    let nsec = self.make_nsec(
                        qname,
                        &next_name,
                        &[RecordType::RRSIG, RecordType::NSEC],
                    );
                    response.add_name_server(nsec.clone());

                    if let Some(ref signer) = self.dnssec {
                        if let Ok(rrsig) = signer.sign_rrset(&[nsec], &self.domain, 3600) {
                            response.add_name_server(self.make_rrsig(qname, 3600, rrsig));
                        }
                    }
                }
            }
        }

        // Check response size for UDP truncation
        if let Ok(response_bytes) = response.to_bytes() {
            if response_bytes.len() > max_payload as usize {
                // Truncate: keep header and question, set TC bit
                let mut truncated = hickory_proto::op::Message::new();
                truncated.set_id(response.id());
                truncated.set_message_type(MessageType::Response);
                truncated.set_op_code(OpCode::Query);
                truncated.set_authoritative(true);
                truncated.set_truncated(true);
                truncated.set_recursion_desired(request.recursion_desired());
                truncated.add_query(query.clone());
                if do_dnssec {
                    let mut edns = Edns::new();
                    edns.set_dnssec_ok(true);
                    edns.set_max_payload(4096);
                    truncated.set_edns(edns);
                }
                return truncated;
            }
        }

        response
    }

    async fn handle_tcp_connection(self: Arc<Self>, mut stream: TcpStream) -> Result<()> {
        loop {
            let mut len_buf = [0u8; 2];
            match stream.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            }
            let len = u16::from_be_bytes(len_buf) as usize;

            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await?;

            let request = hickory_proto::op::Message::from_bytes(&buf)?;
            let response = self.handle_query(&request);
            let response_bytes = response.to_bytes()?;

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
            self.config.address.as_deref().unwrap_or("[::]"),
            self.config.port
        )
        .parse()?;

        let udp_socket = UdpSocket::bind(addr)?;
        udp_socket.set_nonblocking(true)?;
        let udp_socket = tokio::net::UdpSocket::from_std(udp_socket)?;
        let udp_socket = Arc::new(udp_socket);

        let tcp_listener = TcpListener::bind(addr).await?;

        tracing::info!("DNS server listening on {} (TCP+UDP)", addr);

        let server = Arc::clone(&self);
        let udp_socket_clone = Arc::clone(&udp_socket);
        let mut shutdown_udp = shutdown.resubscribe();

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
