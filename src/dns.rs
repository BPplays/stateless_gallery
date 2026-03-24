//! DNS resolver supporting DoH (DNS-over-HTTPS), DoT (DNS-over-TLS), and
//! plain UDP/TCP DNS.
//!
//! Groups are tried in order; within each group all servers are queried
//! in parallel and the first non-empty result wins.

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use tokio::task::JoinSet;
use trust_dns_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{DNSClass, Name, RData, RecordType},
        serialize::binary::{BinDecodable, BinEncoder, BinEncodable},
    },
    TokioAsyncResolver,
};

use crate::config::{DnsServer, NetworkConfig};

// ── Types ─────────────────────────────────────────────────────────────────────

/// A single SSHFP record from DNS (RFC 4255 / RFC 6594 / RFC 7479).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshfpRecord {
    /// Algorithm: 1=RSA, 2=DSA, 3=ECDSA, 4=Ed25519
    pub algorithm: u8,
    /// Fingerprint type: 1=SHA-1, 2=SHA-256
    pub fp_type: u8,
    /// Raw fingerprint bytes
    pub fingerprint: Vec<u8>,
}

// ── DnsResolver ──────────────────────────────────────────────────────────────

/// Resolver that tries configured groups in order, with per-group parallelism.
#[derive(Clone)]
pub struct DnsResolver {
    groups: Vec<Arc<DnsGroup>>,
    http: reqwest::Client,
}

struct DnsGroup {
    /// Resolvers for DoT / plain DNS (trust-dns)
    resolvers: Vec<TokioAsyncResolver>,
    /// DoH endpoints (we query these with reqwest ourselves)
    doh_endpoints: Vec<String>,
}

// Well-known TLS names for popular public resolvers.
fn known_tls_name(ip: &IpAddr) -> Option<&'static str> {
    match ip.to_string().as_str() {
        "1.1.1.1" | "1.0.0.1" |
        "2606:4700:4700::1111" | "2606:4700:4700::1001" => Some("cloudflare-dns.com"),
        "8.8.8.8" | "8.8.4.4" |
        "2001:4860:4860::8888" | "2001:4860:4860::8844" => Some("dns.google"),
        "9.9.9.9" | "149.112.112.112" |
        "2620:fe::fe" | "2620:fe::9" => Some("dns.quad9.net"),
        _ => None,
    }
}

/// Build a `SocketAddr` from a server config, applying the protocol default port.
fn server_addr(s: &DnsServer) -> Result<(IpAddr, SocketAddr)> {
    let ip = IpAddr::from_str(&s.host)
        .map_err(|e| anyhow::anyhow!("invalid DNS server IP {:?}: {e}", s.host))?;
    let default_port = match s.kind.as_str() {
        "dot" => 853,
        "doh" => 443,
        _     => 53,
    };
    let port = s.port.unwrap_or(default_port);
    Ok((ip, SocketAddr::new(ip, port)))
}

/// Build a DoH endpoint URL from a server config.
fn doh_url(s: &DnsServer) -> Result<String> {
    let ip = IpAddr::from_str(&s.host)?;
    let port = s.port.unwrap_or(443);
    let host_part = if ip.is_ipv6() {
        format!("[{}]", ip)
    } else {
        ip.to_string()
    };
    let tls_name = s.tls_name.as_deref()
        .or_else(|| known_tls_name(&ip));
    // Prefer the TLS name in the URL when available (better certificate match)
    let host_for_url = tls_name.unwrap_or(&host_part);
    Ok(format!("https://{}:{}/dns-query", host_for_url, port))
}

/// Build a trust-dns resolver for a single DoT or plain-DNS server.
fn build_resolver(s: &DnsServer) -> Option<TokioAsyncResolver> {
    let (ip, addr) = server_addr(s).ok()?;

    let (protocol, tls_name) = match s.kind.as_str() {
        "dot" => {
            let name = s.tls_name.clone()
                .or_else(|| known_tls_name(&ip).map(str::to_owned));
            if name.is_none() {
                tracing::warn!(
                    server = %s.host,
                    "DoT server has no TLS name; skipping \
                     (add 'tls_name: dns.example.com' to config)"
                );
                return None;
            }
            (Protocol::Tls, name)
        }
        _ => (Protocol::Udp, None),
    };

    let mut ns = NameServerConfig::new(addr, protocol);
    ns.tls_dns_name = tls_name;

    let mut cfg = ResolverConfig::new();
    cfg.add_name_server(ns);

    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(5);
    opts.attempts = 1;

    Some(TokioAsyncResolver::tokio(cfg, opts))
}

fn build_group(servers: &[DnsServer]) -> DnsGroup {
    let mut resolvers  = Vec::new();
    let mut doh_endpoints = Vec::new();

    for s in servers {
        match s.kind.as_str() {
            "doh" => {
                match doh_url(s) {
                    Ok(u)  => doh_endpoints.push(u),
                    Err(e) => tracing::warn!(server = %s.host, "invalid DoH server: {e}"),
                }
            }
            "dot" | "dns" => {
                if let Some(r) = build_resolver(s) {
                    resolvers.push(r);
                }
            }
            other => tracing::warn!(kind = %other, "unknown DNS server type, ignoring"),
        }
    }

    DnsGroup { resolvers, doh_endpoints }
}

/// Default groups: DoT then plain DNS, using Cloudflare + Google.
fn default_groups() -> Vec<Arc<DnsGroup>> {
    let dot_servers = [
        ("2606:4700:4700::1111", "dot", Some("cloudflare-dns.com")),
        ("2606:4700:4700::1001", "dot", Some("cloudflare-dns.com")),
        ("2001:4860:4860::8888", "dot", Some("dns.google")),
        ("2001:4860:4860::8844", "dot", Some("dns.google")),
        ("1.1.1.1",              "dot", Some("cloudflare-dns.com")),
        ("1.0.0.1",              "dot", Some("cloudflare-dns.com")),
        ("8.8.8.8",              "dot", Some("dns.google")),
        ("8.8.4.4",              "dot", Some("dns.google")),
    ];
    let dns_servers = [
        "2606:4700:4700::1111", "2606:4700:4700::1001",
        "2001:4860:4860::8888", "2001:4860:4860::8844",
        "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
    ];

    let dot_group = {
        let mut resolvers = Vec::new();
        for (host, _kind, tls_name) in dot_servers {
            let ip = IpAddr::from_str(host).unwrap();
            let addr = SocketAddr::new(ip, 853);
            let mut ns = NameServerConfig::new(addr, Protocol::Tls);
            ns.tls_dns_name = tls_name.map(str::to_owned);
            let mut cfg = ResolverConfig::new();
            cfg.add_name_server(ns);
            let mut opts = ResolverOpts::default();
            opts.timeout = Duration::from_secs(5);
            opts.attempts = 1;
            resolvers.push(TokioAsyncResolver::tokio(cfg, opts));
        }
        Arc::new(DnsGroup { resolvers, doh_endpoints: vec![] })
    };

    let dns_group = {
        let mut resolvers = Vec::new();
        for host in dns_servers {
            let ip = IpAddr::from_str(host).unwrap();
            let addr = SocketAddr::new(ip, 53);
            let ns = NameServerConfig::new(addr, Protocol::Udp);
            let mut cfg = ResolverConfig::new();
            cfg.add_name_server(ns);
            let mut opts = ResolverOpts::default();
            opts.timeout = Duration::from_secs(5);
            opts.attempts = 1;
            resolvers.push(TokioAsyncResolver::tokio(cfg, opts));
        }
        Arc::new(DnsGroup { resolvers, doh_endpoints: vec![] })
    };

    vec![dot_group, dns_group]
}

impl DnsResolver {
    pub fn new(config: &NetworkConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .user_agent("stateless-gallery/1.0 dns-sshfp-verify")
            .build()
            .unwrap_or_default();

        let groups = if config.dns.is_empty() {
            default_groups()
        } else {
            config.dns.iter()
                .map(|g| Arc::new(build_group(&g.servers)))
                .collect()
        };

        DnsResolver { groups, http }
    }

    /// Query SSHFP records for `hostname`.
    /// Groups tried in order; within a group all servers queried in parallel.
    pub async fn query_sshfp(&self, hostname: &str) -> Vec<SshfpRecord> {
        let hostname = hostname.trim_end_matches('.');
        for group in &self.groups {
            let records = query_group(group, hostname, &self.http).await;
            if !records.is_empty() {
                return records;
            }
        }
        vec![]
    }
}

async fn query_group(group: &DnsGroup, hostname: &str, http: &reqwest::Client) -> Vec<SshfpRecord> {
    let mut set: JoinSet<Vec<SshfpRecord>> = JoinSet::new();

    for resolver in &group.resolvers {
        let r = resolver.clone();
        let h = hostname.to_owned();
        set.spawn(async move {
            query_via_resolver(&r, &h).await.unwrap_or_default()
        });
    }

    for endpoint in &group.doh_endpoints {
        let ep = endpoint.clone();
        let h  = hostname.to_owned();
        let hc = http.clone();
        set.spawn(async move {
            query_via_doh(&hc, &ep, &h).await.unwrap_or_default()
        });
    }

    // Return the first non-empty result; cancel the rest.
    while let Some(res) = set.join_next().await {
        if let Ok(records) = res {
            if !records.is_empty() {
                set.abort_all();
                return records;
            }
        }
    }
    vec![]
}

// ── Resolver-based query (DoT / plain DNS) ────────────────────────────────────

async fn query_via_resolver(resolver: &TokioAsyncResolver, hostname: &str) -> Result<Vec<SshfpRecord>> {
    let fqdn = if hostname.ends_with('.') {
        hostname.to_owned()
    } else {
        format!("{}.", hostname)
    };
    let lookup = tokio::time::timeout(
        Duration::from_secs(6),
        resolver.lookup(&fqdn, RecordType::SSHFP),
    ).await??;

    let records = lookup.iter()
        .filter_map(parse_sshfp_rdata)
        .collect();
    Ok(records)
}

fn parse_sshfp_rdata(rdata: &RData) -> Option<SshfpRecord> {
    if let RData::SSHFP(sshfp) = rdata {
        Some(SshfpRecord {
            algorithm:   u8::from(sshfp.algorithm()),
            fp_type:     u8::from(sshfp.fingerprint_type()),
            fingerprint: sshfp.fingerprint().to_vec(),
        })
    } else {
        None
    }
}

// ── DoH query (reqwest + DNS wire format) ─────────────────────────────────────

static DNS_MSG_ID: AtomicU16 = AtomicU16::new(1);

fn build_sshfp_query(hostname: &str) -> Result<Vec<u8>> {
    let id  = DNS_MSG_ID.fetch_add(1, Ordering::Relaxed);
    let mut msg = Message::new();
    msg.set_id(id)
       .set_message_type(MessageType::Query)
       .set_op_code(OpCode::Query)
       .set_recursion_desired(true);

    let name = Name::from_str(hostname)
        .map_err(|e| anyhow::anyhow!("invalid hostname {hostname:?}: {e}"))?;
    let mut q = Query::new();
    q.set_name(name)
     .set_query_type(RecordType::SSHFP)
     .set_query_class(DNSClass::IN);
    msg.add_query(q);

    let mut buf = Vec::new();
    let mut enc = BinEncoder::new(&mut buf);
    msg.emit(&mut enc)?;
    Ok(buf)
}

fn parse_sshfp_response(bytes: &[u8]) -> Vec<SshfpRecord> {
    let Ok(msg) = Message::from_bytes(bytes) else { return vec![]; };
    msg.answers().iter()
        .filter_map(|rec| parse_sshfp_rdata(rec.data()?))
        .collect()
}

async fn query_via_doh(http: &reqwest::Client, endpoint: &str, hostname: &str) -> Result<Vec<SshfpRecord>> {
    let query_bytes = build_sshfp_query(hostname)?;
    let encoded = URL_SAFE_NO_PAD.encode(&query_bytes);
    let url = format!("{}?dns={}", endpoint, encoded);

    let resp = tokio::time::timeout(
        Duration::from_secs(6),
        http.get(&url)
            .header("accept", "application/dns-message")
            .send(),
    ).await??;

    if !resp.status().is_success() {
        anyhow::bail!("DoH {endpoint} returned {}", resp.status());
    }
    let body = resp.bytes().await?;
    Ok(parse_sshfp_response(&body))
}
