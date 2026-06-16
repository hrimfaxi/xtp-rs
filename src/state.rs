use anyhow::{Context, Result, bail};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use iptrie::{IpPrefix, Ipv4RTrieSet, Ipv6RTrieSet};
use maxminddb::Reader;
use maxminddb::geoip2::Country;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

#[allow(unused_imports)]
use tracing::{debug, error, info, trace, warn};

#[cfg(feature = "geosite")]
use geosite_rs::{GeoSite, GeoSiteList};
#[cfg(feature = "geosite")]
use prost::Message;

use crate::cli::{Config, PortForwardProto, ProxyMode, parse_listen_addr};
use crate::sniff::udp::UdpSnifferEngine;
use crate::sniff::{Sniffer, build_sniffers, build_udp_sniffers};
use crate::socket_factory::{
    SocketFactory, create_tproxy_tcp_listeners, create_tproxy_udp_sockets,
};
use crate::tcp::{run_tcp_port_forward, tcp_accept_loop};
use crate::udp::{UdpRuntime, run_udp_gc_loop, run_udp_loop, run_udp_port_forward};
use crate::upstream::{UpstreamSet, run_health_check_task};
use crate::util::{
    TaskGuard, build_ip_tries, canonical_domain, domain_matches_suffix, parse_ip_net_list,
    parse_ip_or_cidr, warn_if_splice_with_forwarding,
};

#[derive(Debug, Clone)]
pub struct DomainRouteTable {
    exact: HashMap<String, String>,
    suffixes: Vec<(String, String)>,
}

impl DomainRouteTable {
    pub fn lookup(&self, domain: &str) -> Option<&str> {
        let domain = canonical_domain(domain);
        if let Some(group) = self.exact.get(&domain) {
            return Some(group);
        }
        for (suffix, group) in &self.suffixes {
            if domain_matches_suffix(&domain, suffix) {
                return Some(group);
            }
        }
        None
    }
}

/// 基于 CIDR 最长前缀匹配的客户端路由表。
#[derive(Debug, Clone)]
pub struct ClientCidrRoutes<T: Clone> {
    v4: Vec<(Ipv4Net, T)>,
    v6: Vec<(Ipv6Net, T)>,
}

impl<T: Clone> Default for ClientCidrRoutes<T> {
    fn default() -> Self {
        Self {
            v4: Vec::new(),
            v6: Vec::new(),
        }
    }
}

impl<T: Clone> ClientCidrRoutes<T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, net: IpNet, value: T) {
        match net {
            IpNet::V4(v4) => self.v4.push((v4, value)),
            IpNet::V6(v6) => self.v6.push((v6, value)),
        }
    }

    /// 按前缀长度从大到小排序，保证 lookup 时优先命中更具体的网段。
    pub fn finalize(&mut self) {
        self.v4
            .sort_by_key(|(net, _)| std::cmp::Reverse(net.prefix_len()));
        self.v6
            .sort_by_key(|(net, _)| std::cmp::Reverse(net.prefix_len()));
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<&T> {
        match ip {
            IpAddr::V4(ip) => self
                .v4
                .iter()
                .find(|(net, _)| net.contains(&ip))
                .map(|(_, v)| v),
            IpAddr::V6(ip) => self
                .v6
                .iter()
                .find(|(net, _)| net.contains(&ip))
                .map(|(_, v)| v),
        }
    }
}

/// 客户端 IP 路由表：基于 CIDR 最长前缀匹配，映射到 upstream 分组名。
pub type ClientIpRoutes = ClientCidrRoutes<String>;

/// 客户端域名路由表：基于 CIDR 最长前缀匹配，映射到域名路由表。
pub type ClientDomainRoutes = ClientCidrRoutes<DomainRouteTable>;

pub struct AppRuntime {
    pub proxy_mode: AtomicU8,
    pub udp: Arc<UdpRuntime>,
    pub client_routes: ClientIpRoutes,
    pub client_domain_routes: ClientDomainRoutes,
}

#[cfg(feature = "geosite")]
type GeositeIndex = HashMap<String, Vec<geosite_rs::Domain>>;

pub struct AppState {
    pub mmdb: Option<Arc<Reader<Vec<u8>>>>,
    pub config: Config,
    pub config_path: String,
    pub force_direct_v4: Ipv4RTrieSet,
    pub force_direct_v6: Ipv6RTrieSet,
    pub force_socks5_v4: Ipv4RTrieSet,
    pub force_socks5_v6: Ipv6RTrieSet,
    pub sniffers: Vec<Arc<dyn Sniffer>>,
    pub udp_sniffers: Vec<Arc<dyn UdpSnifferEngine>>,
    pub upstreams: UpstreamSet,
    pub tcp_listeners: TaskGuard,
    pub udp_listeners: TaskGuard,
    pub port_forwards: TaskGuard,
    pub upstream_scores: TaskGuard,
    pub tcp_handlers: TaskGuard,
    pub health_check: TaskGuard,
    pub udp_gc: TaskGuard,
    pub runtime: Arc<AppRuntime>,
    #[cfg(feature = "geosite")]
    pub geosite: Option<Arc<GeositeIndex>>,
}

fn ipv4_trie_contains(trie: &Ipv4RTrieSet, ip: &Ipv4Addr) -> bool {
    trie.lookup(ip).len() != 0
}

fn ipv6_trie_contains(trie: &Ipv6RTrieSet, ip: &Ipv6Addr) -> bool {
    trie.lookup(ip).len() != 0
}

#[cfg(feature = "geosite")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GeositeDomainType {
    Plain,
    Regex,
    Domain,
    Full,
    Unknown(i32),
}

#[cfg(feature = "geosite")]
impl From<i32> for GeositeDomainType {
    fn from(value: i32) -> Self {
        match value {
            0 => Self::Plain,
            1 => Self::Regex,
            2 => Self::Domain,
            3 => Self::Full,
            other => Self::Unknown(other),
        }
    }
}

#[cfg(feature = "geosite")]
fn geosite_domain_match(rule: &geosite_rs::Domain, domain: &str) -> bool {
    let domain = canonical_domain(domain);
    let value = canonical_domain(&rule.value);

    match GeositeDomainType::from(rule.r#type) {
        GeositeDomainType::Plain => !value.is_empty() && domain.contains(&value),
        GeositeDomainType::Regex => false, // 不支持正则
        GeositeDomainType::Domain => domain_matches_suffix(&domain, &value),
        GeositeDomainType::Full => !value.is_empty() && domain == value,
        GeositeDomainType::Unknown(t) => {
            trace!(rule_type = t, value = %rule.value, "unknown geosite domain type");
            false
        }
    }
}

#[cfg(feature = "geosite")]
fn geosite_contains(index: &GeositeIndex, tag: &str, domain: &str) -> bool {
    let Some(rules) = index.get(&tag.to_lowercase()) else {
        return false;
    };

    rules.iter().any(|rule| geosite_domain_match(rule, domain))
}

impl AppState {
    /// geosite 是否需要域名 sniff
    pub fn need_geosite_sniff(&self) -> bool {
        #[cfg(feature = "geosite")]
        if self.geosite.is_some()
            && (!self.config.proxy_geosite_tags.is_empty()
                || !self.config.direct_geosite_tags.is_empty())
            && matches!(
                ProxyMode::from_u8(self.runtime.proxy_mode.load(Ordering::Relaxed)),
                ProxyMode::Smart,
            )
        {
            return true;
        }
        false
    }

    /// client_domain_routes 是否需要域名 sniff（只在代理路径上需要）
    pub fn need_upstream_domain_sniff(&self, client_ip: IpAddr) -> bool {
        !self.config.client_domain_routes.is_empty()
            && self
                .runtime
                .client_domain_routes
                .lookup(client_ip)
                .is_some()
    }

    /// 判断目标 IP 是否应直连。
    ///
    /// 当前运行时模式通过全局 `PROXY_MODE` 获取，
    /// 在 Global/Bypass 模式下直接短路返回，否则进入智能规则匹配。
    /// 注意：该方法依赖进程级全局状态，测试时需注意模式隔离。
    pub fn should_direct(&self, ip: IpAddr, domain: Option<&str>) -> bool {
        let mode = ProxyMode::from_u8(self.runtime.proxy_mode.load(Ordering::Relaxed));
        match mode {
            ProxyMode::Global => {
                debug!(%ip, "force proxy (global mode)");
                return false;
            }
            ProxyMode::Bypass => {
                debug!(%ip, "force direct (bypass mode)");
                return true;
            }
            ProxyMode::Smart => {}
        }

        #[cfg(not(feature = "geosite"))]
        {
            _ = domain;
        }

        // 域名规则优先
        #[cfg(feature = "geosite")]
        if let (Some(geo), Some(domain)) = (&self.geosite, domain) {
            for tag in &self.config.proxy_geosite_tags {
                if geosite_contains(geo, tag, domain) {
                    debug!(%domain, %tag, "force proxy (geosite)");
                    return false;
                }
            }
            for tag in &self.config.direct_geosite_tags {
                if geosite_contains(geo, tag, domain) {
                    debug!(%domain, %tag, "force direct (geosite)");
                    return true;
                }
            }
        }

        match ip {
            IpAddr::V4(ipv4) => {
                if ipv4_trie_contains(&self.force_socks5_v4, &ipv4) {
                    return false;
                }
                if ipv4_trie_contains(&self.force_direct_v4, &ipv4) {
                    return true;
                }
            }
            IpAddr::V6(ipv6) => {
                if ipv6_trie_contains(&self.force_socks5_v6, &ipv6) {
                    return false;
                }
                if ipv6_trie_contains(&self.force_direct_v6, &ipv6) {
                    return true;
                }
            }
        }

        (self.config.direct_local_ip && is_must_direct_local_ip(ip))
            || self.is_direct_country_ip(ip)
    }

    pub fn is_direct_country_ip(&self, ip: IpAddr) -> bool {
        let mmdb = match self.mmdb.as_ref() {
            Some(reader) => reader,
            None => return false,
        };
        let lookup_result = match mmdb.lookup(ip) {
            Ok(r) => r,
            Err(_) => return false,
        };

        let country = match lookup_result.decode::<Country>() {
            Ok(Some(c)) => c,
            _ => return false,
        };

        country
            .country
            .iso_code
            .map(|code| {
                self.config
                    .direct_countries
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(code))
            })
            .unwrap_or(false)
    }

    pub fn socks5_credentials(&self) -> Option<(&str, &str)> {
        match (&self.config.socks5_user, &self.config.socks5_password) {
            (Some(u), Some(p)) => Some((u.as_str(), p.as_str())),
            _ => None,
        }
    }

    /// 停止当前 generation 的 listener、UDP runtime 和辅助任务。
    ///
    /// reload 时不断已有 TCP 连接，只停 listener 和辅助 task。
    pub async fn shutdown_for_reload(&self, timeout: Duration) -> bool {
        let mut ok = true;
        // 1. 先停 listener / port-forward：不再 accept 新连接、不再创建新 UDP session
        ok &= self.tcp_listeners.shutdown(timeout).await;
        ok &= self.udp_listeners.shutdown(timeout).await;
        ok &= self.port_forwards.shutdown(timeout).await;

        // 2. 停 GC，避免它和 runtime shutdown 并发操作 sessions/fake_udp
        ok &= self.udp_gc.shutdown(timeout).await;

        // 3. 再清理现有 UDP session：把还在跑的 recv loop 全部 cancel
        ok &= self.runtime.udp.shutdown(timeout).await;

        // 4. 停 score task（不依赖 fd，随时可停）
        ok &= self.upstream_scores.shutdown(timeout).await;

        // 5. 最后停 health check
        ok &= self.health_check.shutdown(timeout).await;

        if !ok {
            warn!(
                "some tasks did not exit within {:?}, they were aborted",
                timeout
            );
        }

        ok
    }

    /// 进程退出时完整 shutdown，包括已 accept 的 TCP handler
    pub async fn shutdown_for_exit(&self, timeout: Duration) -> bool {
        let mut ok = self.shutdown_for_reload(timeout).await;
        ok &= self.tcp_handlers.shutdown(timeout).await;
        ok
    }

    /// 从 Config 从头构建，MMDB 也重新加载
    pub async fn build(config: Config, config_path: String) -> Result<Self> {
        warn_if_splice_with_forwarding(config.splice).await;

        let mmdb = match config.mmdb_path.as_deref() {
            Some("") | None => {
                info!("MMDB is disabled");
                None
            }
            Some(path) => {
                let data = tokio::fs::read(path)
                    .await
                    .with_context(|| format!("failed to read MMDB file {}", path))?;
                let reader = Reader::from_source(data).context("invalid MMDB data")?;
                info!(path = %path, "MMDB loaded");
                Some(Arc::new(reader))
            }
        };

        let mut direct_list = config.force_direct_ips.clone();
        if let Some(ref p) = config.force_direct_ips_file {
            let content = tokio::fs::read_to_string(p)
                .await
                .with_context(|| format!("failed to read force_direct_ips_file '{}'", p))?;
            direct_list.extend(
                content
                    .lines()
                    .filter(|l| !l.trim().is_empty())
                    .map(|l| l.trim().to_string()),
            );
        }

        let mut socks5_list = config.force_socks5_ips.clone();
        if let Some(ref p) = config.force_socks5_ips_file {
            let content = tokio::fs::read_to_string(p)
                .await
                .with_context(|| format!("failed to read force_socks5_ips_file '{}'", p))?;
            socks5_list.extend(
                content
                    .lines()
                    .filter(|l| !l.trim().is_empty())
                    .map(|l| l.trim().to_string()),
            );
        }

        let direct_nets =
            parse_ip_net_list(&direct_list).context("failed to parse force_direct_ips")?;
        let socks5_nets =
            parse_ip_net_list(&socks5_list).context("failed to parse force_socks5_ips")?;
        let (force_direct_v4, force_direct_v6) =
            build_ip_tries(&direct_nets).context("failed to build force_direct tries")?;
        let (force_socks5_v4, force_socks5_v6) =
            build_ip_tries(&socks5_nets).context("failed to build force_socks5 tries")?;

        let sniffers = build_sniffers(&config);
        let udp_sniffers = build_udp_sniffers(&config);
        let upstreams = config.build_upstream_set()?;

        let udp_runtime = Arc::new(UdpRuntime::new(Duration::from_secs(
            config.udp_session_timeout_secs,
        )));

        let proxy_mode = config.proxy_mode.as_u8();

        #[cfg(feature = "geosite")]
        let geosite: Option<Arc<GeositeIndex>> = if let Some(ref path) = config.geosite_path {
            use std::collections::HashSet;

            // Read the geosite.dat file
            let data = tokio::fs::read(path)
                .await
                .with_context(|| format!("failed to read geosite file: {}", path))?;

            // Decode the entire dataset
            let full = GeoSiteList::decode(data.as_slice())
                .with_context(|| "failed to decode geosite data")?;

            if tracing::enabled!(tracing::Level::TRACE) {
                for entry in &full.entry {
                    trace!("available geosite tag: {}", entry.country_code);
                }
            }

            // Collect needed tags (case‑insensitive)
            let needed_lower: HashSet<String> = config
                .proxy_geosite_tags
                .iter()
                .chain(config.direct_geosite_tags.iter())
                .map(|s| s.to_lowercase())
                .collect();

            // Filter entries: keep only those whose tag matches (case‑insensitive)
            let filtered_entries: Vec<GeoSite> = full
                .entry
                .into_iter()
                .filter(|e| needed_lower.contains(&e.country_code.to_lowercase()))
                .collect();

            // Warn about tags that were configured but not found in the data
            for tag in &config.proxy_geosite_tags {
                if !filtered_entries
                    .iter()
                    .any(|e| e.country_code.eq_ignore_ascii_case(tag))
                {
                    warn!("geosite tag not found in data: {}", tag);
                }
            }
            for tag in &config.direct_geosite_tags {
                if !filtered_entries
                    .iter()
                    .any(|e| e.country_code.eq_ignore_ascii_case(tag))
                {
                    warn!("geosite tag not found in data: {}", tag);
                }
            }

            let index: GeositeIndex = filtered_entries
                .into_iter()
                .map(|entry| (entry.country_code.to_lowercase(), entry.domain))
                .collect();

            Some(Arc::new(index))
        } else {
            None
        };

        #[cfg(not(feature = "geosite"))]
        {
            if config.geosite_path.is_some()
                || !config.proxy_geosite_tags.is_empty()
                || !config.direct_geosite_tags.is_empty()
            {
                warn!(
                    "geosite support is not compiled in, but geosite config is present; ignoring all geosite rules"
                );
            }
        }

        #[cfg(feature = "geosite")]
        if config.geosite_path.is_none()
            && (!config.proxy_geosite_tags.is_empty() || !config.direct_geosite_tags.is_empty())
        {
            warn!(
                "geosite tags are configured but geosite_path is empty; geosite routing is disabled"
            );
        }

        let client_routes = {
            let mut routes = ClientIpRoutes::new();
            for (ip_str, group) in &config.client_routes {
                let net = parse_ip_or_cidr(ip_str)
                    .with_context(|| format!("invalid client_routes ip/cidr '{}'", ip_str))?;
                routes.insert(net, group.clone());
            }
            routes.finalize();
            routes
        };

        let client_domain_routes = {
            let mut routes = ClientDomainRoutes::new();
            for (ip_str, domain_map) in &config.client_domain_routes {
                let net = parse_ip_or_cidr(ip_str).with_context(|| {
                    format!("invalid client_domain_routes ip/cidr '{}'", ip_str)
                })?;

                let mut exact = HashMap::new();
                let mut suffixes = Vec::new();
                for (domain_key, group) in domain_map {
                    if let Some(stripped) = domain_key.strip_prefix('.') {
                        let suffix_norm = canonical_domain(stripped);
                        if suffix_norm.is_empty() {
                            bail!(
                                "empty suffix domain pattern '{}' in client_domain_routes for IP '{}'",
                                domain_key,
                                ip_str
                            );
                        }
                        suffixes.push((suffix_norm, group.clone()));
                    } else {
                        let exact_norm = canonical_domain(domain_key);
                        if exact_norm.is_empty() {
                            bail!(
                                "empty exact domain pattern '{}' in client_domain_routes for IP '{}'",
                                domain_key,
                                ip_str
                            );
                        }
                        exact.insert(exact_norm, group.clone());
                    }
                }
                // 按后缀长度降序，保证最长匹配优先
                suffixes.sort_by_key(|b| std::cmp::Reverse(b.0.len()));
                routes.insert(net, DomainRouteTable { exact, suffixes });
            }
            routes.finalize();
            routes
        };

        Ok(AppState {
            mmdb,
            config,
            config_path,
            force_direct_v4,
            force_direct_v6,
            force_socks5_v4,
            force_socks5_v6,
            sniffers,
            udp_sniffers,
            upstreams,
            tcp_listeners: TaskGuard::new(),
            udp_listeners: TaskGuard::new(),
            port_forwards: TaskGuard::new(),
            upstream_scores: TaskGuard::new(),
            tcp_handlers: TaskGuard::new(),
            health_check: TaskGuard::new(),
            udp_gc: TaskGuard::new(),
            runtime: Arc::new(AppRuntime {
                proxy_mode: AtomicU8::new(proxy_mode),
                udp: udp_runtime,
                client_routes,
                client_domain_routes,
            }),
            #[cfg(feature = "geosite")]
            geosite,
        })
    }

    /// 使用 &Arc<Self> 保证 self 就是任务所属的 generation
    pub async fn spawn_all_tasks(self: &Arc<Self>) -> Result<()> {
        self.spawn_listener_tasks()?;
        self.spawn_port_forward_tasks().await?;

        if self.config.health_check_interval_secs > 0 {
            let state = Arc::clone(self);
            self.health_check
                .spawn(|cancel| run_health_check_task(state, cancel));
        }

        if !self.config.disable_upstream_score {
            for up in self.upstreams.iter() {
                let up = up.clone();
                self.upstream_scores
                    .spawn(|cancel| up.run_score_task(cancel));
            }
        }

        let state = Arc::clone(self);
        self.udp_gc.spawn(|cancel| async move {
            run_udp_gc_loop(state, cancel).await;
        });

        Ok(())
    }

    fn spawn_listener_tasks(self: &Arc<Self>) -> Result<()> {
        let (listen_ip, listen_port) =
            parse_listen_addr(&self.config.listen).context("invalid listen address")?;
        let (tcp_v4, tcp_v6) = create_tproxy_tcp_listeners(listen_ip, listen_port)?;

        if let Some(l) = tcp_v4 {
            info!("TPROXY TCP (IPv4) on 0.0.0.0:{}", listen_port);
            let state = Arc::clone(self);
            self.tcp_listeners
                .spawn(|cancel| async move { tcp_accept_loop(l, state, cancel).await });
        }

        if let Some(l) = tcp_v6 {
            info!("TPROXY TCP (IPv6) on [::]:{}", listen_port);
            let state = Arc::clone(self);
            self.tcp_listeners
                .spawn(|cancel| async move { tcp_accept_loop(l, state, cancel).await });
        }

        if self.config.udp {
            let (udp_v4, udp_v6) = create_tproxy_udp_sockets(listen_ip, listen_port)?;

            if let Some(sock) = udp_v4 {
                info!("TPROXY UDP (IPv4) on 0.0.0.0:{}", listen_port);
                let state = Arc::clone(self);
                self.udp_listeners.spawn(|cancel| async move {
                    if let Err(e) = run_udp_loop(state, sock, cancel).await {
                        error!(
                            error = format!("{:#}", e),
                            "IPv4 UDP loop exited with error"
                        );
                    }
                });
            }

            if let Some(sock) = udp_v6 {
                info!("TPROXY UDP (IPv6) on [::]:{}", listen_port);
                let state = Arc::clone(self);
                self.udp_listeners.spawn(|cancel| async move {
                    if let Err(e) = run_udp_loop(state, sock, cancel).await {
                        error!(
                            error = format!("{:#}", e),
                            "IPv6 UDP loop exited with error"
                        );
                    }
                });
            }
        }

        Ok(())
    }

    async fn spawn_port_forward_tasks(self: &Arc<Self>) -> Result<()> {
        // 阶段1：先 bind 所有 socket，任一失败都不进入阶段2
        enum Prepared {
            Tcp {
                listener: tokio::net::TcpListener,
                remote: SocketAddr,
                name: String,
            },
            Udp {
                socket: Arc<tokio::net::UdpSocket>,
                bind: SocketAddr,
                remote: SocketAddr,
                name: String,
            },
            Both {
                tcp_listener: tokio::net::TcpListener,
                udp_socket: Arc<tokio::net::UdpSocket>,
                bind: SocketAddr,
                remote: SocketAddr,
                name: String,
            },
        }

        let mut prepared = Vec::with_capacity(self.config.port_forward.len());

        for pf in &self.config.port_forward {
            let bind_addr: SocketAddr = pf
                .bind
                .parse()
                .with_context(|| format!("invalid port-forward bind '{}'", pf.bind))?;
            let remote_addr: SocketAddr = pf
                .remote
                .parse()
                .with_context(|| format!("invalid port-forward remote '{}'", pf.remote))?;
            let name = pf.name.clone().unwrap_or_default();

            match pf.network {
                PortForwardProto::Tcp => {
                    let listener = SocketFactory::new()
                        .bind_tcp_listener(
                            bind_addr, true,  // reuse_addr
                            false, // transparent
                            None,  // only_v6
                            1024,  // backlog
                        )
                        .with_context(|| format!("port-forward TCP bind {}", bind_addr))?;
                    prepared.push(Prepared::Tcp {
                        listener,
                        remote: remote_addr,
                        name,
                    });
                }
                PortForwardProto::Udp => {
                    let socket = SocketFactory::new()
                        .bind_port_forward_udp_listener(bind_addr)
                        .with_context(|| format!("port-forward UDP bind {}", bind_addr))?;
                    prepared.push(Prepared::Udp {
                        socket,
                        bind: bind_addr,
                        remote: remote_addr,
                        name,
                    });
                }
                PortForwardProto::Both => {
                    let tcp_listener = SocketFactory::new()
                        .bind_tcp_listener(bind_addr, true, false, None, 1024)
                        .with_context(|| format!("port-forward TCP bind {}", bind_addr))?;
                    let udp_socket = SocketFactory::new()
                        .bind_port_forward_udp_listener(bind_addr)
                        .with_context(|| format!("port-forward UDP bind {}", bind_addr))?;
                    prepared.push(Prepared::Both {
                        tcp_listener,
                        udp_socket,
                        bind: bind_addr,
                        remote: remote_addr,
                        name,
                    });
                }
            }
        }

        // 阶段2：全部 bind 成功后再统一 spawn，避免半启动
        for p in prepared {
            match p {
                Prepared::Tcp {
                    listener,
                    remote,
                    name,
                } => {
                    let state = Arc::clone(self);
                    self.port_forwards.spawn(|cancel| async move {
                        if let Err(e) = run_tcp_port_forward(listener, remote, state, cancel).await
                        {
                            error!(name = %name, error = format!("{:#}", e), "port-forward TCP error");
                        }
                    });
                }
                Prepared::Udp {
                    socket,
                    bind,
                    remote,
                    name,
                } => {
                    let state = Arc::clone(self);
                    self.port_forwards.spawn(|cancel| async move {
                        if let Err(e) =
                            run_udp_port_forward(socket, bind, remote, state, cancel).await
                        {
                            error!(name = %name, error = format!("{:#}", e), "port-forward UDP error");
                        }
                    });
                }
                Prepared::Both {
                    tcp_listener,
                    udp_socket,
                    bind,
                    remote,
                    name,
                } => {
                    let state_tcp = Arc::clone(self);
                    let state_udp = Arc::clone(self);
                    let name_tcp = name.clone();
                    let name_udp = name;

                    self.port_forwards.spawn(|cancel| async move {
                        if let Err(e) =
                            run_tcp_port_forward(tcp_listener, remote, state_tcp, cancel).await
                        {
                            error!(name = %name_tcp, error = format!("{:#}", e), "port-forward TCP(both) error");
                        }
                    });
                    self.port_forwards.spawn(|cancel| async move {
                        if let Err(e) =
                            run_udp_port_forward(udp_socket, bind, remote, state_udp, cancel).await
                        {
                            error!(name = %name_udp, error = format!("{:#}", e), "port-forward UDP(both) error");
                        }
                    });
                }
            }
        }

        Ok(())
    }
}

pub fn is_must_direct_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_must_direct_local_ipv4(ip),
        IpAddr::V6(ip) => is_must_direct_local_ipv6(ip),
    }
}

fn is_must_direct_local_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_loopback() || ip.is_link_local() || ip.is_broadcast() || ip.is_unspecified()
}

fn is_must_direct_local_ipv6(ip: Ipv6Addr) -> bool {
    ip.is_loopback() || ip.is_unspecified() || ip.is_unicast_link_local()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::UpstreamConfig;
    use crate::upstream::Upstream;
    use std::net::IpAddr;

    #[test]
    fn local_ipv4_loopback() {
        assert!(is_must_direct_local_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn local_ipv4_link_local() {
        assert!(is_must_direct_local_ip(IpAddr::V4(Ipv4Addr::new(
            169, 254, 1, 1
        ))));
    }

    #[test]
    fn local_ipv4_broadcast() {
        assert!(is_must_direct_local_ip(IpAddr::V4(Ipv4Addr::BROADCAST)));
    }

    #[test]
    fn local_ipv4_unspecified() {
        assert!(is_must_direct_local_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    }

    #[test]
    fn local_ipv6_loopback() {
        assert!(is_must_direct_local_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn local_ipv6_unspecified() {
        assert!(is_must_direct_local_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    }

    #[test]
    fn local_ipv6_link_local() {
        let ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        assert!(is_must_direct_local_ip(IpAddr::V6(ip)));
    }

    #[test]
    fn not_local_public_ip() {
        assert!(!is_must_direct_local_ip(IpAddr::V4(Ipv4Addr::new(
            8, 8, 8, 8
        ))));
        assert!(!is_must_direct_local_ip(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888
        ))));
    }

    // Helper to create a minimal AppState for should_direct tests
    fn minimal_app_state() -> AppState {
        let upstream = Upstream::new(
            "test",
            "127.0.0.1:1080".parse().unwrap(),
            vec!["default".to_string()],
        );
        let upstreams = UpstreamSet::new(vec![upstream], 0, 70).unwrap();
        let udp_runtime = Arc::new(UdpRuntime::new(Duration::from_secs(60)));
        AppState {
            mmdb: None,
            config: Config {
                direct_local_ip: true,
                ..create_test_config()
            },
            config_path: String::new(),
            force_direct_v4: Ipv4RTrieSet::new(),
            force_direct_v6: Ipv6RTrieSet::new(),
            force_socks5_v4: Ipv4RTrieSet::new(),
            force_socks5_v6: Ipv6RTrieSet::new(),
            sniffers: vec![],
            udp_sniffers: vec![],
            upstreams,
            tcp_listeners: TaskGuard::new(),
            udp_listeners: TaskGuard::new(),
            port_forwards: TaskGuard::new(),
            upstream_scores: TaskGuard::new(),
            tcp_handlers: TaskGuard::new(),
            health_check: TaskGuard::new(),
            udp_gc: TaskGuard::new(),
            runtime: Arc::new(AppRuntime {
                proxy_mode: AtomicU8::new(ProxyMode::Smart.as_u8()),
                udp: udp_runtime,
                client_routes: ClientIpRoutes::new(),
                client_domain_routes: ClientDomainRoutes::new(),
            }),
            #[cfg(feature = "geosite")]
            geosite: None,
        }
    }

    fn create_test_config() -> Config {
        Config {
            listen: "[::]:10810".into(),
            udp: true,
            socks5_user: None,
            socks5_password: None,
            fwmark: 2,
            mmdb_path: None,
            udp_session_timeout_secs: 60,
            splice: false,
            sniff_tls_sni: false,
            sniff_http_host: false,
            sniff_quic_sni: false,
            tcp_peek_buffer_size: 32 * 1024,
            tls_sniff_peek_len: 2048,
            tls_sniff_max_len: 32 * 1024,
            tls_sniff_max_retries: 5,
            tls_sniff_wait_more_ms: 100,
            tls_sniff_timeout_ms: 1000,
            http_sniff_peek_len: 512,
            http_sniff_max_len: 16 * 1024,
            http_sniff_max_retries: 5,
            http_sniff_wait_more_ms: 100,
            http_sniff_timeout_ms: 1000,
            log_level: None,
            direct_countries: vec![],
            force_direct_ips: vec![],
            force_socks5_ips: vec![],
            force_direct_ips_file: None,
            force_socks5_ips_file: None,
            port_forward: vec![],
            direct_local_ip: true,
            upstream: vec![UpstreamConfig {
                id: "test".into(),
                addr: "127.0.0.1:1080".parse().unwrap(),
                groups: None,
            }],
            disable_upstream_score: false,
            upstream_switch_tolerance: 0,
            health_check_interval_secs: 0,
            health_check_timeout_secs: 5,
            health_check_fail_threshold: 2,
            health_check_url: "cp.cloudflare.com".into(),
            quic_weight: 70,
            proxy_mode: ProxyMode::default(),
            geosite_path: None,
            direct_geosite_tags: vec![],
            proxy_geosite_tags: vec![],
            client_routes: HashMap::new(),
            client_domain_routes: HashMap::new(),
            connect_timeout_secs: 20,
        }
    }

    #[test]
    fn should_direct_local_with_flag_true() {
        let state = minimal_app_state();
        assert!(state.should_direct(IpAddr::V4(Ipv4Addr::LOCALHOST), None));
        assert!(state.should_direct(IpAddr::V6(Ipv6Addr::LOCALHOST), None));
    }

    // For brevity, we demonstrate one direct test; extending to other cases is similar
    #[test]
    fn should_direct_force_socks5_has_higher_priority() {
        // build state with force_socks5_ips containing 8.8.8.8
        let socks5_nets = parse_ip_net_list(&["8.8.8.8".to_string()]).unwrap();
        let (_, _) = build_ip_tries(&socks5_nets).unwrap(); // returns v4, v6 tries
        let (force_socks5_v4, _) = build_ip_tries(&socks5_nets).unwrap();
        let state = AppState {
            force_socks5_v4,
            force_socks5_v6: Ipv6RTrieSet::new(),
            ..minimal_app_state()
        };
        assert!(!state.should_direct(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), None));
    }

    #[test]
    fn force_socks5_has_higher_priority_than_force_direct() {
        let nets = parse_ip_net_list(&["8.8.8.8".to_string()]).unwrap();
        let (v4, v6) = build_ip_tries(&nets).unwrap();
        let mut state = minimal_app_state();
        state.force_direct_v4 = v4.clone();
        state.force_direct_v6 = v6.clone();
        state.force_socks5_v4 = v4;
        state.force_socks5_v6 = v6;
        assert!(!state.should_direct("8.8.8.8".parse().unwrap(), None));
    }

    #[test]
    fn force_direct_returns_true() {
        let nets = parse_ip_net_list(&["8.8.8.8".to_string()]).unwrap();
        let (v4, v6) = build_ip_tries(&nets).unwrap();
        let mut state = minimal_app_state();
        state.force_direct_v4 = v4;
        state.force_direct_v6 = v6;
        assert!(state.should_direct("8.8.8.8".parse().unwrap(), None));
    }

    #[test]
    fn local_ip_not_direct_when_flag_false() {
        let mut state = minimal_app_state();
        state.config.direct_local_ip = false;
        assert!(!state.should_direct(IpAddr::V4(Ipv4Addr::LOCALHOST), None));
    }

    #[test]
    fn client_ip_routes_exact_ip_match() {
        let mut routes = ClientIpRoutes::new();
        routes.insert("192.168.1.10/32".parse::<IpNet>().unwrap(), "a".to_string());
        routes.finalize();

        assert_eq!(
            routes.lookup("192.168.1.10".parse::<IpAddr>().unwrap()),
            Some(&"a".to_string())
        );
        assert_eq!(
            routes.lookup("192.168.1.11".parse::<IpAddr>().unwrap()),
            None
        );
    }

    #[test]
    fn client_ip_routes_cidr_match() {
        let mut routes = ClientIpRoutes::new();
        routes.insert(
            "192.168.1.0/24".parse::<IpNet>().unwrap(),
            "lan".to_string(),
        );
        routes.finalize();

        assert_eq!(
            routes.lookup("192.168.1.55".parse::<IpAddr>().unwrap()),
            Some(&"lan".to_string())
        );
        assert_eq!(
            routes.lookup("192.168.2.1".parse::<IpAddr>().unwrap()),
            None
        );
    }

    #[test]
    fn client_ip_routes_longest_prefix_match() {
        let mut routes = ClientIpRoutes::new();
        routes.insert(
            "192.168.0.0/16".parse::<IpNet>().unwrap(),
            "broad".to_string(),
        );
        routes.insert(
            "192.168.1.0/24".parse::<IpNet>().unwrap(),
            "narrow".to_string(),
        );
        routes.finalize();

        assert_eq!(
            routes.lookup("192.168.1.42".parse::<IpAddr>().unwrap()),
            Some(&"narrow".to_string())
        );
        assert_eq!(
            routes.lookup("192.168.2.42".parse::<IpAddr>().unwrap()),
            Some(&"broad".to_string())
        );
    }

    #[test]
    fn client_ip_routes_ipv6_match() {
        let mut routes = ClientIpRoutes::new();
        routes.insert("2001:db8::/32".parse::<IpNet>().unwrap(), "v6".to_string());
        routes.finalize();

        assert_eq!(
            routes.lookup("2001:db8::1".parse::<IpAddr>().unwrap()),
            Some(&"v6".to_string())
        );
        assert_eq!(
            routes.lookup("2001:dead::1".parse::<IpAddr>().unwrap()),
            None
        );
    }

    #[test]
    fn client_domain_routes_exact_ip_match() {
        let mut routes = ClientDomainRoutes::new();
        let mut exact = HashMap::new();
        exact.insert("example.com".to_string(), "group_a".to_string());
        routes.insert(
            "192.168.1.10/32".parse::<IpNet>().unwrap(),
            DomainRouteTable {
                exact,
                suffixes: vec![],
            },
        );
        routes.finalize();

        assert_eq!(
            routes
                .lookup("192.168.1.10".parse::<IpAddr>().unwrap())
                .and_then(|t| t.lookup("example.com")),
            Some("group_a")
        );
        assert_eq!(
            routes
                .lookup("192.168.1.11".parse::<IpAddr>().unwrap())
                .and_then(|t| t.lookup("example.com")),
            None
        );
    }

    #[test]
    fn client_domain_routes_cidr_suffix_match() {
        let mut routes = ClientDomainRoutes::new();
        let suffixes = vec![("google.com".to_string(), "group_b".to_string())];
        routes.insert(
            "192.168.1.0/24".parse::<IpNet>().unwrap(),
            DomainRouteTable {
                exact: HashMap::new(),
                suffixes,
            },
        );
        routes.finalize();

        assert_eq!(
            routes
                .lookup("192.168.1.55".parse::<IpAddr>().unwrap())
                .and_then(|t| t.lookup("www.google.com")),
            Some("group_b")
        );
        assert_eq!(
            routes
                .lookup("192.168.2.1".parse::<IpAddr>().unwrap())
                .and_then(|t| t.lookup("www.google.com")),
            None
        );
    }

    #[test]
    fn client_domain_routes_longest_prefix_match() {
        let mut routes = ClientDomainRoutes::new();
        let mut exact1 = HashMap::new();
        exact1.insert("youtube.com".to_string(), "broad".to_string());
        routes.insert(
            "192.168.0.0/16".parse::<IpNet>().unwrap(),
            DomainRouteTable {
                exact: exact1,
                suffixes: vec![],
            },
        );

        let mut exact2 = HashMap::new();
        exact2.insert("youtube.com".to_string(), "narrow".to_string());
        routes.insert(
            "192.168.1.0/24".parse::<IpNet>().unwrap(),
            DomainRouteTable {
                exact: exact2,
                suffixes: vec![],
            },
        );
        routes.finalize();

        assert_eq!(
            routes
                .lookup("192.168.1.42".parse::<IpAddr>().unwrap())
                .and_then(|t| t.lookup("youtube.com")),
            Some("narrow")
        );
        assert_eq!(
            routes
                .lookup("192.168.2.42".parse::<IpAddr>().unwrap())
                .and_then(|t| t.lookup("youtube.com")),
            Some("broad")
        );
    }

    #[test]
    fn client_domain_routes_canonicalization() {
        let mut routes = ClientDomainRoutes::new();
        let mut exact = HashMap::new();
        exact.insert("example.com".to_string(), "group_x".to_string());
        routes.insert(
            "10.0.0.0/8".parse::<IpNet>().unwrap(),
            DomainRouteTable {
                exact,
                suffixes: vec![],
            },
        );
        routes.finalize();

        assert_eq!(
            routes
                .lookup("10.0.0.1".parse::<IpAddr>().unwrap())
                .and_then(|t| t.lookup("Example.COM")),
            Some("group_x")
        );
        assert_eq!(
            routes
                .lookup("10.0.0.1".parse::<IpAddr>().unwrap())
                .and_then(|t| t.lookup("EXAMPLE.COM.")),
            Some("group_x")
        );
    }

    #[test]
    fn client_domain_routes_suffix_priority() {
        let mut routes = ClientDomainRoutes::new();
        let suffixes = vec![
            ("google.com".to_string(), "g1".to_string()),
            ("com".to_string(), "g2".to_string()),
        ];
        routes.insert(
            "10.0.0.0/8".parse::<IpNet>().unwrap(),
            DomainRouteTable {
                exact: HashMap::new(),
                suffixes,
            },
        );
        routes.finalize();

        assert_eq!(
            routes
                .lookup("10.0.0.1".parse::<IpAddr>().unwrap())
                .and_then(|t| t.lookup("www.google.com")),
            Some("g1")
        );
        assert_eq!(
            routes
                .lookup("10.0.0.1".parse::<IpAddr>().unwrap())
                .and_then(|t| t.lookup("example.com")),
            Some("g2")
        );
    }

    #[test]
    fn client_domain_routes_ipv6_match() {
        let mut routes = ClientDomainRoutes::new();
        let mut exact = HashMap::new();
        exact.insert("test.com".to_string(), "v6".to_string());
        routes.insert(
            "2001:db8::/32".parse::<IpNet>().unwrap(),
            DomainRouteTable {
                exact,
                suffixes: vec![],
            },
        );
        routes.finalize();

        assert_eq!(
            routes
                .lookup("2001:db8::1".parse::<IpAddr>().unwrap())
                .and_then(|t| t.lookup("test.com")),
            Some("v6")
        );
        assert_eq!(
            routes
                .lookup("2001:dead::1".parse::<IpAddr>().unwrap())
                .and_then(|t| t.lookup("test.com")),
            None
        );
    }
}
