use anyhow::{Context, Result};
use iptrie::{IpPrefix, Ipv4RTrieSet, Ipv6RTrieSet};
use maxminddb::Reader;
use maxminddb::geoip2::Country;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

use crate::cli::{Config, PortForwardProto, parse_listen_addr};
use crate::sniff::udp::UdpSnifferEngine;
use crate::sniff::{Sniffer, build_sniffers, build_udp_sniffers};
use crate::socket_factory::{
    SocketFactory, create_tproxy_tcp_listeners, create_tproxy_udp_sockets,
};
use crate::tcp::{run_tcp_port_forward, tcp_accept_loop};
use crate::udp::{UdpRuntime, run_udp_gc_loop, run_udp_loop, run_udp_port_forward};
use crate::upstream::{UpstreamSet, run_health_check_task};
use crate::util::{TaskGuard, build_ip_tries, parse_ip_net_list, warn_if_splice_with_forwarding};

pub struct AppState {
    pub mmdb: Option<Arc<Reader<Vec<u8>>>>,
    pub config: Config,
    pub config_path: String,
    pub udp_runtime: Arc<UdpRuntime>,
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
}

fn ipv4_trie_contains(trie: &Ipv4RTrieSet, ip: &Ipv4Addr) -> bool {
    trie.lookup(ip).len() != 0
}

fn ipv6_trie_contains(trie: &Ipv6RTrieSet, ip: &Ipv6Addr) -> bool {
    trie.lookup(ip).len() != 0
}

impl AppState {
    pub fn should_direct(&self, ip: IpAddr) -> bool {
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
        ok &= self.udp_runtime.shutdown(timeout).await;

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
        warn_if_splice_with_forwarding(config.splice);
        validate_port_forward_binds(&config)?;

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
                info!("MMDB loaded from {}", path);
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

        Ok(AppState {
            mmdb,
            config,
            config_path,
            udp_runtime,
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
                        error!("IPv4 UDP loop exited with error: {:#}", e);
                    }
                });
            }

            if let Some(sock) = udp_v6 {
                info!("TPROXY UDP (IPv6) on [::]:{}", listen_port);
                let state = Arc::clone(self);
                self.udp_listeners.spawn(|cancel| async move {
                    if let Err(e) = run_udp_loop(state, sock, cancel).await {
                        error!("IPv6 UDP loop exited with error: {:#}", e);
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
                            error!("port-forward TCP {name} error: {:#}", e);
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
                            error!("port-forward UDP {name} error: {:#}", e);
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
                            error!("port-forward TCP(both) {name_tcp} error: {:#}", e);
                        }
                    });
                    self.port_forwards.spawn(|cancel| async move {
                        if let Err(e) =
                            run_udp_port_forward(udp_socket, bind, remote, state_udp, cancel).await
                        {
                            error!("port-forward UDP(both) {name_udp} error: {:#}", e);
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

fn validate_port_forward_binds(config: &Config) -> Result<()> {
    use std::collections::HashSet;

    let mut tcp_binds = HashSet::new();
    let mut udp_binds = HashSet::new();

    for pf in &config.port_forward {
        let bind: SocketAddr = pf
            .bind
            .parse()
            .with_context(|| format!("invalid port-forward bind '{}'", pf.bind))?;

        match pf.network {
            PortForwardProto::Tcp => {
                if !tcp_binds.insert(bind) {
                    anyhow::bail!("duplicate TCP port-forward bind: {}", bind);
                }
            }
            PortForwardProto::Udp => {
                if !udp_binds.insert(bind) {
                    anyhow::bail!("duplicate UDP port-forward bind: {}", bind);
                }
            }
            PortForwardProto::Both => {
                if !tcp_binds.insert(bind) {
                    anyhow::bail!("duplicate TCP port-forward bind: {}", bind);
                }
                if !udp_binds.insert(bind) {
                    anyhow::bail!("duplicate UDP port-forward bind: {}", bind);
                }
            }
        }
    }

    Ok(())
}

fn is_must_direct_local_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_loopback() || ip.is_link_local() || ip.is_broadcast() || ip.is_unspecified()
}

fn is_must_direct_local_ipv6(ip: Ipv6Addr) -> bool {
    ip.is_loopback() || ip.is_unspecified() || ip.is_unicast_link_local()
}
