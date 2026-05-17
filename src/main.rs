mod cli;
mod sniff;
mod socket_factory;
mod socks5;
mod state;
mod tcp;
mod udp;
mod upstream;
mod util;

use anyhow::{Context, Result};
use clap::Parser;
use maxminddb::Reader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info};

use crate::cli::{Cli, Config, PortForwardProto, parse_listen_addr};
use crate::sniff::{build_sniffers, build_udp_sniffers};
use crate::socket_factory::{create_tproxy_tcp_listeners, create_tproxy_udp_sockets};
use crate::state::AppState;
use crate::tcp::{run_tcp_port_forward, tcp_accept_loop};
use crate::udp::{UdpRuntime, run_udp_gc_loop, run_udp_loop, run_udp_port_forward};
use crate::upstream::run_upstream_stats_listener;
use crate::util::{build_ip_tries, parse_ip_net_list, warn_if_splice_with_forwarding};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let config_str = tokio::fs::read_to_string(&cli.config)
        .await
        .with_context(|| format!("failed to read config file {}", cli.config))?;

    let config: Config = toml::from_str(&config_str).context("invalid config")?;

    let env_filter = if let Some(ref level) = config.log_level {
        tracing_subscriber::EnvFilter::new(level)
    } else {
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into())
    };

    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    debug!("xtp-rs started");

    warn_if_splice_with_forwarding(config.splice);

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

    let udp_runtime = Arc::new(UdpRuntime::new(Duration::from_secs(
        config.udp_session_timeout_secs,
    )));

    let (listen_ip, listen_port) =
        parse_listen_addr(&config.listen).context("invalid listen address")?;

    let mut direct_list = config.force_direct_ips.clone();
    if let Some(ref path) = config.force_direct_ips_file {
        let content = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("failed to read force_direct_ips_file '{}'", path))?;
        direct_list.extend(
            content
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| l.trim().to_string()),
        );
    }

    let mut socks5_list = config.force_socks5_ips.clone();
    if let Some(ref path) = config.force_socks5_ips_file {
        let content = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("failed to read force_socks5_ips_file '{}'", path))?;
        socks5_list.extend(
            content
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| l.trim().to_string()),
        );
    }

    let direct_nets =
        parse_ip_net_list(&direct_list).context("failed to parse force_direct_ips")?;
    info!("force_direct_ips: {} entries loaded", direct_nets.len());
    let socks5_nets =
        parse_ip_net_list(&socks5_list).context("failed to parse force_socks5_ips")?;
    info!("force_socks5_ips: {} entries loaded", socks5_nets.len());

    let (force_direct_v4, force_direct_v6) =
        build_ip_tries(&direct_nets).context("failed to build force_direct tries")?;
    let (force_socks5_v4, force_socks5_v6) =
        build_ip_tries(&socks5_nets).context("failed to build force_socks5 tries")?;

    let sniffers = build_sniffers(&config);
    let udp_sniffers = build_udp_sniffers(&config);

    let upstreams = config.build_upstream_set()?;

    let state = Arc::new(AppState {
        mmdb: mmdb.clone(),
        config,
        udp_runtime,
        force_direct_v4,
        force_direct_v6,
        force_socks5_v4,
        force_socks5_v6,
        sniffers,
        udp_sniffers,
        upstreams,
    });

    let (tcp_v4, tcp_v6) = create_tproxy_tcp_listeners(listen_ip, listen_port)?;

    if let Some(l) = tcp_v4 {
        info!("TPROXY TCP (IPv4) on 0.0.0.0:{}", listen_port);
        let state = state.clone();
        tokio::spawn(async move { tcp_accept_loop(l, state).await });
    }

    if let Some(l) = tcp_v6 {
        info!("TPROXY TCP (IPv6) on [::]:{}", listen_port);
        let state = state.clone();
        tokio::spawn(async move { tcp_accept_loop(l, state).await });
    }

    let (udp_v4, udp_v6) = if state.config.udp {
        create_tproxy_udp_sockets(listen_ip, listen_port)?
    } else {
        (None, None)
    };

    if let Some(sock) = udp_v4 {
        info!("TPROXY UDP (IPv4) on 0.0.0.0:{}", listen_port);
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = run_udp_loop(state, sock).await {
                error!("IPv4 UDP loop exited with error: {:#}", e);
            }
        });
    }

    if let Some(sock) = udp_v6 {
        info!("TPROXY UDP (IPv6) on [::]:{}", listen_port);
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = run_udp_loop(state, sock).await {
                error!("IPv6 UDP loop exited with error: {:#}", e);
            }
        });
    }

    for pf in &state.config.port_forward {
        let bind_addr: SocketAddr = pf
            .bind
            .parse()
            .with_context(|| format!("invalid port-forward bind '{}'", pf.bind))?;
        let remote_addr: SocketAddr = pf
            .remote
            .parse()
            .with_context(|| format!("invalid port-forward remote '{}'", pf.remote))?;
        let state = state.clone();
        let name = pf.name.clone().unwrap_or_default();

        match pf.network {
            PortForwardProto::Tcp => {
                tokio::spawn(async move {
                    if let Err(e) = run_tcp_port_forward(bind_addr, remote_addr, state).await {
                        error!("port-forward TCP {name} error: {:#}", e);
                    }
                });
            }
            PortForwardProto::Udp => {
                tokio::spawn(async move {
                    if let Err(e) = run_udp_port_forward(bind_addr, remote_addr, state).await {
                        error!("port-forward UDP {name} error: {:#}", e);
                    }
                });
            }
            PortForwardProto::Both => {
                let name_tcp = name.clone();
                let name_udp = name.clone();
                let tcp_state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = run_tcp_port_forward(bind_addr, remote_addr, tcp_state).await {
                        error!("port-forward TCP(both) {name_tcp} error: {:#}", e);
                    }
                });
                tokio::spawn(async move {
                    if let Err(e) = run_udp_port_forward(bind_addr, remote_addr, state).await {
                        error!("port-forward UDP(both) {name_udp} error: {:#}", e);
                    }
                });
            }
        }
    }

    if !state.config.disable_upstream_score {
        for up in state.upstreams.iter() {
            let up = Arc::clone(up);
            tokio::spawn(async move {
                up.spawn_score_task();
            });
        }
        let state_clone = Arc::clone(&state);
        tokio::spawn(async move {
            run_upstream_stats_listener(state_clone).await;
        });
    }

    // 启动主动健康检查（interval=0 时禁用）
    if state.config.health_check_interval_secs > 0 {
        crate::upstream::spawn_health_check_task(Arc::clone(&state));
    }

    {
        let state = state.clone();
        tokio::spawn(async move {
            run_udp_gc_loop(state).await;
        });
    }

    tokio::signal::ctrl_c().await?;
    info!("shutting down");

    Ok(())
}
