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
use arc_swap::ArcSwap;
use clap::Parser;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::signal::unix::SignalKind;
use tokio::signal::unix::signal;
use tracing::{debug, error, info, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry, reload};

use crate::cli::{Cli, Config, ProxyMode};
use crate::state::AppState;
use crate::upstream::run_upstream_stats_listener;
use crate::util::TaskGuard;

/// 全局保存，reload 时用来改日志级别
static LOG_RELOAD_HANDLE: std::sync::OnceLock<reload::Handle<EnvFilter, Registry>> =
    std::sync::OnceLock::new();

fn build_env_filter(config: &Config) -> Result<EnvFilter> {
    if let Some(ref level) = config.log_level {
        EnvFilter::try_new(level).with_context(|| format!("invalid log_level '{}'", level))
    } else {
        Ok(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let config_str = tokio::fs::read_to_string(&cli.config)
        .await
        .with_context(|| format!("failed to read config file {}", cli.config))?;
    let mut config: Config = toml::from_str(&config_str).context("invalid config")?;
    config.normalize_geosite_tags();
    config.validate()?;

    let env_filter = build_env_filter(&config)?;
    let (reload_layer, reload_handle) = reload::Layer::new(env_filter);

    tracing_subscriber::registry()
        .with(reload_layer) // 先包 reload
        .with(tracing_subscriber::fmt::layer().without_time()) // 再包 fmt
        // 强行把全局最大级别推到 TRACE，确保任何日志都能走到 Layer 内部
        .with(tracing_subscriber::filter::LevelFilter::TRACE)
        .init();

    let _ = LOG_RELOAD_HANDLE.set(reload_handle);

    debug!("xtp-rs started");

    let app_state = AppState::build(config, cli.config.clone()).await?;
    let state = Arc::new(ArcSwap::from(Arc::new(app_state)));

    {
        let initial = state.load_full();
        initial.spawn_all_tasks().await?;
    }

    // stats listener 全局单例，用独立 TaskGuard 管理
    let state_for_stats = Arc::clone(&state);
    let stats_guard = TaskGuard::new();
    stats_guard.spawn(|cancel| async move {
        run_upstream_stats_listener(state_for_stats, cancel).await;
    });

    // SIGHUP 热重载
    let sighup_guard = TaskGuard::new();
    let state_for_sighup = Arc::clone(&state);
    sighup_guard.spawn(move |cancel| async move {
        let mut sighup = signal(SignalKind::hangup()).unwrap();
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    info!("SIGHUP handler shutting down");
                    break;
                }
                r = sighup.recv() => {
                    if r.is_none() {
                        info!("SIGHUP stream closed");
                        break;
                    }

                    info!("SIGHUP received, reloading config...");
                    if let Err(e) = reload_config(Arc::clone(&state_for_sighup)).await {
                        error!("reload failed: {:#}", e);
                    }
                }
            }
        }
    });

    // SIGUSR1: 循环切换代理模式 (smart -> global -> bypass -> smart)
    let usr1_guard = TaskGuard::new();
    let state_for_usr1 = Arc::clone(&state);
    usr1_guard.spawn(|cancel| async move {
        let mut stream = match signal(SignalKind::user_defined1()) {
            Ok(s) => s,
            Err(e) => {
                warn!("SIGUSR1 handler install failed: {}", e);
                return;
            }
        };
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    info!("SIGUSR1 handler shutting down");
                    break;
                }
                Some(()) = stream.recv() => {
                    let current = state_for_usr1.load();
                    let old = ProxyMode::from_u8(current.runtime.proxy_mode.load(Ordering::Relaxed));
                    let new = old.next();
                    current.runtime.proxy_mode.store(new.as_u8(), Ordering::Relaxed);
                    info!("Proxy mode rotated: {} -> {}", old, new);
                }
            }
        }
    });

    tokio::signal::ctrl_c().await?;
    info!("shutting down");

    // 先停全局 stats listener（它有 socket 文件要清理）
    if !stats_guard.shutdown(Duration::from_secs(1)).await {
        warn!("stats listener shutdown timed out");
    }

    // 停 SIGHUP handler
    if !sighup_guard.shutdown(Duration::from_secs(10)).await {
        warn!("sighup handler shutdown timed out");
    }

    // 停 SIGUSR1 handler
    if !usr1_guard.shutdown(Duration::from_secs(2)).await {
        warn!("SIGUSR1 handler shutdown timed out");
    }

    let current = state.load_full();
    if !current.shutdown_for_exit(Duration::from_secs(2)).await {
        warn!("shutdown timed out, some tasks aborted");
    }

    Ok(())
}

async fn reload_config(state: Arc<ArcSwap<AppState>>) -> Result<()> {
    let old_snapshot = state.load_full();
    let path = old_snapshot.config_path.clone();

    // 不要持有 old_snapshot 做太多事，这里只是拿 config path。
    drop(old_snapshot);

    // 1. 先读取并构建新配置。失败时旧 generation 完全不动。
    let config_str = tokio::fs::read_to_string(&path)
        .await
        .with_context(|| format!("failed to read config file {}", path))?;

    let mut config: Config = toml::from_str(&config_str).context("invalid config")?;
    config.normalize_geosite_tags();
    config.validate()?;
    // 提前校验 log filter，失败时旧 generation 不动
    let new_filter = build_env_filter(&config)?;
    let new_arc = Arc::new(AppState::build(config, path.clone()).await?);

    // 2. 尝试启动新 generation。失败时 rollback，新 generation 自己清理，旧服务不动。
    //
    // 注意：所有 listener 都需要 SO_REUSEADDR + SO_REUSEPORT，
    // 否则这里先启新 generation 时会因为旧 generation 还占着端口而 EADDRINUSE。
    if let Err(e) = new_arc.spawn_all_tasks().await {
        error!("new generation spawn failed, rolling back: {:#}", e);
        new_arc.shutdown_for_exit(Duration::from_secs(1)).await;
        return Err(e);
    }

    // 3. 新 generation 启动成功后，原子切换全局 state。
    //
    // state.swap() 会返回被替换掉的旧 generation。
    // 这一步之后，stats listener 等全局任务会读到 new_arc。
    let old_arc = state.swap(new_arc.clone());

    let reset_mode = ProxyMode::from_u8(new_arc.runtime.proxy_mode.load(Ordering::Relaxed));
    info!("Proxy mode reset to config value: {}", reset_mode);

    // 4. 热更新 tracing filter。
    //
    // 提前构建好的 filter，swap 成功后直接应用
    if let Some(handle) = LOG_RELOAD_HANDLE.get() {
        if let Err(e) = handle.reload(new_filter) {
            error!("failed to reload tracing filter: {}", e);
        } else {
            info!("tracing filter reloaded");
        }
    }

    // 5. 停旧 generation。
    //
    // 这里只停一次。
    if !old_arc.shutdown_for_reload(Duration::from_secs(2)).await {
        warn!("old generation shutdown timed out, some tasks aborted");
    }

    info!("config reloaded from {}", path);
    Ok(())
}
