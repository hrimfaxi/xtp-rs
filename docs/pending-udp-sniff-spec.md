# 需求说明书：Pending UDP — 使能 QUIC SNI 嗅探域名路由

## 1. 背景

TCP 路径通过 `MSG_PEEK` 在连接建立前嗅探 TLS SNI，将域名传给 `should_direct(ip, domain)` 实现 geosite 规则匹配和基于域名的 upstream 分组选择。

UDP 路径（QUIC）存在消费端缺陷：

1. pending sniff 链路已将 `sniffed_host` 透传到 session 创建路径
2. 但 `create_udp_session` 在路由决策时传 `None` 给 `should_direct`，忽略 `spec.sniffed_host`
3. geosite 规则对 QUIC 流量不生效
4. SOCKS5 UDP target 永远使用 IP，域名分支不可达

**结果**：QUIC 嗅探模块的 CPU 开销是纯浪费。

## 2. 现有架构

```
UDP 包到达
  ├── 已有 session？→ 直接转发
  ├── 已有 pending sniff？→ 喂给 sniffer
  │     ├── Matched → 标记 sniffed_host（但 flush 时 session 已存在，host 丢失）
  │     ├── NeedMore → 继续缓存
  │     ├── NotMatched/Failed/Expired → flush 缓存包
  └── 新包？
        ├── 嗅探器匹配 → 立即创建 session（host 被丢弃）
        ├── NeedMore → 创建 PendingUdpSniff，缓存包
        └── 无嗅探器/直连 → 直接创建 session
```

核心问题：`create_udp_session` 在路由决策时未读取 `spec.sniffed_host`，导致 pending sniff 链路虽然已将嗅探结果透传到 session 创建路径，但 QUIC 域名路由始终不生效。

## 3. 目标架构

**延迟 session 创建到 sniff 完成之后**，使 sniffed_host 可用于：

- `should_direct(ip, domain)` — geosite 规则对 QUIC 生效
- SOCKS5 UDP target — 使用域名而非 IP
- upstream 分组选择 — 基于域名的 client_domain_routes

```
UDP 包到达
  ├── 已有 session？→ 直接转发（不变）
  ├── 已有 pending sniff？→ 喂给 sniffer
  │     ├── Matched → 携带 sniffed_host ensure session，replay 缓存包
  │     ├── NeedMore → 继续缓存（不变）
  │     └── NotMatched/Failed/Expired → 不带 host ensure session，replay 缓存包
  └── 新包？
        ├── 嗅探器 Matched → 携带 host 创建 session，转发当前包
        ├── NeedMore → 创建 PendingUdpSniff（不创建 session）
        └── 无嗅探器/直连 → 直接创建 session（不变）
```

## 4. 详细需求

### 4.1 `flush_pending_udp_sniff` — 在 replay 前确保 session 已创建

**现状**：`flush` 调用 `forward_udp_payload`，后者调用 `get_or_create_udp_session`。
如果 pending sniff 的包到达时 session 尚未创建，`forward_udp_payload` 会在无 domain 的情况下创建 session。

**要求**：flush 必须在 replay 缓存包之前，基于最终 `spec`（可能含 `sniffed_host`）确保 session 已创建完成。

方案：
- `flush_pending_udp_sniff(state, pending)` 接收完整的 `PendingUdpSniff`（含 `spec.sniffed_host`）
- 显式调用 `get_or_create_udp_session(state, spec)` 确保 session 存在
- 如果 session 已存在（并发创建），直接复用（`get_or_create` 语义天然支持）
- session 确保就绪后，逐包 `send_payload` replay 缓存的 datagram

### 4.2 `handle_pending_udp_sniff` 的 sniff 成功路径

**现状**（`pending.rs:270-281`）：
```rust
UdpSniffOutcome::Matched { host } => {
    pending.spec.sniffed_host = Some(host);
    flush_pending_udp_sniff(state, pending).await;  // flush 会 ensure session
}
```

**要求**：此路径已经正确——`spec.sniffed_host` 被设置后传给 `flush`，`flush` 用带 host 的 spec ensure session。无需改动。

### 4.3 `handle_new_udp_sniff` 的立即匹配路径

**现状**（`pending.rs:350-365`）：
```rust
UdpSniffOutcome::Matched { host } => {
    spec.sniffed_host = Some(host);
    forward_udp_payload(state, spec, payload).await;  // 转发时创建 session
}
```

**要求**：此路径已经正确——`spec` 带 host 传给 `forward_udp_payload`，session 创建时 `should_direct` 应使用该 host。

**变更**：`create_udp_session` 中 `should_direct` 调用需改为 `state.should_direct(key.target_addr.ip(), spec.sniffed_host.as_deref())`。

### 4.4 `create_udp_session` 使用 sniffed_host

**现状**（`mod.rs:386`）：
```rust
if state.should_direct(key.target_addr.ip(), None) {
```

**要求**：
```rust
if state.should_direct(key.target_addr.ip(), spec.sniffed_host.as_deref()) {
```

**影响**：
- 当 `sniffed_host = Some("google.com")` 且 geosite 匹配 `google.com` 为直连时，创建 Direct outbound
- 当 `sniffed_host = Some("blocked.com")` 且 geosite 匹配为代理时，创建 Socks5 outbound
- 当 `sniffed_host = None` 时，行为与现在完全一致

### 4.5 `handle_new_udp_sniff` 的初始 `should_direct` 检查

**现状**（`pending.rs:338-343`）：
```rust
let target_ip_direct = matches!(spec.routing, UdpRoutingMode::Auto)
    && state.should_direct(spec.key.target_addr.ip(), None);

if target_ip_direct {
    return false;  // 跳过嗅探，直接创建 session
}
```

**要求**：此检查在 sniff 前执行，此时没有 domain，只能按 IP 判断。保留现状。

**理由**：IP-based direct decision has higher or equal precedence than domain-based proxy override in current routing semantics. 如果 IP 已确定为直连（如 RFC1918、loopback、link-local、已知直连 CIDR），无需 sniff。此短路避免无意义的嗅探开销。

**前提**：当前策略语义中，IP 命中直连时 domain 不会将其反转为代理。如果未来策略允许"IP 直连但域名强制代理"，此短路需重新评估。

### 4.6 Pending 缓冲区限制（不变）

| 参数 | 值 | 说明 |
|------|-----|------|
| `UDP_SNIFF_TIMEOUT_SECS` | 5 | 超时后 flush |
| `UDP_SNIFF_MAX_CACHED_DATAGRAMS` | 8 | 最大缓存包数 |
| `UDP_SNIFF_MAX_CACHED_BYTES` | 64KB | 最大缓存字节 |
| `UDP_SNIFF_MAX_PENDING_SESSIONS` | 4096 | 最大 pending 数 |

超时或溢出时，不带 host 创建 session 并 flush。行为与现在一致。

### 4.7 Session 已存在时的 pending 清理

**现状**（`pending.rs:201-202`）：
```rust
if let Some(session) = state.runtime.udp.get_ready_udp_session(key).await {
    pending_sniff.lock().await.remove(&key);
    // ...
}
```

**要求**：保留。当 session 已存在时，移除 pending 并直接转发。

**理由**：session 一旦存在，该 key 的路由决策已冻结（无论是以 `None` 还是 `Some(host)` 创建的），pending 再继续 sniff 已无意义。这不是"sniff 一定完成了"，而是"路由已定型，不可更改"。

### 4.8 移除死代码 TODO

实现完成后，移除以下 TODO 注释：
- `src/udp/mod.rs:383-385` — should_direct 未传 sniffed_host
- `src/udp/pending.rs:339` — 同上
- `src/udp/session.rs:148` — sniffed_host 分支不可达

## 5. 不变量

### 5.1 `sniffed_host` 是创建时快照

`UdpSession.sniffed_host` 在 session 创建时由 `spec` 决定，**一旦 session ready，不可更改**。

- 后续包即使又嗅探到 host，也不能改写其路由
- 这保证同一 session 的出站方式（direct/socks5）和 SOCKS5 target 形式（IP/domain）在其生命周期内不变

### 5.2 状态互斥

对同一个 `UdpSessionKey`，以下三种状态互斥且单向流转：

```
Absent → PendingSniff → ensure session (Creating → Ready)
Absent → Creating → Ready  （无嗅探路径）
```

- `Ready` 存在 → 不保留 `PendingSniff`
- `PendingSniff` 存在 → 不进入 `create_udp_session`
- `Creating` 存在 → 后续包等待 `Notify`，不独立 sniff

`UdpKeyLock` 保证同 key 串行，状态转换不会并发冲突。

### 5.3 Pending flush 单次消费

对同一个 `PendingUdpSniff`，flush 必须是单次消费语义：

1. 从 `pending_sniff` map 中 `remove`（原子获取所有权）
2. 释放 map 锁
3. 基于 `pending.spec` ensure session
4. replay datagrams

"remove then process" 模式防止同一 pending 被多个路径（matched/timeout/reap/overflow）重复 flush。

当前代码已通过 `pending_sniff.lock().await.remove(&key)` 实现了这一点。

## 6. 边界情况与 Fallback

| 场景 | 行为 |
|------|------|
| 嗅探超时（5s） | 不带 host 创建 session，flush 缓存包。与现在一致 |
| 嗅探失败 / NotMatched | 不带 host 创建 session，flush 缓存包 |
| 缓冲区溢出 | 不带 host 创建 session，flush 缓存包 |
| 嗅探成功但 session 创建失败 | flush 打 warn 日志后丢弃缓存包 |
| 并发包到达同一个 key | `UdpKeyLock` 保证串行；后续包看到 `Creating` 状态后等待 |
| `UdpSniffMaxPendingSessions` 溢出 | 最老的 pending 被驱逐（不带 host flush），不变 |
| IP 直连短路命中 | 跳过嗅探，直接创建 Direct session，不变 |
| port-forward 模式（ForceSocks5） | sniffed_host 用于 SOCKS5 UDP target 的域名，但不影响路由（已强制代理） |

## 7. 不变部分

- `PendingReplayBuffer` 结构和限制
- `PendingUdpSniff` 生命周期管理（超时、reap、容量限制）
- `UdpSession` 结构（`sniffed_host` 字段已有，只是现在有值了）
- `UdpSession::send_payload` 的 SOCKS5 target 逻辑（已有 domain 分支，只是现在可达了）
- UDP recv loop（direct / socks5）
- session 超时清理、shutdown 流程
- port-forward UDP 路径

## 8. 验收标准

### 功能

1. QUIC 流量的目标域名能被嗅探并传给 `should_direct`
2. geosite 规则中匹配的域名能正确影响 QUIC 流量的直连/代理决策
3. SOCKS5 UDP 转发使用域名而非 IP（当 sniff 成功时）
4. sniff 超时/失败时 fallback 到 IP 路由，无功能回退
5. 现有测试全部通过

### 可观测性

6. session 创建日志包含 `sniffed_host`（debug 级别）：
   ```
   created UDP session, sniffed_host=Some("google.com"), route=direct/socks5, upstream=...
   ```

### 测试覆盖

7. sniff 成功 → session 带 host 创建，`should_direct` 使用域名
8. sniff 超时 → session 不带 host 创建
9. SOCKS5 UDP target 分支可达性：sniff 成功时走 domain target，失败时走 IP target
10. ForceSocks5 模式下 sniff 只影响 target 形式，不影响路由模式
11. 并发竞态：matched 与 timeout/reap 同时发生，不重复 flush/replay
12. 并发竞态：一个包触发 create，另一个包在 pending 路径，最终只创建一个 session

## 9. 实现 Checklist

1. `create_udp_session` 中 `should_direct(ip, None)` → `should_direct(ip, spec.sniffed_host.as_deref())`
2. `flush_pending_udp_sniff` 改为先 `get_or_create_udp_session(spec)`，再逐包 `send_payload`
3. 确认 pending flush 的 "remove then process" 单次消费语义（已满足）
4. 确认 `UdpKeyLock` 保证 ready/creating/pending 状态互斥（已满足）
5. 核对 SOCKS5 UDP target（`session.rs:149`）与 upstream route selection 都能看到同一个 `spec.sniffed_host`
6. 删除 3 处 TODO 注释
7. 补 race test 和 domain target test

## 10. 不在范围内

- 多包 QUIC reassembly 的嗅探改进（现有 sniffer 的 `NeedMore` 处理不变）
- 嗅探器性能优化
- TCP 路径改动
- 路由缓存与 sniffed_host 的交互（后续优化）
