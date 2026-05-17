use iptrie::{IpPrefix, Ipv4RTrieSet, Ipv6RTrieSet};
use maxminddb::Reader;
use maxminddb::geoip2::Country;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use crate::cli::Config;
use crate::sniff::Sniffer;
use crate::sniff::udp::UdpSnifferEngine;
use crate::udp::UdpRuntime;
use crate::upstream::UpstreamSet;

pub struct AppState {
    pub mmdb: Option<Arc<Reader<Vec<u8>>>>,
    pub config: Config,
    pub udp_runtime: Arc<UdpRuntime>,
    pub force_direct_v4: Ipv4RTrieSet,
    pub force_direct_v6: Ipv6RTrieSet,
    pub force_socks5_v4: Ipv4RTrieSet,
    pub force_socks5_v6: Ipv6RTrieSet,
    pub sniffers: Vec<Arc<dyn Sniffer>>,
    pub udp_sniffers: Vec<Arc<dyn UdpSnifferEngine>>,
    pub upstreams: UpstreamSet,
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
