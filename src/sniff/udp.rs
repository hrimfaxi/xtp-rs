pub trait UdpSnifferEngine: Send + Sync {
    fn name(&self) -> &'static str;
    fn new_session(&self) -> Box<dyn UdpSnifferSessionEngine>;
}

pub trait UdpSnifferSessionEngine: Send {
    fn feed(&mut self, payload: &[u8]) -> UdpSniffOutcome;
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpSniffProtocol {
    QuicSni,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum UdpSniffOutcome {
    Matched {
        protocol: UdpSniffProtocol,
        host: String,
    },
    NotMatched,
    NeedMore {
        protocol: UdpSniffProtocol,
    },
    Failed {
        protocol: UdpSniffProtocol,
        error: UdpSniffError,
    },
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpSniffError {
    ProtocolNotMatched,
    InsufficientPrefix,
    NoTarget,
    ParseError,
    InvalidHostname,
    TooLarge,
}

pub fn udp_sniff_protocol_name(protocol: UdpSniffProtocol) -> &'static str {
    match protocol {
        UdpSniffProtocol::QuicSni => "quic_sni",
    }
}

pub fn udp_sniff_error_reason(error: UdpSniffError) -> &'static str {
    match error {
        UdpSniffError::ProtocolNotMatched => "protocol_not_matched",
        UdpSniffError::InsufficientPrefix => "insufficient_prefix",
        UdpSniffError::NoTarget => "no_target",
        UdpSniffError::ParseError => "parse_error",
        UdpSniffError::InvalidHostname => "invalid_hostname",
        UdpSniffError::TooLarge => "too_large",
    }
}
