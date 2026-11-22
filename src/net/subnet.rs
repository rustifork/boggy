use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Debug)]
pub struct Subnet {
    pub network: Ipv4Addr,
    pub prefix: u8,
}

impl Subnet {
    pub fn parse(s: &str) -> Option<Self> {
        let (ip, pref) = if let Some((a, b)) = s.split_once('/') {
            (a, b.parse::<u8>().ok()?)
        } else {
            (s, 24)
        };
        let ip: Ipv4Addr = ip.parse().ok()?;
        if pref > 32 { return None; }
        let mask = if pref == 0 { 0 } else { !0u32 << (32 - pref) };
        let net = Ipv4Addr::from(u32::from(ip) & mask);
        Some(Self { network: net, prefix: pref })
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let mask = if self.prefix == 0 { 0 } else { !0u32 << (32 - self.prefix) };
        (u32::from(ip) & mask) == u32::from(self.network)
    }

    pub fn hosts(&self) -> Vec<Ipv4Addr> {
        let mut out = Vec::new();
        let base = u32::from(self.network);
        let count = if self.prefix >= 31 { 1u32 } else { 1u32 << (32 - self.prefix) };
        // skip network and broadcast for /24 and larger
        let start = if self.prefix <= 30 { 1 } else { 0 };
        let end = if self.prefix <= 30 { count - 1 } else { count };
        for i in start..end {
            out.push(Ipv4Addr::from(base + i));
        }
        out
    }

    pub fn auto() -> Option<Self> {
        // connect udp to a public addr to learn local ip
        use std::net::UdpSocket;
        let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
        sock.connect("8.8.8.8:80").ok()?;
        let local = sock.local_addr().ok()?.ip();
        if let IpAddr::V4(v4) = local {
            let o = v4.octets();
            let net = Ipv4Addr::new(o[0], o[1], o[2], 0);
            return Some(Self { network: net, prefix: 24 });
        }
        None
    }
}