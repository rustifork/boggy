use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Copy, Debug)]
pub struct Subnet {
    pub network: Ipv4Addr,
    pub prefix: u8,
}

impl Subnet {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let (ip, pref) = match s.split_once('/') {
            Some((a, b)) => (a.trim(), b.trim().parse::<u8>().ok()?),
            None => (s, 24),
        };
        let ip: Ipv4Addr = ip.parse().ok()?;
        if pref > 32 {
            return None;
        }
        let mask = mask(pref);
        Some(Self {
            network: Ipv4Addr::from(u32::from(ip) & mask),
            prefix: pref,
        })
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        (u32::from(ip) & mask(self.prefix)) == u32::from(self.network)
    }

    /// Number of enumerated addresses, computed before allocating a host list.
    pub fn host_count(&self) -> usize {
        match self.prefix {
            32 => 1,
            31 => 2,
            p if p <= 30 => {
                let count = 1usize.checked_shl(32 - p as u32).unwrap_or(usize::MAX);
                count.saturating_sub(2)
            }
            _ => 1,
        }
    }

    /// Enumerate usable addresses. /31 and /32 are treated as single-host routes.
    /// Hard-capped so a direct call cannot allocate an unbounded vector; callers
    /// should check `host_count()` first for large CIDRs.
    pub fn hosts(&self) -> Vec<Ipv4Addr> {
        const MAX_ENUMERATED: usize = 1 << 20;
        let count = self.host_count();
        if count == 0 || count > MAX_ENUMERATED {
            return Vec::new();
        }
        let base = u32::from(self.network) as u64;
        let count = count as u64;
        // host_count() excludes network/broadcast for <= /30; add them back to
        // reconstruct the address range before skipping the first and last.
        let (start, end) = if self.prefix <= 30 {
            (1u64, count + 1)
        } else {
            (0u64, count)
        };
        (start..end)
            .map(|i| Ipv4Addr::from((base + i) as u32))
            .collect()
    }

    pub fn auto() -> Option<Self> {
        use std::net::UdpSocket;
        let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
        sock.connect("8.8.8.8:80").ok()?;
        if let IpAddr::V4(v4) = sock.local_addr().ok()?.ip() {
            let o = v4.octets();
            return Some(Self {
                network: Ipv4Addr::new(o[0], o[1], o[2], 0),
                prefix: 24,
            });
        }
        None
    }
}

fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_contains() {
        let s = Subnet::parse("192.168.1.77/24").unwrap();
        assert_eq!(s.network, Ipv4Addr::new(192, 168, 1, 0));
        assert!(s.contains(Ipv4Addr::new(192, 168, 1, 200)));
        assert!(!s.contains(Ipv4Addr::new(192, 168, 2, 1)));
    }

    #[test]
    fn host_counts() {
        assert_eq!(Subnet::parse("10.0.0.0/30").unwrap().hosts().len(), 2);
        assert_eq!(Subnet::parse("10.0.0.0/31").unwrap().hosts().len(), 2);
        assert_eq!(Subnet::parse("10.0.0.1/32").unwrap().hosts().len(), 1);
        assert_eq!(Subnet::parse("10.0.0.0/24").unwrap().hosts().len(), 254);
        assert_eq!(
            Subnet::parse("10.0.0.0/8").unwrap().host_count(),
            16_777_214
        );
        assert!(Subnet::parse("10.0.0.0/0").unwrap().hosts().is_empty());
    }
}
