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
    pub fn hosts(&self) -> Vec<Ipv4Addr> {
        let count = match self.prefix {
            32 => 1u32,
            31 => 2u32,
            _ => 1u32 << (32 - self.prefix),
        };
        let (start, end) = if self.prefix <= 30 {
            (1u32, count.saturating_sub(1))
        } else {
            (0u32, count)
        };
        (start..end)
            .map(|i| Ipv4Addr::from(u32::from(self.network) + i))
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
        assert_eq!(
            Subnet::parse("10.0.0.0/8").unwrap().host_count(),
            Subnet::parse("10.0.0.0/8").unwrap().hosts().len()
        );
    }
}
