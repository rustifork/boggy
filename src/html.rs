//! Self-contained HTML report: no JavaScript, no external assets.

use crate::types::{ScanReport, Severity};

fn esc(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

pub fn render(report: &ScanReport) -> String {
    let css = "body{font:14px system-ui,sans-serif;margin:2rem auto;max-width:1100px;color:#1b1f24;background:#fafbfc}h1{margin-bottom:.2rem}h2{border-bottom:1px solid #d8dee4;padding-bottom:.3rem;margin-top:2rem}.cards{display:flex;gap:1rem;flex-wrap:wrap;margin:1rem 0}.card{background:#fff;border:1px solid #d8dee4;border-radius:8px;padding:.8rem 1.2rem;min-width:120px}.card b{display:block;font-size:1.6rem}table{width:100%;border-collapse:collapse;background:#fff}th,td{text-align:left;padding:.45rem .6rem;border-bottom:1px solid #eaeef2;vertical-align:top}th{background:#f3f5f7}.critical{color:#b00020;font-weight:bold}.high{color:#c2410c;font-weight:bold}.medium{color:#a16207}.low{color:#2563eb}.info{color:#64748b}code{background:#f1f3f5;padding:.1rem .3rem;border-radius:3px}.diff{background:#fff;border:1px solid #d8dee4;padding:1rem;border-radius:8px}";
    let mut out = String::new();
    out.push_str("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    out.push_str("<title>boggy scan report</title><style>");
    out.push_str(css);
    out.push_str("</style></head><body>\n<h1>boggy scan report</h1>");
    out.push_str(&format!(
        "<p>Target <code>{}</code> · {} → {}</p>",
        esc(&report.target),
        esc(&report.started),
        esc(&report.finished)
    ));

    let s = &report.summary;
    out.push_str("<div class=\"cards\">");
    for (label, value) in [
        ("Hosts", s.hosts),
        ("Open ports", s.open_ports),
        ("Findings", s.findings),
        ("Critical", s.critical),
        ("High", s.high),
        ("Medium", s.medium),
    ] {
        out.push_str(&format!(
            "<div class=\"card\"><b>{}</b>{}</div>",
            value, label
        ));
    }
    out.push_str("</div>");

    if let Some(diff) = &report.diff {
        out.push_str("<h2>Baseline comparison</h2><div class=\"diff\">");
        let n = |key: &str| {
            diff.get(key)
                .and_then(crate::json::Json::as_u64)
                .unwrap_or(0)
        };
        out.push_str(&format!(
            "New hosts: {} · Missing hosts: {} · New findings: {} · Resolved findings: {}",
            n("new_hosts"),
            n("missing_hosts"),
            n("new_findings"),
            n("resolved_findings")
        ));
        out.push_str("</div>");
    }

    out.push_str("<h2>Hosts</h2><table><thead><tr><th>Host</th><th>Vendor / type</th><th>Open ports</th><th>Findings</th></tr></thead><tbody>");
    for host in &report.hosts {
        out.push_str("<tr>");
        out.push_str(&format!("<td><code>{}</code>", esc(&host.ip.to_string())));
        if let Some(hn) = &host.hostname {
            out.push_str(&format!("<br>{}", esc(hn)));
        }
        if let Some(m) = &host.mac {
            out.push_str(&format!("<br><small>{}</small>", esc(m)));
        }
        out.push_str("</td><td>");
        for value in [&host.vendor, &host.model, &host.device_type] {
            if let Some(v) = value {
                out.push_str(&esc(v));
                out.push_str("<br>");
            }
        }
        out.push_str("</td><td>");
        for port in &host.ports {
            out.push_str(&format!(
                "<code>{}/{}</code> {}<br>",
                port.port,
                esc(port.service.as_deref().unwrap_or("")),
                esc(port.banner.as_deref().unwrap_or(""))
            ));
        }
        out.push_str("</td><td>");
        for finding in &host.findings {
            let class = match finding.rank() {
                Severity::Critical => "critical",
                Severity::High => "high",
                Severity::Medium => "medium",
                Severity::Low => "low",
                Severity::Info => "info",
            };
            out.push_str(&format!(
                "<span class=\"{}\">[{}]</span> {}",
                class,
                esc(finding.rank().as_str()),
                esc(&finding.title)
            ));
            if let Some(cve) = &finding.cve {
                out.push_str(&format!(" <code>{}</code>", esc(cve)));
            }
            out.push_str("<br><small>");
            out.push_str(&esc(&finding.detail));
            out.push_str("</small><br>");
        }
        out.push_str("</td></tr>");
    }
    out.push_str("</tbody></table>\n</body></html>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_and_renders() {
        let mut report = ScanReport {
            target: "test".into(),
            hosts: Vec::new(),
            started: "0".into(),
            finished: "0".into(),
            summary: Default::default(),
            diff: None,
        };
        report.summary.hosts = 1;
        let text = render(&report);
        assert!(text.starts_with("<!doctype html>"));
        assert!(text.contains("<b>1</b>Hosts"));
        assert!(esc("<script>&\"") == "&lt;script&gt;&amp;&quot;");
    }
}
