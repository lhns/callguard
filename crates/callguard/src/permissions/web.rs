//! `WebFetch(domain:...)` and `mcp__server__tool` rules.
//!
//! There is no `url` crate in the lock file without nah, so hosts are read by
//! two small functions instead: [`strict_host`] for allow accepts only the
//! plain `scheme://host[:port]/...` shape and refuses everything odd, and
//! [`candidate_hosts`] for deny and ask returns every host the text could
//! mean, so a trick (`https://evil.com\@example.com`) cannot hide the real one.

use super::spec::glob;

/// A parsed `domain:` pattern: lower case, no trailing dot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Domain {
    pat: String,
}

impl Domain {
    /// Parses the text between the parentheses of `WebFetch(...)`.
    pub fn parse(spec: &str) -> Result<Domain, String> {
        let Some(d) = spec.trim().strip_prefix("domain:") else {
            return Err("only `domain:<host>` is supported inside WebFetch(...)".into());
        };
        let pat = strip_dot(&d.trim().to_ascii_lowercase()).to_owned();
        if pat.is_empty() {
            return Err("empty domain".into());
        }
        if !pat
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '*'))
        {
            return Err("a domain holds letters, digits, `.`, `-`, `_` and `*`".into());
        }
        Ok(Domain { pat })
    }

    pub fn is_blanket(&self) -> bool {
        self.pat.split('.').all(|l| l.chars().all(|c| c == '*'))
    }

    /// Case-insensitive, trailing dot ignored. `*.x` is any depth of
    /// subdomain, not `x`; any other `*` stays between two dots.
    pub fn matches(&self, host: &str) -> bool {
        let host = strip_dot(&host.to_ascii_lowercase()).to_owned();
        if host.is_empty() {
            return false;
        }
        if self.pat == "*" {
            return true;
        }
        if let Some(suffix) = self.pat.strip_prefix("*.") {
            return host
                .match_indices('.')
                .any(|(k, _)| k > 0 && labels_match(suffix, &host[k + 1..]));
        }
        labels_match(&self.pat, &host)
    }
}

fn strip_dot(s: &str) -> &str {
    s.strip_suffix('.').unwrap_or(s)
}

/// Same number of labels, each matching its label pattern.
fn labels_match(pat: &str, host: &str) -> bool {
    let (p, h): (Vec<&str>, Vec<&str>) = (pat.split('.').collect(), host.split('.').collect());
    p.len() == h.len() && p.iter().zip(&h).all(|(p, h)| glob(p, h))
}

/// The host of `url` if it has the plain shape `http(s)://host[:port]/...` and
/// nothing a parser could read differently: ASCII only, no whitespace,
/// backslash or user info. None otherwise.
pub(super) fn strict_host(url: &str) -> Option<String> {
    if !url.bytes().all(|b| (0x21..0x7f).contains(&b)) || url.contains('\\') {
        return None;
    }
    let (scheme, rest) = url.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return None;
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let auth = &rest[..end];
    if auth.contains(['@', '[']) {
        return None;
    }
    let (host, port) = match auth.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (auth, None),
    };
    if port.is_some_and(|p| p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit())) {
        return None;
    }
    let host = strip_dot(host).to_ascii_lowercase();
    let ok = !host.is_empty()
        && host.split('.').all(|l| {
            !l.is_empty()
                && l.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        });
    ok.then_some(host)
}

/// Every host `url` could mean, for deny and ask. Over-approximates: user
/// info, backslashes and stray whitespace each add candidates.
pub(super) fn candidate_hosts(url: &str) -> Vec<String> {
    let squeezed: String = url
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && !c.is_ascii_control())
        .collect();
    let mut out: Vec<String> = Vec::new();
    for text in [url.trim(), squeezed.as_str()] {
        let after = match text.find("://") {
            Some(k) => &text[k + 3..],
            None => text.strip_prefix("//").unwrap_or(text),
        };
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        for chunk in after[..end].split(['@', '\\']) {
            let host = chunk.split(':').next().unwrap_or("");
            let host = strip_dot(host.trim_matches('.')).to_ascii_lowercase();
            if !host.is_empty() && !out.contains(&host) {
                out.push(host);
            }
        }
    }
    out
}

/// A parsed `mcp__server`, `mcp__server__tool` or `mcp__server__get_*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mcp {
    server: String,
    /// A glob over the tool segment; None for the whole server.
    tool: Option<String>,
}

impl Mcp {
    pub fn parse(name: &str) -> Result<Mcp, String> {
        let rest = name.strip_prefix("mcp__").unwrap_or(name);
        let (server, tool) = match rest.split_once("__") {
            Some((s, "")) => {
                return Err(format!("`{s}__` names no tool; write `mcp__{s}__*`"));
            }
            Some((s, t)) => (s, Some(t.to_owned())),
            None => (rest, None),
        };
        if server.is_empty() {
            return Err("no server name after `mcp__`".into());
        }
        if server.contains('*') {
            return Err("the server name must not contain `*`".into());
        }
        Ok(Mcp {
            server: server.to_owned(),
            tool,
        })
    }

    pub fn matches(&self, tool: &str) -> bool {
        let prefix = format!("mcp__{}__", self.server);
        let Some(rest) = tool.strip_prefix(&prefix).filter(|r| !r.is_empty()) else {
            return false;
        };
        self.tool.as_ref().is_none_or(|g| glob(g, rest))
    }
}
