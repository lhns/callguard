//! `WebFetch(domain:...)` and `mcp__server__tool` rules.
//!
//! A URL parser may read a host differently from the client that fetches, so
//! hosts are read by two small functions instead: [`strict_host`] for allow
//! accepts only the plain `scheme://host[:port]/...` shape and refuses
//! everything odd, and
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
/// info, backslashes, stray whitespace, `scheme:/host` with too few slashes,
/// percent escapes and Unicode full stops each add candidates.
pub(super) fn candidate_hosts(url: &str) -> Vec<String> {
    let squeezed: String = url
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && !c.is_ascii_control())
        .collect();
    let mut out: Vec<String> = Vec::new();
    for text in [url.trim(), squeezed.as_str()] {
        let mut afters = vec![match text.find("://") {
            Some(k) => &text[k + 3..],
            None => text.strip_prefix("//").unwrap_or(text),
        }];
        // `https:/evil.com/`: browsers and curl read it as `https://evil.com/`.
        if let Some((scheme, rest)) = text.split_once(':')
            && !scheme.is_empty()
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
        {
            afters.push(rest.trim_start_matches(['/', '\\']));
        }
        for after in afters {
            let end = after.find(['/', '?', '#']).unwrap_or(after.len());
            let auth = &after[..end];
            let decoded = percent_decode(auth);
            for auth in [auth, decoded.as_str()] {
                for chunk in auth.split(['@', '\\']) {
                    let host = chunk.split(':').next().unwrap_or("");
                    let host: String = host
                        .chars()
                        .map(|c| {
                            if "\u{3002}\u{ff0e}\u{ff61}".contains(c) {
                                '.'
                            } else {
                                c
                            }
                        })
                        .collect();
                    let host = strip_dot(host.trim_matches('.')).to_ascii_lowercase();
                    if !host.is_empty() && !out.contains(&host) {
                        out.push(host);
                    }
                }
            }
        }
    }
    out
}

/// `%41` as `A`; a malformed escape stays as written.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let byte = (b[i] == b'%')
            .then(|| {
                s.get(i + 1..i + 3)
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
            })
            .flatten();
        match byte {
            Some(v) => {
                out.push(v);
                i += 3;
            }
            None => {
                out.push(b[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
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

    /// With `strict` (allow), a remainder holding `__` does not match: the
    /// name could belong to a server whose own name contains `__`.
    pub fn matches(&self, tool: &str, strict: bool) -> bool {
        let prefix = format!("mcp__{}__", self.server);
        let Some(rest) = tool.strip_prefix(&prefix).filter(|r| !r.is_empty()) else {
            return false;
        };
        if strict && rest.contains("__") {
            return false;
        }
        self.tool.as_ref().is_none_or(|g| glob(g, rest))
    }
}
