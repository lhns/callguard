use super::*;

// ---------------------------------------------------------------------------
// HTTP

/// An HTTP client that uses the system trust store and the proxy the
/// environment names for `url` (see [`proxy_for`]).
pub(super) fn http_agent(url: &str) -> Result<ureq::Agent, BackendError> {
    http_agent_from(url, &|k| std::env::var(k).ok())
}

pub(super) fn http_agent_from(
    url: &str,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<ureq::Agent, BackendError> {
    let tls = ureq::tls::TlsConfig::builder()
        .root_certs(ureq::tls::RootCerts::PlatformVerifier)
        .build();
    // An unusable proxy value is an error; connecting directly instead would
    // send the request around a proxy the operator meant it to use.
    let proxy = match proxy_for(url, env) {
        Some(p) => Some(
            ureq::Proxy::new(&p)
                .map_err(|e| other(format!("proxy {p:?} from the environment: {e}")))?,
        ),
        None => None,
    };
    Ok(ureq::Agent::config_builder()
        .tls_config(tls)
        .proxy(proxy)
        // A redirect would carry `x-api-key` along (ureq strips only
        // `Authorization` and `Cookie`): it is an error, which is the fail-safe.
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .into())
}

/// The scheme, lower-case host (no brackets) and port of `url`, the port
/// defaulted from the scheme.
pub(super) fn url_target(url: &str) -> Option<(String, String, u16)> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let auth = rest.split(['/', '?', '#']).next()?;
    let auth = auth.rsplit('@').next()?;
    let (host, port) = if let Some(r) = auth.strip_prefix('[') {
        let (h, after) = r.split_once(']')?;
        (h, after.strip_prefix(':'))
    } else if let Some((h, p)) = auth.split_once(':') {
        (h, Some(p))
    } else {
        (auth, None)
    };
    let default = if scheme == "https" { 443 } else { 80 };
    let port = match port {
        Some(p) if !p.is_empty() => p.parse().ok()?,
        _ => default,
    };
    Some((scheme, host.to_ascii_lowercase(), port))
}

pub(super) fn is_loopback(host: &str) -> bool {
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

pub(super) fn first_set(env: &dyn Fn(&str) -> Option<String>, names: &[&str]) -> Option<String> {
    names
        .iter()
        .filter_map(|n| env(n))
        .map(|v| v.trim().to_owned())
        .find(|v| !v.is_empty())
}

/// The proxy for a request to `url`: `HTTPS_PROXY` for https, `HTTP_PROXY` for
/// http (upper case wins over lower), nothing for loopback or for a target
/// that `NO_PROXY` lists. `ALL_PROXY` is not read. None means connect directly.
pub(crate) fn proxy_for(url: &str, env: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    let (scheme, host, port) = url_target(url)?;
    if is_loopback(&host) {
        return None;
    }
    let proxy = match scheme.as_str() {
        "https" => first_set(env, &["HTTPS_PROXY", "https_proxy"]),
        "http" => first_set(env, &["HTTP_PROXY", "http_proxy"]),
        _ => None,
    }?;
    let no_proxy = first_set(env, &["NO_PROXY", "no_proxy"]).unwrap_or_default();
    if no_proxy
        .split(',')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .any(|e| no_proxy_matches(e, &host, port))
    {
        return None;
    }
    Some(proxy)
}

/// Whether one `NO_PROXY` entry covers the target: `*`, an IP, a CIDR, a
/// host (itself and its subdomains), `.host` (subdomains only), each with an
/// optional `:port`.
pub(super) fn no_proxy_matches(entry: &str, host: &str, port: u16) -> bool {
    if entry == "*" {
        return true;
    }
    let entry = entry.to_ascii_lowercase();
    if let Some((net, bits)) = entry.split_once('/') {
        let (Ok(net), Ok(bits), Ok(ip)) = (
            net.parse::<std::net::IpAddr>(),
            bits.parse::<u32>(),
            host.parse::<std::net::IpAddr>(),
        ) else {
            return false;
        };
        return in_cidr(ip, net, bits);
    }
    let (name, eport) = if let Some(r) = entry.strip_prefix('[') {
        match r.split_once(']') {
            Some((h, after)) => (h, after.strip_prefix(':')),
            None => return false,
        }
    } else if entry.matches(':').count() == 1 {
        let (h, p) = entry.split_once(':').unwrap_or((&entry, ""));
        (h, Some(p))
    } else {
        (entry.as_str(), None)
    };
    if let Some(p) = eport
        && !p.is_empty()
        && p.parse::<u16>().is_ok_and(|p| p != port)
    {
        return false;
    }
    if let Ok(ip) = name.parse::<std::net::IpAddr>() {
        return host.parse::<std::net::IpAddr>().is_ok_and(|h| h == ip);
    }
    let name = name.strip_prefix('*').unwrap_or(name);
    if name.starts_with('.') {
        host.ends_with(name)
    } else {
        host == name || host.ends_with(&format!(".{name}"))
    }
}

pub(super) fn in_cidr(ip: std::net::IpAddr, net: std::net::IpAddr, bits: u32) -> bool {
    use std::net::IpAddr::{V4, V6};
    match (ip, net) {
        (V4(a), V4(n)) if bits <= 32 => {
            let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
            u32::from(a) & mask == u32::from(n) & mask
        }
        (V6(a), V6(n)) if bits <= 128 => {
            let mask = u128::MAX.checked_shl(128 - bits).unwrap_or(0);
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

/// The time left until `deadline`, or `Timeout` if there is none.
pub(super) fn remaining(deadline: Instant) -> Result<Duration, BackendError> {
    match deadline.checked_duration_since(Instant::now()) {
        Some(d) if !d.is_zero() => Ok(d),
        _ => Err(BackendError::Timeout),
    }
}

/// Sends `body` to `url` and returns the body of a 2xx response. `who` names
/// the backend in errors.
pub(super) fn post_json(
    agent: &ureq::Agent,
    url: &str,
    headers: &[(&str, &str)],
    body: String,
    deadline: Instant,
    who: &str,
) -> Result<Vec<u8>, BackendError> {
    let fail = |e: &dyn std::fmt::Display| {
        if Instant::now() >= deadline {
            BackendError::Timeout
        } else {
            other(format!("{who}: {e}"))
        }
    };
    let mut req = agent
        .post(url)
        .config()
        .timeout_global(Some(remaining(deadline)?))
        .build();
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let mut resp = req.send(body).map_err(|e| match e {
        ureq::Error::Timeout(_) => BackendError::Timeout,
        e => fail(&e),
    })?;
    let status = resp.status().as_u16();
    let mut raw = Vec::new();
    resp.body_mut()
        .as_reader()
        .take(MAX_RESPONSE_BYTES)
        .read_to_end(&mut raw)
        .map_err(|e| fail(&format_args!("reading response: {e}")))?;
    if !(200..=299).contains(&status) {
        return Err(other(format!(
            "{who}: HTTP {status}: {}",
            clip(&String::from_utf8_lossy(&raw), MAX_ERR_BODY)
        )));
    }
    Ok(raw)
}
