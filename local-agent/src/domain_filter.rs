use std::sync::RwLock;

use tracing::info;

/// Stores and matches domain patterns fetched from the proxy server.
///
/// Thread-safe: uses `RwLock` for concurrent read access from proxy/transparent
/// handlers, with infrequent writes when the domain list is updated.
pub struct DomainFilter {
    patterns: RwLock<Vec<String>>,
}

impl DomainFilter {
    /// Create a new filter with an empty domain list.
    /// When empty, no domains match — all traffic goes direct.
    pub fn new() -> Self {
        Self {
            patterns: RwLock::new(Vec::new()),
        }
    }

    /// Replace the current domain list with a new one from the server.
    pub fn update(&self, domains: Vec<String>) {
        info!(count = domains.len(), "domain filter updated");
        let mut patterns = self.patterns.write().unwrap();
        *patterns = domains;
    }

    /// Check if a hostname matches any configured domain pattern.
    ///
    /// Supports:
    /// - Exact match (case-insensitive): `api.openai.com`
    /// - Wildcard prefix: `*.example.com` matches `sub.example.com` but NOT `example.com`
    pub fn matches(&self, hostname: &str) -> bool {
        let patterns = self.patterns.read().unwrap();
        let hostname_lower = hostname.to_ascii_lowercase();

        for pattern in patterns.iter() {
            let pattern_lower = pattern.to_ascii_lowercase();

            if let Some(suffix) = pattern_lower.strip_prefix("*.") {
                // Wildcard: hostname must end with .suffix and be longer than suffix
                if hostname_lower.ends_with(&format!(".{}", suffix)) {
                    return true;
                }
            } else {
                // Exact match
                if hostname_lower == pattern_lower {
                    return true;
                }
            }
        }

        false
    }

    /// Returns true if no domains are configured (nothing will be tunneled).
    pub fn is_empty(&self) -> bool {
        self.patterns.read().unwrap().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_filter_matches_nothing() {
        let filter = DomainFilter::new();
        assert!(!filter.matches("api.openai.com"));
        assert!(!filter.matches("example.com"));
        assert!(filter.is_empty());
    }

    #[test]
    fn exact_match() {
        let filter = DomainFilter::new();
        filter.update(vec!["api.openai.com".to_string()]);
        assert!(filter.matches("api.openai.com"));
        assert!(!filter.matches("other.openai.com"));
        assert!(!filter.matches("openai.com"));
        assert!(!filter.is_empty());
    }

    #[test]
    fn exact_match_case_insensitive() {
        let filter = DomainFilter::new();
        filter.update(vec!["API.OpenAI.com".to_string()]);
        assert!(filter.matches("api.openai.com"));
        assert!(filter.matches("API.OPENAI.COM"));
        assert!(filter.matches("Api.Openai.Com"));
    }

    #[test]
    fn wildcard_match() {
        let filter = DomainFilter::new();
        filter.update(vec!["*.example.com".to_string()]);
        assert!(filter.matches("sub.example.com"));
        assert!(filter.matches("deep.sub.example.com"));
        assert!(!filter.matches("example.com")); // wildcard doesn't match bare domain
        assert!(!filter.matches("notexample.com"));
    }

    #[test]
    fn wildcard_case_insensitive() {
        let filter = DomainFilter::new();
        filter.update(vec!["*.Example.COM".to_string()]);
        assert!(filter.matches("sub.example.com"));
        assert!(filter.matches("SUB.EXAMPLE.COM"));
    }

    #[test]
    fn multiple_patterns() {
        let filter = DomainFilter::new();
        filter.update(vec![
            "api.openai.com".to_string(),
            "*.anthropic.com".to_string(),
            "api.cohere.ai".to_string(),
        ]);
        assert!(filter.matches("api.openai.com"));
        assert!(filter.matches("api.anthropic.com"));
        assert!(filter.matches("docs.anthropic.com"));
        assert!(filter.matches("api.cohere.ai"));
        assert!(!filter.matches("example.com"));
    }

    #[test]
    fn update_replaces_list() {
        let filter = DomainFilter::new();
        filter.update(vec!["api.openai.com".to_string()]);
        assert!(filter.matches("api.openai.com"));

        filter.update(vec!["api.anthropic.com".to_string()]);
        assert!(!filter.matches("api.openai.com"));
        assert!(filter.matches("api.anthropic.com"));
    }

    #[test]
    fn is_empty_after_clear() {
        let filter = DomainFilter::new();
        filter.update(vec!["api.openai.com".to_string()]);
        assert!(!filter.is_empty());

        filter.update(vec![]);
        assert!(filter.is_empty());
    }
}
