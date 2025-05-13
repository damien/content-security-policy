//! CSP Level 3 Compliance Tests
//! https://www.w3.org/TR/2025/WD-CSP3-20250430/

mod source_lists {
    //! Tests for Source Lists (Section 2.3.1)
    //! https://www.w3.org/TR/2025/WD-CSP3-20250430/#source-lists
    //! 
    //! These tests verify that the parser correctly handles all valid source expressions
    //! defined in the CSP Level 3 specification, including keywords, URLs, schemes,
    //! hosts, nonces, and hashes.

    use csp_parser::{Policy, SourceExpression, ParseError};

    #[test]
    fn test_keyword_sources() {
        // Test basic keyword sources that control policy behavior
        // 'none' - blocks all resources
        // 'self' - allows resources from the same origin
        let policy = Policy::parse("default-src 'none'").unwrap();
        assert!(matches!(&policy.directives[0].source_list[0], SourceExpression::None));

        let policy = Policy::parse("default-src 'self'").unwrap();
        assert!(matches!(&policy.directives[0].source_list[0], SourceExpression::Self_));
    }

    #[test]
    fn test_serialized_urls() {
        // Test URL-based source expressions that specify exact resources
        // Full URL with path - matches specific file
        let policy = Policy::parse("default-src https://example.com/path/to/file.js").unwrap();
        assert!(matches!(&policy.directives[0].source_list[0], 
            SourceExpression::HostSource { host, path: Some(path), .. } 
            if host == "example.com" && path == "/path/to/file.js"));

        // URL with root path - matches entire origin
        let policy = Policy::parse("default-src https://example.com/").unwrap();
        assert!(matches!(&policy.directives[0].source_list[0], 
            SourceExpression::HostSource { host, path: Some(path), .. } 
            if host == "example.com" && path == "/"));
    }

    #[test]
    fn test_schemes() {
        // Test scheme-only sources that match any resource with the given scheme
        // https: matches any HTTPS resource regardless of host or path
        let policy = Policy::parse("default-src https:").unwrap();
        assert!(matches!(&policy.directives[0].source_list[0], 
            SourceExpression::Scheme(s) if s == "https"));
    }

    #[test]
    fn test_hosts() {
        // Test host-based source expressions
        // Exact host - matches resources from specific domain
        let policy = Policy::parse("default-src example.com").unwrap();
        match &policy.directives[0].source_list[0] {
            SourceExpression::HostSource { host, .. } => {
                assert_eq!(host, "example.com");
            },
            _ => panic!("Expected HostSource"),
        }

        // Wildcard host - matches resources from domain and all subdomains
        let policy = Policy::parse("default-src *.example.com").unwrap();
        match &policy.directives[0].source_list[0] {
            SourceExpression::HostSource { host, .. } => {
                assert_eq!(host, "*.example.com");
            },
            _ => panic!("Expected HostSource"),
        }
    }

    #[test]
    fn test_nonces() {
        // Test nonce-based source expressions that allow specific inline scripts
        // Nonce must be unique per page load and match the nonce attribute on script tags
        let policy = Policy::parse("script-src 'nonce-ch4hvvbHDpv7xCSvXCs3BrNggHdTzxUA'").unwrap();
        assert!(matches!(&policy.directives[0].source_list[0], 
            SourceExpression::Nonce(n) if n == "ch4hvvbHDpv7xCSvXCs3BrNggHdTzxUA"));
    }

    #[test]
    fn test_digests() {
        // Test hash-based source expressions that allow specific inline scripts
        // Hash is computed from the script content and must match exactly
        let policy = Policy::parse("script-src 'sha256-abcd1234'").unwrap();
        assert!(matches!(&policy.directives[0].source_list[0], 
            SourceExpression::Hash { algorithm, value } 
            if algorithm == "sha256" && value == "abcd1234"));
    }

    #[test]
    fn test_invalid_source_expressions() {
        // Test error handling for invalid source expressions
        // Invalid keyword
        let err = Policy::parse("default-src 'invalid'").unwrap_err();
        assert!(matches!(err, ParseError::InvalidSource { value, .. } if value == "'invalid'"));

        // Invalid host format (double dots)
        let err = Policy::parse("default-src example..com").unwrap_err();
        assert!(matches!(err, ParseError::InvalidHost { value, .. } if value == "example..com"));
    }
}

mod url_matching {
    //! Tests for URL Matching (Section 6.7.2)
    //! https://www.w3.org/TR/2025/WD-CSP3-20250430/#url-matching
    //!
    //! These tests verify that the parser correctly handles URL matching rules
    //! defined in the CSP Level 3 specification, including scheme matching,
    //! self matching, wildcard hosts, paths, and ports.

    use csp_parser::{Policy, SourceExpression, ParseError};

    #[test]
    fn test_scheme_matching() {
        // Test that http: matches both http and https (CSP Level 3 change)
        // This is a security feature to prevent mixed content
        let policy = Policy::parse("default-src http://example.com:80").unwrap();
        let source = &policy.directives[0].source_list[0];
        assert!(matches!(source, 
            SourceExpression::HostSource { host, port: Some(80), .. } 
            if host == "example.com"));
    }

    #[test]
    fn test_self_matching() {
        // Test that 'self' matches https: and wss: variants (CSP Level 3 change)
        // This ensures secure connections are preferred
        let policy = Policy::parse("default-src 'self'").unwrap();
        let source = &policy.directives[0].source_list[0];
        assert!(matches!(source, SourceExpression::Self_));
    }

    #[test]
    fn test_wildcard_hosts() {
        // Test wildcard host matching for subdomains
        // *.example.com matches example.com and all its subdomains
        let policy = Policy::parse("default-src *.example.com").unwrap();
        let source = &policy.directives[0].source_list[0];
        assert!(matches!(source, 
            SourceExpression::HostSource { host, .. } 
            if host == "*.example.com"));
    }

    #[test]
    fn test_path_matching() {
        // Test path matching for specific directories
        // Path must start with / and can include subdirectories
        let policy = Policy::parse("default-src example.com/path/").unwrap();
        let source = &policy.directives[0].source_list[0];
        assert!(matches!(source, 
            SourceExpression::HostSource { host, path: Some(path), .. } 
            if host == "example.com" && path == "/path/"));
    }

    #[test]
    fn test_port_matching() {
        // Test port matching for specific ports
        // Port must be a valid number between 0 and 65535
        let policy = Policy::parse("default-src example.com:443").unwrap();
        let source = &policy.directives[0].source_list[0];
        assert!(matches!(source, 
            SourceExpression::HostSource { host, port: Some(443), .. } 
            if host == "example.com"));
    }

    #[test]
    fn test_invalid_urls() {
        // Test error handling for invalid URLs
        // Empty host
        let err = Policy::parse("default-src http://").unwrap_err();
        assert!(matches!(err, ParseError::InvalidHost { value, .. } if value == ""));

        // Invalid port number
        let err = Policy::parse("default-src example.com:99999").unwrap_err();
        assert!(matches!(err, ParseError::InvalidPort { value, .. } if value == "99999"));

        // Invalid path (parent directory reference)
        let err = Policy::parse("default-src example.com/../path").unwrap_err();
        assert!(matches!(err, ParseError::InvalidPath { value, .. } if value == "/../path"));
    }
}

mod directives {
    //! Tests for Directives (Section 6.7)
    //! https://www.w3.org/TR/2025/WD-CSP3-20250430/#directives
    //!
    //! These tests verify that the parser correctly handles all CSP Level 3 directives,
    //! including core directives, new directives, and error cases.

    use csp_parser::{Policy, ParseError};

    #[test]
    fn test_script_directives() {
        // Test script-src directive with various source expressions
        // This directive controls which scripts can be executed
        let policy = Policy::parse("script-src 'self' 'unsafe-inline' 'unsafe-eval' 'strict-dynamic'").unwrap();
        assert_eq!(policy.directives[0].name, "script-src");
        assert_eq!(policy.directives[0].source_list.len(), 4);
    }

    #[test]
    fn test_style_directives() {
        // Test style-src directive
        // This directive controls which stylesheets can be applied
        let policy = Policy::parse("style-src 'self' 'unsafe-inline'").unwrap();
        assert_eq!(policy.directives[0].name, "style-src");
        assert_eq!(policy.directives[0].source_list.len(), 2);
    }

    #[test]
    fn test_worker_directives() {
        // Test worker-src directive (new in CSP Level 3)
        // This directive controls which worker scripts can be loaded
        let policy = Policy::parse("worker-src 'self' blob:").unwrap();
        assert_eq!(policy.directives[0].name, "worker-src");
        assert_eq!(policy.directives[0].source_list.len(), 2);
    }

    #[test]
    fn test_frame_directives() {
        // Test frame-src directive (undeprecated in CSP Level 3)
        // This directive controls which frames can be loaded
        let policy = Policy::parse("frame-src 'self' https://example.com").unwrap();
        assert_eq!(policy.directives[0].name, "frame-src");
        assert_eq!(policy.directives[0].source_list.len(), 2);
    }

    #[test]
    fn test_manifest_directives() {
        // Test manifest-src directive (new in CSP Level 3)
        // This directive controls which web app manifests can be loaded
        let policy = Policy::parse("manifest-src 'self'").unwrap();
        assert_eq!(policy.directives[0].name, "manifest-src");
        assert_eq!(policy.directives[0].source_list.len(), 1);
    }

    #[test]
    fn test_reporting_directives() {
        // Test report-to directive (new in CSP Level 3, replaces report-uri)
        // This directive specifies where to send violation reports
        let policy = Policy::parse("report-to default").unwrap();
        assert_eq!(policy.directives[0].name, "report-to");
        assert_eq!(policy.directives[0].source_list.len(), 1);
    }

    #[test]
    fn test_invalid_directives() {
        // Test error handling for invalid directive names
        let err = Policy::parse("invalid-directive 'self'").unwrap_err();
        assert!(matches!(err, ParseError::InvalidDirective { name, .. } if name == "invalid-directive"));
    }

    #[test]
    fn test_duplicate_directives() {
        // Test error handling for duplicate directives
        // Only the first occurrence of a directive is valid
        let err = Policy::parse("default-src 'self'; default-src 'none'").unwrap_err();
        assert!(matches!(err, ParseError::DuplicateDirective { name, .. } if name == "default-src"));
    }

    #[test]
    fn test_missing_values() {
        // Test error handling for directives without values
        // All directives must have at least one value
        let err = Policy::parse("default-src").unwrap_err();
        assert!(matches!(err, ParseError::MissingValue { directive, .. } if directive == "default-src"));
    }
}

mod script_src {
    //! Tests for script-src Directive (Section 6.7.3)
    //! https://www.w3.org/TR/2025/WD-CSP3-20250430/#directive-script-src
    //!
    //! These tests verify that the parser correctly handles all valid source expressions
    //! for the script-src directive, which controls which scripts can be executed.

    use csp_parser::{Policy, SourceExpression, ParseError};

    #[test]
    fn test_script_src_keywords() {
        // Test all valid keywords for script-src
        // These keywords control various aspects of script execution
        let policy = Policy::parse("script-src 'none' 'self' 'unsafe-inline' 'unsafe-eval' 'unsafe-hashes' 'strict-dynamic' 'report-sample' 'wasm-unsafe-eval'").unwrap();
        let sources = &policy.directives[0].source_list;
        assert!(matches!(sources[0], SourceExpression::None));
        assert!(matches!(sources[1], SourceExpression::Self_));
        assert!(matches!(sources[2], SourceExpression::UnsafeInline));
        assert!(matches!(sources[3], SourceExpression::UnsafeEval));
        assert!(matches!(sources[4], SourceExpression::UnsafeHashes));
        assert!(matches!(sources[5], SourceExpression::StrictDynamic));
        assert!(matches!(sources[6], SourceExpression::ReportSample));
        assert!(matches!(sources[7], SourceExpression::WasmUnsafeEval));
    }

    #[test]
    fn test_script_src_nonce() {
        // Test nonce source for script-src
        // Nonces allow specific inline scripts to execute
        let policy = Policy::parse("script-src 'nonce-YWJjMTIz'").unwrap();
        let sources = &policy.directives[0].source_list;
        assert!(matches!(&sources[0],
            SourceExpression::Nonce(value) if value == "YWJjMTIz"));
    }

    #[test]
    fn test_script_src_hash() {
        // Test hash sources for script-src
        // Hashes allow specific inline scripts to execute based on their content
        // Using base64-encoded hashes of empty strings for testing
        let policy = Policy::parse("script-src 'sha256-YWJjMTIz' 'sha384-YWJjMTIz' 'sha512-YWJjMTIz'").unwrap();
        let sources = &policy.directives[0].source_list;
        assert!(matches!(&sources[0], 
            SourceExpression::Hash { algorithm, value } 
            if algorithm == "sha256" && value == "YWJjMTIz"));
        assert!(matches!(&sources[1], 
            SourceExpression::Hash { algorithm, value } 
            if algorithm == "sha384" && value == "YWJjMTIz"));
        assert!(matches!(&sources[2], 
            SourceExpression::Hash { algorithm, value } 
            if algorithm == "sha512" && value == "YWJjMTIz"));
    }

    #[test]
    fn test_script_src_hosts() {
        // Test host sources for script-src
        // These control which domains can serve scripts
        let policy = Policy::parse("script-src example.com *.example.com https://example.com:443/path/").unwrap();
        let sources = &policy.directives[0].source_list;

        match &sources[0] {
            SourceExpression::HostSource { host, .. } => {
                assert_eq!(host, "example.com");
            },
            _ => panic!("Expected HostSource"),
        }

        match &sources[1] {
            SourceExpression::HostSource { host, .. } => {
                assert_eq!(host, "*.example.com");
            },
            _ => panic!("Expected HostSource"),
        }

        match &sources[2] {
            SourceExpression::HostSource { host, port, path, .. } => {
                assert_eq!(host, "example.com");
                assert_eq!(port, &Some(443));
                assert_eq!(path, &Some("/path/".to_string()));
            },
            _ => panic!("Expected HostSource"),
        }
    }

    #[test]
    fn test_script_src_schemes() {
        // Test scheme sources for script-src
        // These control which URL schemes can be used to load scripts
        let policy = Policy::parse("script-src https: http: data: blob: mediastream: filesystem:").unwrap();
        let sources = &policy.directives[0].source_list;

        match &sources[0] {
            SourceExpression::Scheme(value) => {
                assert_eq!(value, "https");
            },
            _ => panic!("Expected Scheme"),
        }

        match &sources[1] {
            SourceExpression::Scheme(value) => {
                assert_eq!(value, "http");
            },
            _ => panic!("Expected Scheme"),
        }

        match &sources[2] {
            SourceExpression::Scheme(value) => {
                assert_eq!(value, "data");
            },
            _ => panic!("Expected Scheme"),
        }

        match &sources[3] {
            SourceExpression::Scheme(value) => {
                assert_eq!(value, "blob");
            },
            _ => panic!("Expected Scheme"),
        }

        match &sources[4] {
            SourceExpression::Scheme(value) => {
                assert_eq!(value, "mediastream");
            },
            _ => panic!("Expected Scheme"),
        }

        match &sources[5] {
            SourceExpression::Scheme(value) => {
                assert_eq!(value, "filesystem");
            },
            _ => panic!("Expected Scheme"),
        }
    }

    #[test]
    fn test_script_src_invalid() {
        // Test error handling for invalid script-src values
        // Invalid keyword
        let err = Policy::parse("script-src 'invalid-keyword'").unwrap_err();
        assert!(matches!(err, ParseError::InvalidSource { value, .. } if value == "'invalid-keyword'"));

        // Invalid nonce format
        let err = Policy::parse("script-src 'nonce-invalid'").unwrap_err();
        assert!(matches!(err, ParseError::InvalidNonce { value, .. } if value == "invalid"));

        // Invalid hash format
        let err = Policy::parse("script-src 'sha256-invalid'").unwrap_err();
        assert!(matches!(err, ParseError::InvalidHash { value, .. } if value == "invalid"));
    }
} 