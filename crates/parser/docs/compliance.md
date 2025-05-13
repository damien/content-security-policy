# CSP Level 3 Compliance Testing

This document outlines how the test suite validates adherence to the Content Security Policy Level 3 specification.

## Test Organization

Tests are organized into modules that correspond to key sections of the CSP Level 3 specification:

### Source Lists (Section 2.3.1)

Tests validate parsing of source expressions:
- Keyword sources (`'none'`, `'self'`)
- Serialized URLs (specific files and origins)
- Scheme-only sources (`https:`, `http:`)
- Host sources (including wildcards)
- Nonce sources
- Hash-based sources (SHA-256, SHA-384, SHA-512)

### URL Matching (Section 6.7.2)

Tests verify the URL matching algorithm:
- Scheme matching (http: matches both http and https)
- Self matching (matches https: and wss: variants)
- Wildcard host matching
- Path matching
- Port matching
- Invalid URL handling

### Directives (Section 6.7)

Tests cover all CSP Level 3 directives:
- Core directives (default-src, script-src, style-src)
- New directives (worker-src, manifest-src)
- Undeprecated directives (frame-src)
- Reporting directives (report-to)
- Invalid/duplicate/missing directive handling

### Script Directive (Section 6.7.3)

Tests validate script-src specific features:
- All valid keywords
- Nonce sources
- Hash sources
- Host sources
- Scheme sources
- Invalid value handling

## Running Compliance Tests

To run all compliance tests:

```bash
cargo test --test csp3_compliance
```

To run tests for a specific section:

```bash
cargo test --test csp3_compliance source_lists
cargo test --test csp3_compliance url_matching
cargo test --test csp3_compliance directives
cargo test --test csp3_compliance script_src
```

## Test Coverage

The test suite ensures compliance by:

1. Testing all valid source expressions defined in the spec
2. Verifying correct parsing of CSP Level 3 specific features
3. Validating error handling for invalid inputs
4. Testing edge cases and boundary conditions
5. Ensuring proper handling of new CSP Level 3 features

## Adding New Tests

When adding new tests:

1. Reference the specific section of the CSP Level 3 spec
2. Include both valid and invalid test cases
3. Document the expected behavior
4. Place tests in the appropriate module
5. Follow the existing test patterns

## References

- [CSP Level 3 Specification](https://www.w3.org/TR/2025/WD-CSP3-20250430/)
- [Source Lists](https://www.w3.org/TR/2025/WD-CSP3-20250430/#source-lists)
- [URL Matching](https://www.w3.org/TR/2025/WD-CSP3-20250430/#url-matching)
- [Directives](https://www.w3.org/TR/2025/WD-CSP3-20250430/#directives)
- [Script Directive](https://www.w3.org/TR/2025/WD-CSP3-20250430/#directive-script-src) 