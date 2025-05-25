use nom::{
    branch::alt,
    bytes::complete::{tag, take_while},
    character::complete::{char, space0},
    combinator::{map, opt},
    IResult,
    sequence::delimited,
    Parser,
};

use crate::error::ParseError;

/// A source expression as defined in CSP Level 3.
#[derive(Debug, Clone, PartialEq)]
pub enum SourceExpression {
    /// The 'none' keyword source.
    None,
    /// The 'self' keyword source.
    Self_,
    /// The 'unsafe-inline' keyword source.
    UnsafeInline,
    /// The 'unsafe-eval' keyword source.
    UnsafeEval,
    /// The 'unsafe-hashes' keyword source.
    UnsafeHashes,
    /// The 'strict-dynamic' keyword source.
    StrictDynamic,
    /// The 'report-sample' keyword source.
    ReportSample,
    /// The 'wasm-unsafe-eval' keyword source.
    WasmUnsafeEval,
    /// A nonce source expression.
    Nonce(String),
    /// A hash source expression with algorithm and value.
    Hash {
        /// The hash algorithm (e.g., "sha256", "sha384", "sha512").
        algorithm: String,
        /// The hash value.
        value: String,
    },
    /// A scheme source expression.
    Scheme(String),
    /// A host source expression.
    HostSource {
        /// The host value (e.g., "example.com", "*.example.com").
        host: String,
        /// Optional port number.
        port: Option<u16>,
        /// Optional path.
        path: Option<String>,
    },
}

/// Parse a keyword source expression.
fn parse_keyword(input: &str) -> IResult<&str, SourceExpression, ParseError> {
    let res = alt((
        map(tag("'none'"), |_| SourceExpression::None),
        map(tag("'self'"), |_| SourceExpression::Self_),
        map(tag("'unsafe-inline'"), |_| SourceExpression::UnsafeInline),
        map(tag("'unsafe-eval'"), |_| SourceExpression::UnsafeEval),
        map(tag("'unsafe-hashes'"), |_| SourceExpression::UnsafeHashes),
        map(tag("'strict-dynamic'"), |_| SourceExpression::StrictDynamic),
        map(tag("'report-sample'"), |_| SourceExpression::ReportSample),
        map(tag("'wasm-unsafe-eval'"), |_| SourceExpression::WasmUnsafeEval),
    )).parse(input);
    match res {
        Err(nom::Err::Error(_)) | Err(nom::Err::Failure(_)) if input.starts_with("'") => {
            // If it looks like a keyword but is not valid, treat as invalid source
            let end = input.find(' ').unwrap_or(input.len());
            let value = &input[..end];
            Err(nom::Err::Failure(ParseError::InvalidSource { 
                value: value.to_string(), 
                position: 0 
            }))
        }
        _ => res,
    }
}

/// Validate if a string contains valid base64 characters according to CSP Level 3 spec.
/// CSP Level 3 is more permissive than standard base64:
/// - Allows both standard base64 chars (A-Z, a-z, 0-9, +, /, =) and URL-safe chars (-, _)
/// - Doesn't require decodability, only proper format
/// - The value should be non-empty and contain only valid base64 characters
/// - If padding is present, it must be at the end (1-2 '=' chars)
fn is_valid_base64(s: &str) -> bool {
    // Check if empty
    if s.is_empty() {
        return false;
    }

    // Only base64 chars (both standard and URL-safe)
    if !s.chars().all(|c| 
        c.is_ascii_alphanumeric() || 
        c == '+' || c == '/' || c == '=' || 
        c == '-' || c == '_'
    ) {
        return false;
    }

    // Padding check: must be at the end
    if let Some(idx) = s.find('=') {
        if s[idx..].chars().any(|c| c != '=') {
            return false;
        }
        // At most 2 padding chars
        let padding_len = s.len() - idx;
        if padding_len > 2 {
            return false;
        }
    }
    
    // CSP Level 3 only requires valid base64 characters, not strict format
    true
}

/// Parse a nonce source expression.
/// 
/// According to CSP Level 3, nonce values must:
/// 1. Contain only valid base64 characters
/// 2. Have correct padding if padding is present
/// 3. Be non-empty
///
/// Note: CSP Level 3 does not require nonces to be decodable.
fn parse_nonce(input: &str) -> IResult<&str, SourceExpression, ParseError> {
    let (input, _) = tag("'nonce-")(input)?;
    let (input, value) = take_while(|c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '+' || c == '/' || c == '=')(input)?;
    let (input, end) = nom::combinator::opt(char('\'')).parse(input)?;
    
    if value.is_empty() || !is_valid_base64(value) {
        return Err(nom::Err::Failure(ParseError::InvalidNonce {
            value: value.to_string(),
            position: 0,
        }));
    }
    if end.is_none() {
        return Err(nom::Err::Failure(ParseError::InvalidNonce {
            value: format!("'nonce-{}", value),
            position: 0,
        }));
    }
    Ok((input, SourceExpression::Nonce(value.to_string())))
}

/// Parse a hash source expression.
/// 
/// According to CSP Level 3, hash values must:
/// 1. Contain only valid base64 characters
/// 2. Have correct padding if padding is present
/// 3. Be non-empty
///
/// Per CSP Level 3, hash values represent digests but strict validation of 
/// decodability is not required at the parsing level.
fn parse_hash(input: &str) -> IResult<&str, SourceExpression, ParseError> {
    let (input, _) = char('\'').parse(input)?;
    let (input, algorithm) = alt((
        tag("sha256-"),
        tag("sha384-"),
        tag("sha512-"),
    )).parse(input)?;
    let (input, value) = take_while(|c: char| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=').parse(input)?;
    let (input, end) = nom::combinator::opt(char('\'')).parse(input)?;

    if value.is_empty() || !is_valid_base64(value) {
        return Err(nom::Err::Failure(ParseError::InvalidHash {
            value: value.to_string(),
            position: 0,
        }));
    }
    
    if end.is_none() {
        return Err(nom::Err::Failure(ParseError::InvalidHash {
            value: format!("'{}{}", &algorithm[..algorithm.len()-1], value),
            position: 0,
        }));
    }
    Ok((input, SourceExpression::Hash {
        algorithm: algorithm[..algorithm.len()-1].to_string(),
        value: value.to_string(),
    }))
}

/// Parse a port number, ensuring it's valid per CSP Level 3.
fn parse_port(port_str: &str) -> Result<Option<u16>, ParseError> {
    if port_str.is_empty() {
        return Ok(None);
    }
    
    // Ports that can't be parsed as u16 are invalid; they either exceed the maximum port number or are not a valid number.
    match port_str.parse::<u16>() {
        Ok(port_num) => Ok(Some(port_num)),
        _ => Err(ParseError::InvalidPort { 
            value: port_str.to_string(), 
            position: 0,
        }),
    }
}

/// Parse a host source expression.
fn parse_host(input: &str) -> IResult<&str, SourceExpression, ParseError> {
    // Host with port pattern: check for invalid port before regular parsing
    if let Some(colon_idx) = input.find(':') {
        if colon_idx + 1 < input.len() {
            let port_str = &input[colon_idx + 1..];
            let end_idx = port_str.find(|c| c == '/' || c == ' ' || c == ';').unwrap_or(port_str.len());
            let port_val = &port_str[..end_idx];
            
            // Propogate the error if the port is invalid;
            // Ensure the position is the index of the port in the input string, not the parsed port.
            if let Err(_) = parse_port(port_val) {
                return Err(nom::Err::Failure(ParseError::InvalidPort { 
                    value: port_val.to_string(), 
                    position: colon_idx + 1
                }));
            }
        }
    }
    
    let (input, host) = take_while(|c: char| c.is_alphanumeric() || c == '.' || c == '*' || c == '-').parse(input)?;
    if host.is_empty() {
        return Err(nom::Err::Failure(ParseError::InvalidHost { 
            value: "".to_string(), 
            position: 0 
        }));
    }
    if host.contains("..") {
        return Err(nom::Err::Failure(ParseError::InvalidHost { 
            value: host.to_string(), 
            position: 0 
        }));
    }
    // Validate wildcard subdomain format
    if host.contains('*') {
        if !host.starts_with("*.") || host.matches('*').count() > 1 {
            return Err(nom::Err::Failure(ParseError::InvalidHost { 
                value: host.to_string(), 
                position: 0 
            }));
        }
    }
    
    let (input, port_str) = opt(delimited(
        char(':'),
        take_while(|c: char| c.is_ascii_digit()),
        space0,
    )).parse(input)?;
    
    let port = match port_str {
        Some(p) => match parse_port(p) {
            Ok(port_val) => port_val,
            Err(e) => return Err(nom::Err::Failure(e)),
        },
        None => None,
    };
    
    let (input, path_str) = opt(delimited(
        char('/'),
        take_while(|c: char| c.is_alphanumeric() || c == '/' || c == '-' || c == '_' || c == '.' || c == '~'),
        space0,
    )).parse(input)?;
    
    let path = match path_str {
        Some(p) => {
            if p.split('/').any(|seg| seg == "..") {
                return Err(nom::Err::Failure(ParseError::InvalidPath { 
                    value: format!("/{p}"), 
                    position: 0 
                }));
            }
            Some(format!("/{p}"))
        },
        None => None,
    };
    
    Ok((input, SourceExpression::HostSource {
        host: host.to_string(),
        port,
        path,
    }))
}

/// Check if a string contains a host with a port.
/// 
/// This is used to determine if a string is a host with a port, or a scheme.
fn is_host_with_port(input: &str) -> bool {
    input.contains(':') &&
    input.chars().position(|c| c == ':').map(|pos| pos + 1 < input.len() &&
    input.chars().nth(pos + 1).map(|c| c.is_ascii_digit()).unwrap_or(false)).unwrap_or(false)
}

/// Parse a scheme source expression.
fn parse_scheme(input: &str) -> IResult<&str, SourceExpression, ParseError> {
    // Don't parse as scheme if it contains a colon followed by a digit
    // This likely indicates a host with port (example.com:443)
    if is_host_with_port(input) {
        return Err(nom::Err::Error(ParseError::InvalidSource {
            value: input.to_string(),
            position: 0,
        }));
    }

    let (input, scheme) = take_while(|c: char| c.is_alphanumeric() || c == '+' || c == '-' || c == '.').parse(input)?;
    if scheme.is_empty() {
        return Err(nom::Err::Error(ParseError::InvalidSource {
            value: scheme.to_string(),
            position: 0,
        }));
    }
    // Require ':' not followed by '/'
    let (input, _) = char(':').parse(input)?;
    if !input.is_empty() && input.starts_with('/') {
        return Err(nom::Err::Error(ParseError::InvalidSource {
            value: format!("{scheme}:{input}"),
            position: 0,
        }));
    }
    Ok((input, SourceExpression::Scheme(scheme.to_string())))
}

/// Parse a scheme+host source expression.
fn parse_scheme_host(input: &str) -> IResult<&str, SourceExpression, ParseError> {    
    let (input, scheme) = take_while(|c: char| c.is_alphanumeric() || c == '+' || c == '-' || c == '.').parse(input)?;
    if scheme.is_empty() {
        return Err(nom::Err::Error(ParseError::InvalidSource { 
            value: scheme.to_string(), 
            position: 0 
        }));
    }
    // Require '://' after scheme
    let (input, _) = tag("://").parse(input)?;
    let (input, host) = take_while(|c: char| c.is_alphanumeric() || c == '.' || c == '*' || c == '-').parse(input)?;
    if host.is_empty() {
        return Err(nom::Err::Failure(ParseError::InvalidHost { 
            value: "".to_string(), 
            position: 0 
        }));
    }
    if host.contains("..") {
        return Err(nom::Err::Failure(ParseError::InvalidHost { 
            value: host.to_string(), 
            position: 0 
        }));
    }
    // Validate wildcard subdomain format
    if host.contains('*') {
        if !host.starts_with("*.") || host.matches('*').count() > 1 {
            return Err(nom::Err::Failure(ParseError::InvalidHost { 
                value: host.to_string(), 
                position: 0 
            }));
        }
    }
    
    let (input, port_str) = opt(delimited(
        char(':'),
        take_while(|c: char| c.is_ascii_digit()),
        space0,
    )).parse(input)?;
    
    let port = match port_str {
        Some(p) => match parse_port(p) {
            Ok(port_val) => port_val,
            Err(e) => return Err(nom::Err::Failure(e)),
        },
        None => None,
    };
    
    let (input, path) = opt(delimited(
        char('/'),
        take_while(|c: char| c.is_alphanumeric() || c == '/' || c == '-' || c == '_' || c == '.' || c == '~'),
        space0,
    )).parse(input)?;
    let path = match path {
        Some(p) => {
            if p.split('/').any(|seg| seg == "..") {
                return Err(nom::Err::Failure(ParseError::InvalidPath { 
                    value: format!("/{p}"), 
                    position: 0 
                }));
            }
            Some(format!("/{p}"))
        }
        None => None,
    };
    Ok((input, SourceExpression::HostSource {
        host: host.to_string(),
        port,
        path,
    }))
}

/// Parse a source expression.
pub fn parse_source_expression(input: &str) -> IResult<&str, SourceExpression, ParseError> {    
    // Try each parser in order
    // We need special error handling to support script-src test cases with specific error types
    
    match parse_keyword(input) {
        Ok(result) => return Ok(result),
        Err(nom::Err::Error(_)) => {}, // Try next parser
        Err(e) => return Err(e),      // Propagate Failure errors
    }
    
    match parse_nonce(input) {
        Ok(result) => return Ok(result),
        Err(nom::Err::Error(_)) => {}, // Try next parser
        Err(e) => return Err(e),      // Propagate Failure errors
    }
    
    match parse_hash(input) {
        Ok(result) => return Ok(result),
        Err(nom::Err::Error(_)) => {}, // Try next parser
        Err(e) => return Err(e),      // Propagate Failure errors
    }
    
    // Try to parse host expressions before scheme expressions if the input contains a port
    // This ensures "example.com:443" is parsed as a host with port, not a scheme
    if is_host_with_port(input) {
        match parse_host(input) {
            Ok(result) => return Ok(result),
            Err(nom::Err::Error(_)) => {}, // Try next parser
            Err(e) => return Err(e),      // Propagate Failure errors
        }
        
        match parse_scheme_host(input) {
            Ok(result) => return Ok(result),
            Err(nom::Err::Error(_)) => {}, // Try next parser
            Err(e) => return Err(e),      // Propagate Failure errors
        }
        
        // If all parsers failed, create a generic error
        return Err(nom::Err::Error(ParseError::InvalidSource {
            value: input.to_string(),
            position: 0,
        }));

    } else {
        // Try to parse scheme expressions before host expressions
        // This ensures "https:" is parsed as a scheme, not a host
        match parse_scheme(input) {
            Ok(result) => return Ok(result),
            Err(nom::Err::Error(_)) => {}, // Try next parser
            Err(e) => return Err(e),      // Propagate Failure errors
        }
        
        match parse_scheme_host(input) {
            Ok(result) => return Ok(result),
            Err(nom::Err::Error(_)) => {}, // Try next parser
            Err(e) => return Err(e),      // Propagate Failure errors
        }
        
        match parse_host(input) {
            Ok(result) => return Ok(result),
            Err(nom::Err::Error(_)) => {
                // If all previous parsers failed, create a generic error
                return Err(nom::Err::Error(ParseError::InvalidSource {
                    value: input.to_string(),
                    position: 0,
                }));
            },
            Err(e) => return Err(e),      // Propagate Failure errors
        }
    }
}


/// Parse a source list.
pub fn parse_source_list(input: &str) -> IResult<&str, Vec<SourceExpression>, ParseError> {
    let (input, _) = space0(input)?;
    let mut remaining = input;
    let mut sources = Vec::new();
    loop {
        let trimmed = remaining.trim_start();
        if trimmed.is_empty() || trimmed.starts_with(';') {
            break;
        }
        
        // Special handling for 'nonce-' and hash values
        let (rest, source) = if trimmed.starts_with("'nonce-") {
            // Extract nonce value
            if let Some(start_idx) = trimmed.find("'nonce-") {
                let value_start = start_idx + 7; // Length of "'nonce-"
                if let Some(end_idx) = trimmed[value_start..].find('\'') {
                    let value = &trimmed[value_start..(value_start + end_idx)];
                    
                    // Validate the nonce is valid base64
                    if value.is_empty() || !is_valid_base64(value) {
                        return Err(nom::Err::Failure(ParseError::InvalidNonce {
                            value: value.to_string(),
                            position: 0,
                        }));
                    }
                    
                    let real_end = value_start + end_idx + 1; // +1 for closing quote
                    ((&trimmed[real_end..]).trim_start(), SourceExpression::Nonce(value.to_string()))
                } else {
                    match parse_source_expression(trimmed) {
                        Ok(res) => res,
                        Err(e) => return Err(e),
                    }
                }
            } else {
                match parse_source_expression(trimmed) {
                    Ok(res) => res,
                    Err(e) => return Err(e),
                }
            }
        } else if trimmed.starts_with("'sha256-") || trimmed.starts_with("'sha384-") || trimmed.starts_with("'sha512-") {
            // Extract hash algorithm and value
            let dash_pos = trimmed.find('-').unwrap_or(0);
            let algorithm = &trimmed[1..dash_pos];
            
            if let Some(start_idx) = trimmed.find('\'') {
                if let Some(end_idx) = trimmed[start_idx+1..].find('\'') {
                    let value_start = dash_pos + 1;
                    let value_end = start_idx + 1 + end_idx;
                    let value = &trimmed[value_start..value_end];
                    
                    // Validate the hash is valid base64
                    if value.is_empty() || !is_valid_base64(value) {
                        return Err(nom::Err::Failure(ParseError::InvalidHash {
                            value: value.to_string(),
                            position: 0,
                        }));
                    }
                    
                    ((&trimmed[value_end+1..]).trim_start(), SourceExpression::Hash {
                        algorithm: algorithm.to_string(),
                        value: value.to_string(),
                    })
                } else {
                    match parse_source_expression(trimmed) {
                        Ok(res) => res,
                        Err(e) => return Err(e),
                    }
                }
            } else {
                match parse_source_expression(trimmed) {
                    Ok(res) => res,
                    Err(e) => return Err(e),
                }
            }
        } else {
            // Normal parsing
            match parse_source_expression(trimmed) {
                Ok(res) => res,
                Err(e) => return Err(e),
            }
        };
        
        sources.push(source);
        remaining = rest;
    }
    Ok((remaining, sources))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_base64() {
        // Valid base64 strings
        assert!(is_valid_base64("YWJjMTIz"), "Standard base64 without padding");
        assert!(is_valid_base64("YWJjMTIz=="), "Standard base64 with padding");
        assert!(is_valid_base64("YWJj"), "4-character standard base64");
        assert!(is_valid_base64("abcd1234"), "Alphanumeric only");
        assert!(is_valid_base64("abc+/="), "With standard base64 special chars");
        assert!(is_valid_base64("abc-_="), "With URL-safe base64 chars");
        assert!(is_valid_base64("YQ=="), "Single char with double padding");
        assert!(is_valid_base64("YWE="), "Two chars with single padding");
        assert!(is_valid_base64("YWJjMTIz="), "Non-standard padding but valid for CSP");
        // Valid short values (CSP Level 3 doesn't require multiple of 4)
        assert!(is_valid_base64("abc"), "Short value is valid in CSP Level 3");
        
        // Invalid base64 strings
        assert!(!is_valid_base64(""), "Empty string");
        assert!(!is_valid_base64("a=bc"), "Padding not at end");
        assert!(!is_valid_base64("abc==="), "Too much padding");
        assert!(!is_valid_base64("abc!"), "Invalid character");
    }
    
    #[test]
    fn test_parse_keyword() {
        assert_eq!(parse_keyword("'none'"), Ok(("", SourceExpression::None)));
        assert_eq!(parse_keyword("'self'"), Ok(("", SourceExpression::Self_)));
        assert_eq!(parse_keyword("'unsafe-inline'"), Ok(("", SourceExpression::UnsafeInline)));
        assert_eq!(parse_keyword("'unsafe-eval'"), Ok(("", SourceExpression::UnsafeEval)));
        assert_eq!(parse_keyword("'unsafe-hashes'"), Ok(("", SourceExpression::UnsafeHashes)));
        assert_eq!(parse_keyword("'strict-dynamic'"), Ok(("", SourceExpression::StrictDynamic)));
        assert_eq!(parse_keyword("'report-sample'"), Ok(("", SourceExpression::ReportSample)));
        assert_eq!(parse_keyword("'wasm-unsafe-eval'"), Ok(("", SourceExpression::WasmUnsafeEval)));
    }

    #[test]
    fn test_parse_nonce() {
        // Valid base64 nonce
        assert_eq!(
            parse_nonce("'nonce-YWJjMTIz'"),
            Ok(("", SourceExpression::Nonce("YWJjMTIz".to_string())))
        );
        // Valid base64 nonce with padding
        assert_eq!(
            parse_nonce("'nonce-YWJjMTIz=='"),
            Ok(("", SourceExpression::Nonce("YWJjMTIz==".to_string())))
        );
        // Valid: base64 characters, no padding, not decodable
        assert_eq!(
            parse_nonce("'nonce-abc123'"),
            Ok(("", SourceExpression::Nonce("abc123".to_string())))
        );
        // Valid: CSP test suite real-world example
        assert_eq!(
            parse_nonce("'nonce-ch4hvvbHDpv7xCSvXCs3BrNggHdTzxUA'"),
            Ok(("", SourceExpression::Nonce("ch4hvvbHDpv7xCSvXCs3BrNggHdTzxUA".to_string())))
        );
        // Valid: base64 characters, correct padding, not decodable
        assert_eq!(
            parse_nonce("'nonce-abc1=='"),
            Ok(("", SourceExpression::Nonce("abc1==".to_string())))
        );
        // Invalid: empty
        assert!(parse_nonce("'nonce-'").is_err(), "Empty value should be invalid");
        // Invalid: not base64 (illegal chars)
        assert!(parse_nonce("'nonce-!@#'").is_err(), "Illegal chars should be invalid");
        // Invalid: incorrect padding (padding not at end)
        assert!(parse_nonce("'nonce-YWJjMTIz=Y'").is_err(), "Padding not at end should be invalid");
        // Valid: not decodable, but valid base64 chars and correct padding
        assert_eq!(
            parse_nonce("'nonce-zzzzzzzz'"),
            Ok(("", SourceExpression::Nonce("zzzzzzzz".to_string())))
        );
    }

    #[test]
    fn test_parse_hash() {
        // Valid base64 hash
        assert_eq!(
            parse_hash("'sha256-YWJjMTIz'"),
            Ok(("", SourceExpression::Hash {
                algorithm: "sha256".to_string(),
                value: "YWJjMTIz".to_string(),
            }))
        );
        // Valid: padding, matches CSP test case
        assert_eq!(
            parse_hash("'sha256-YWJjMTIz=='"),
            Ok(("", SourceExpression::Hash {
                algorithm: "sha256".to_string(),
                value: "YWJjMTIz==".to_string(),
            }))
        );
        // Valid: real-world value
        assert_eq!(
            parse_hash("'sha256-abcd1234'"),
            Ok(("", SourceExpression::Hash {
                algorithm: "sha256".to_string(),
                value: "abcd1234".to_string(),
            }))
        );
        // Invalid: empty
        assert!(parse_hash("'sha256-'").is_err(), "Empty hash should be rejected");
        // Invalid: not base64 (has invalid chars)
        assert!(parse_hash("'sha256-!@#'").is_err(), "Hash with invalid chars should be rejected");
        // Invalid: incorrect padding
        assert!(parse_hash("'sha256-YWJjMTIz=Y'").is_err(), "Incorrect padding should be rejected");
    }

    #[test]
    fn test_parse_scheme() {
        assert_eq!(
            parse_scheme("https:"),
            Ok(("", SourceExpression::Scheme("https".to_string())))
        );
        assert!(parse_scheme("").is_err());
        assert!(parse_scheme("https://").is_err());
    }

    #[test]
    fn test_parse_host() {
        assert_eq!(
            parse_host("example.com"),
            Ok(("", SourceExpression::HostSource {
                host: "example.com".to_string(),
                port: None,
                path: None,
            }))
        );
        assert_eq!(
            parse_host("example.com:8080"),
            Ok(("", SourceExpression::HostSource {
                host: "example.com".to_string(),
                port: Some(8080),
                path: None,
            }))
        );
        assert_eq!(
            parse_host("example.com/path"),
            Ok(("", SourceExpression::HostSource {
                host: "example.com".to_string(),
                port: None,
                path: Some("/path".to_string()),
            }))
        );
        assert!(parse_host("").is_err());
        assert!(parse_host("example..com").is_err());
    }

    #[test]
    fn test_parse_host_wildcard() {
        // Valid wildcard subdomain
        assert_eq!(
            parse_host("*.example.com"),
            Ok(("", SourceExpression::HostSource {
                host: "*.example.com".to_string(),
                port: None,
                path: None,
            }))
        );
        // Invalid: multiple wildcards
        assert!(parse_host("*.*.example.com").is_err());
        // Invalid: wildcard not at start
        assert!(parse_host("sub.*.example.com").is_err());
        // Invalid: wildcard without dot
        assert!(parse_host("*example.com").is_err());
    }

    #[test]
    fn test_parse_scheme_host_wildcard() {
        // Valid wildcard subdomain with scheme
        assert_eq!(
            parse_scheme_host("https://*.example.com"),
            Ok(("", SourceExpression::HostSource {
                host: "*.example.com".to_string(),
                port: None,
                path: None,
            }))
        );
        // Invalid: multiple wildcards
        assert!(parse_scheme_host("https://*.*.example.com").is_err());
        // Invalid: wildcard not at start
        assert!(parse_scheme_host("https://sub.*.example.com").is_err());
        // Invalid: wildcard without dot
        assert!(parse_scheme_host("https://*example.com").is_err());
    }

    #[test]
    fn test_parse_source_list() {
        assert_eq!(
            parse_source_list("'self' 'unsafe-inline'"),
            Ok(("", vec![
                SourceExpression::Self_,
                SourceExpression::UnsafeInline,
            ]))
        );
        assert_eq!(
            parse_source_list("'self' https://example.com"),
            Ok(("", vec![
                SourceExpression::Self_,
                SourceExpression::HostSource {
                    host: "example.com".to_string(),
                    port: None,
                    path: None,
                },
            ]))
        );
    }
}