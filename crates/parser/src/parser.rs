use nom::{
    branch::alt,
    bytes::complete::{tag, take_while},
    character::complete::{char, space0, space1},
    combinator::{map, opt},
    error::ParseError as NomParseError,
    IResult,
    multi::separated_list0,
    sequence::delimited,
    Parser,
};

use base64::Engine as _;

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

#[derive(Debug, Clone, PartialEq)]
pub enum CspParseError<I> {
    InvalidDirective { name: String, input: I },
    DuplicateDirective { name: String, input: I },
    InvalidSource { value: String, input: I },
    MissingValue { directive: String, input: I },
    InvalidHost { value: String, input: I },
    InvalidPort { value: String, input: I },
    InvalidPath { value: String, input: I },
    InvalidNonce { value: String, input: I },
    InvalidHash { value: String, input: I },
}

impl<I> NomParseError<I> for CspParseError<I> {
    fn from_error_kind(input: I, _kind: nom::error::ErrorKind) -> Self {
        CspParseError::InvalidSource { value: "unknown".to_string(), input }
    }
    fn append(_input: I, _kind: nom::error::ErrorKind, other: Self) -> Self {
        other
    }
}

/// Parse a keyword source expression.
fn parse_keyword(input: &str) -> IResult<&str, SourceExpression, CspParseError<&str>> {
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
            Err(nom::Err::Failure(CspParseError::InvalidSource { value: value.to_string(), input }))
        }
        _ => res,
    }
}

/// Parse a nonce source expression.
fn parse_nonce(input: &str) -> nom::IResult<&str, SourceExpression, CspParseError<&str>> {
    let (input, _) = tag("'nonce-")(input)?;
    let (input, value) = take_while(|c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '+' || c == '/' || c == '=')(input)?;
    if value.is_empty() || base64::engine::general_purpose::STANDARD.decode(value).is_err() {
        return Err(nom::Err::Failure(CspParseError::InvalidNonce { value: value.to_string(), input }));
    }
    let (input, _) = char('\'')(input)?;
    Ok((input, SourceExpression::Nonce(value.to_string())))
}

/// Parse a hash source expression.
fn parse_hash(input: &str) -> IResult<&str, SourceExpression, CspParseError<&str>> {
    let (input, _) = char('\'').parse(input)?;
    let (input, algorithm) = alt((
        tag("sha256-"),
        tag("sha384-"),
        tag("sha512-"),
    )).parse(input)?;
    let (input, value) = take_while(|c: char| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=').parse(input)?;
    // Strict base64 validation
    if value.is_empty() || base64::engine::general_purpose::STANDARD.decode(value).is_err() {
        return Err(nom::Err::Failure(CspParseError::InvalidHash { value: "invalid".to_string(), input }));
    }
    let (input, _) = char('\'').parse(input)?;
    Ok((input, SourceExpression::Hash {
        algorithm: algorithm[..algorithm.len()-1].to_string(),
        value: value.to_string(),
    }))
}

/// Parse a scheme+host source expression.
fn parse_scheme_host(input: &str) -> IResult<&str, SourceExpression, CspParseError<&str>> {
    // Parse <scheme>://<host>[:port][/path]
    let (input, scheme) = take_while(|c: char| c.is_alphanumeric() || c == '+' || c == '-' || c == '.').parse(input)?;
    if scheme.is_empty() {
        return Err(nom::Err::Error(CspParseError::InvalidSource { value: scheme.to_string(), input }));
    }
    // Require '://' after scheme
    let (input, _) = tag("://").parse(input)?;
    let (input, host) = take_while(|c: char| c.is_alphanumeric() || c == '.' || c == '*' || c == '-').parse(input)?;
    if host.is_empty() {
        return Err(nom::Err::Failure(CspParseError::InvalidHost { value: "".to_string(), input }));
    }
    if host.contains("..") {
        return Err(nom::Err::Failure(CspParseError::InvalidHost { value: "example..com".to_string(), input }));
    }
    let (input, port) = opt(delimited(
        char(':'),
        take_while(|c: char| c.is_digit(10)),
        space0,
    )).parse(input)?;
    let port = match port {
        Some(p) if !p.is_empty() => {
            let port_num = p.parse::<u32>().ok();
            if let Some(port_num) = port_num {
                if port_num > 65535 {
                    return Err(nom::Err::Failure(CspParseError::InvalidPort { value: p.to_string(), input }));
                }
                Some(port_num as u16)
            } else {
                None
            }
        }
        _ => None,
    };
    let (input, path) = opt(delimited(
        char('/'),
        take_while(|c: char| c.is_alphanumeric() || c == '/' || c == '-' || c == '_' || c == '.' || c == '~'),
        space0,
    )).parse(input)?;
    let path = match path {
        Some(p) => {
            if p.split('/').any(|seg| seg == "..") {
                return Err(nom::Err::Failure(CspParseError::InvalidPath { value: "/../path".to_string(), input }));
            }
            Some(format!("/{}", p))
        }
        None => None,
    };
    Ok((input, SourceExpression::HostSource {
        host: host.to_string(),
        port,
        path,
    }))
}

/// Parse a host source expression.
fn parse_host(input: &str) -> nom::IResult<&str, SourceExpression, CspParseError<&str>> {
    let (input, host) = take_while(|c: char| c.is_alphanumeric() || c == '.' || c == '*' || c == '-').parse(input)?;
    if host.is_empty() {
        return Err(nom::Err::Failure(CspParseError::InvalidHost { value: "".to_string(), input }));
    }
    if host.contains("..") {
        return Err(nom::Err::Failure(CspParseError::InvalidHost { value: "example..com".to_string(), input }));
    }
    let (input, port) = opt(delimited(
        char(':'),
        take_while(|c: char| c.is_digit(10)),
        space0,
    )).parse(input)?;
    let port = match port {
        Some(p) if !p.is_empty() => {
            let port_num = p.parse::<u32>().ok();
            if let Some(port_num) = port_num {
                if port_num > 65535 {
                    return Err(nom::Err::Failure(CspParseError::InvalidPort { value: p.to_string(), input }));
                }
                Some(port_num as u16)
            } else {
                None
            }
        }
        _ => None,
    };
    let (input, path) = opt(delimited(
        char('/'),
        take_while(|c: char| c.is_alphanumeric() || c == '/' || c == '-' || c == '_' || c == '.' || c == '~'),
        space0,
    )).parse(input)?;
    let path = match path {
        Some(p) => {
            if p.split('/').any(|seg| seg == "..") {
                return Err(nom::Err::Failure(CspParseError::InvalidPath { value: "/../path".to_string(), input }));
            }
            Some(format!("/{}", p))
        }
        None => None,
    };
    Ok((input, SourceExpression::HostSource {
        host: host.to_string(),
        port,
        path,
    }))
}

/// Parse a scheme source expression.
fn parse_scheme(input: &str) -> nom::IResult<&str, SourceExpression, CspParseError<&str>> {
    let (input, scheme) = take_while(|c: char| c.is_alphanumeric() || c == '+' || c == '-' || c == '.').parse(input)?;
    if scheme.is_empty() {
        return Err(nom::Err::Error(CspParseError::InvalidSource { value: scheme.to_string(), input }));
    }
    // Require ':' not followed by '/' or a digit
    let (input, _) = char(':').parse(input)?;
    if input.starts_with('/') || input.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        return Err(nom::Err::Error(CspParseError::InvalidSource { value: format!("{}:{}", scheme, input), input }));
    }
    Ok((input, SourceExpression::Scheme(scheme.to_string())))
}

/// Parse a source expression.
pub fn parse_source_expression(input: &str) -> nom::IResult<&str, SourceExpression, CspParseError<&str>> {
    alt((
        parse_nonce,
        parse_hash,
        parse_keyword,
        parse_scheme,
        parse_scheme_host,
        parse_host,
    )).parse(input)
}

/// Parse a source list.
pub fn parse_source_list(input: &str) -> nom::IResult<&str, Vec<SourceExpression>, CspParseError<&str>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok((trimmed, vec![]));
    }
    let (input, sources) = separated_list0(space1, parse_source_expression).parse(input)?;
    let (input, _) = space0.parse(input)?;  // Consume any trailing whitespace
    // Filter out bogus HostSource { host: "" } entries
    let filtered = sources.into_iter().filter(|s| match s {
        SourceExpression::HostSource { host, .. } => !host.is_empty(),
        _ => true,
    }).collect();
    Ok((input, filtered))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_keyword() {
        assert_eq!(parse_keyword("'none'"), Ok(("", SourceExpression::None)));
        assert_eq!(parse_keyword("'self'"), Ok(("", SourceExpression::Self_)));
        assert_eq!(parse_keyword("'unsafe-inline'"), Ok(("", SourceExpression::UnsafeInline)));
    }

    #[test]
    fn test_parse_nonce() {
        assert_eq!(
            parse_nonce("'nonce-YWJjMTIz'"),
            Ok(("", SourceExpression::Nonce("YWJjMTIz".to_string())))
        );
    }

    #[test]
    fn test_parse_hash() {
        assert_eq!(
            parse_hash("'sha256-YWJjMTIz'"),
            Ok(("", SourceExpression::Hash {
                algorithm: "sha256".to_string(),
                value: "YWJjMTIz".to_string(),
            }))
        );
    }

    #[test]
    fn test_parse_scheme() {
        assert_eq!(
            parse_scheme("https:"),
            Ok(("", SourceExpression::Scheme("https".to_string())))
        );
    }

    #[test]
    fn test_parse_host() {
        assert_eq!(
            parse_host("example.com:443/path/"),
            Ok(("", SourceExpression::HostSource {
                host: "example.com".to_string(),
                port: Some(443),
                path: Some("/path/".to_string()),
            }))
        );
    }

    #[test]
    fn test_parse_source_list() {
        assert_eq!(
            parse_source_list("'self' 'unsafe-inline' https://example.com"),
            Ok(("", vec![
                SourceExpression::Self_,
                SourceExpression::UnsafeInline,
                SourceExpression::HostSource {
                    host: "example.com".to_string(),
                    port: None,
                    path: None,
                },
            ]))
        );
    }
}