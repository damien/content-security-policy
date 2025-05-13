//! Content Security Policy (CSP) Level 3 parser.
//! 
//! This crate provides a parser for CSP policies, directives, and source expressions.
//! Terminology and structure closely follow the CSP Level 3 spec: https://www.w3.org/TR/CSP3/

use std::fmt;

mod parser;
mod directive;
mod policy;

/// A Content Security Policy as defined in CSP Level 3.
#[derive(Debug, Clone, PartialEq)]
pub struct Policy {
    /// The ordered set of directives that define the policy's implications.
    pub directives: Vec<Directive>,
}

/// A directive within a Content Security Policy.
#[derive(Debug, Clone, PartialEq)]
pub struct Directive {
    /// The directive name (e.g., "default-src", "script-src").
    pub name: String,
    /// The source list containing the directive's values.
    pub source_list: Vec<SourceExpression>,
}

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

/// Errors that can occur during CSP parsing.
#[derive(Debug, Clone, PartialEq)]
pub enum ParseError {
    /// Invalid directive name.
    InvalidDirective {
        /// The invalid directive name.
        name: String,
        /// The position where the error occurred.
        position: usize,
    },
    /// Invalid source expression.
    InvalidSource {
        /// The invalid source value.
        value: String,
        /// The position where the error occurred.
        position: usize,
    },
    /// Duplicate directive in policy.
    DuplicateDirective {
        /// The duplicate directive name.
        name: String,
        /// The position where the error occurred.
        position: usize,
    },
    /// Missing value for directive.
    MissingValue {
        /// The directive name.
        directive: String,
        /// The position where the error occurred.
        position: usize,
    },
    /// Invalid host value.
    InvalidHost {
        /// The invalid host value.
        value: String,
        /// The position where the error occurred.
        position: usize,
    },
    /// Invalid port value.
    InvalidPort {
        /// The invalid port value.
        value: String,
        /// The position where the error occurred.
        position: usize,
    },
    /// Invalid path value.
    InvalidPath {
        /// The invalid path value.
        value: String,
        /// The position where the error occurred.
        position: usize,
    },
    /// Invalid nonce value.
    InvalidNonce {
        /// The invalid nonce value.
        value: String,
        /// The position where the error occurred.
        position: usize,
    },
    /// Invalid hash value.
    InvalidHash {
        /// The invalid hash value.
        value: String,
        /// The position where the error occurred.
        position: usize,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::InvalidDirective { name, position } => {
                write!(f, "Invalid directive '{}' at position {}", name, position)
            }
            ParseError::InvalidSource { value, position } => {
                write!(f, "Invalid source '{}' at position {}", value, position)
            }
            ParseError::DuplicateDirective { name, position } => {
                write!(f, "Duplicate directive '{}' at position {}", name, position)
            }
            ParseError::MissingValue { directive, position } => {
                write!(f, "Missing value for directive '{}' at position {}", directive, position)
            }
            ParseError::InvalidHost { value, position } => {
                write!(f, "Invalid host '{}' at position {}", value, position)
            }
            ParseError::InvalidPort { value, position } => {
                write!(f, "Invalid port '{}' at position {}", value, position)
            }
            ParseError::InvalidPath { value, position } => {
                write!(f, "Invalid path '{}' at position {}", value, position)
            }
            ParseError::InvalidNonce { value, position } => {
                write!(f, "Invalid nonce '{}' at position {}", value, position)
            }
            ParseError::InvalidHash { value, position } => {
                write!(f, "Invalid hash '{}' at position {}", value, position)
            }
        }
    }
}

impl std::error::Error for ParseError {}

impl Policy {
    /// Parse a CSP policy string into a `Policy` struct.
    ///
    /// # Arguments
    ///
    /// * `input` - The CSP policy string to parse.
    ///
    /// # Returns
    ///
    /// * `Ok(Policy)` - The parsed policy.
    /// * `Err(ParseError)` - An error if parsing fails.
    pub fn parse(input: &str) -> Result<Policy, ParseError> {
        match policy::parse_policy(input) {
            Ok((_, policy)) => Ok(policy),
            Err(nom::Err::Error(e)) | Err(nom::Err::Failure(e)) => {
                use crate::parser::CspParseError;
                match e {
                    CspParseError::InvalidDirective { name, .. } => Err(ParseError::InvalidDirective {
                        name,
                        position: 0,
                    }),
                    CspParseError::DuplicateDirective { name, .. } => Err(ParseError::DuplicateDirective {
                        name,
                        position: 0,
                    }),
                    CspParseError::MissingValue { directive, .. } => Err(ParseError::MissingValue {
                        directive,
                        position: 0,
                    }),
                    CspParseError::InvalidHost { value, .. } => Err(ParseError::InvalidHost {
                        value,
                        position: 0,
                    }),
                    CspParseError::InvalidPort { value, .. } => Err(ParseError::InvalidPort {
                        value,
                        position: 0,
                    }),
                    CspParseError::InvalidPath { value, .. } => Err(ParseError::InvalidPath {
                        value,
                        position: 0,
                    }),
                    CspParseError::InvalidNonce { value, .. } => Err(ParseError::InvalidNonce {
                        value,
                        position: 0,
                    }),
                    CspParseError::InvalidHash { value, .. } => Err(ParseError::InvalidHash {
                        value,
                        position: 0,
                    }),
                    CspParseError::InvalidSource { value, .. } => Err(ParseError::InvalidSource {
                        value,
                        position: 0,
                    }),
                }
            }
            Err(nom::Err::Incomplete(_)) => {
                Err(ParseError::InvalidSource {
                    value: input.to_string(),
                    position: 0,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_parse() {
        let policy = Policy::parse("default-src 'self'; script-src 'unsafe-inline'").unwrap();
        assert_eq!(policy.directives.len(), 2);
        assert_eq!(policy.directives[0].name, "default-src");
        assert_eq!(policy.directives[0].source_list, vec![SourceExpression::Self_]);
        assert_eq!(policy.directives[1].name, "script-src");
        assert_eq!(policy.directives[1].source_list, vec![SourceExpression::UnsafeInline]);
    }

    #[test]
    fn test_policy_parse_invalid() {
        assert!(Policy::parse("invalid-directive 'self'").is_err());
    }

    #[test]
    fn test_policy_parse_duplicate() {
        assert!(Policy::parse("default-src 'self'; default-src 'none'").is_err());
    }
}
