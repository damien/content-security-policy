use std::fmt;

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