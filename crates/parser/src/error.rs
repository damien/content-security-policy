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
                write!(f, "Invalid directive '{name}' at position {position}")
            }
            ParseError::InvalidSource { value, position } => {
                write!(f, "Invalid source '{value}' at position {position}")
            }
            ParseError::DuplicateDirective { name, position } => {
                write!(f, "Duplicate directive '{name}' at position {position}")
            }
            ParseError::MissingValue { directive, position } => {
                write!(f, "Missing value for directive '{directive}' at position {position}")
            }
            ParseError::InvalidHost { value, position } => {
                write!(f, "Invalid host '{value}' at position {position}")
            }
            ParseError::InvalidPort { value, position } => {
                write!(f, "Invalid port '{value}' at position {position}")
            }
            ParseError::InvalidPath { value, position } => {
                write!(f, "Invalid path '{value}' at position {position}")
            }
            ParseError::InvalidNonce { value, position } => {
                write!(f, "Invalid nonce '{value}' at position {position}")
            }
            ParseError::InvalidHash { value, position } => {
                write!(f, "Invalid hash '{value}' at position {position}")
            }
        }
    }
}

impl std::error::Error for ParseError {}

impl<I> nom::error::ParseError<I> for ParseError {
    fn from_error_kind(_input: I, _kind: nom::error::ErrorKind) -> Self {
        ParseError::InvalidSource { 
            value: "unknown".to_string(), 
            position: 0 
        }
    }

    fn append(_input: I, _kind: nom::error::ErrorKind, other: Self) -> Self {
        other
    }
} 