use nom::IResult;
use nom::character::complete::space0;

use crate::directive::{Directive, parse_directive};
use crate::error::ParseError;
use crate::parser::CspParseError;

/// A Content Security Policy as defined in CSP Level 3.
#[derive(Debug, Clone, PartialEq)]
pub struct Policy {
    /// The ordered set of directives that define the policy's implications.
    pub directives: Vec<Directive>,
}

impl Policy {
    /// Parse a CSP policy string.
    fn parse_policy(input: &str) -> IResult<&str, Policy, CspParseError<&str>> {
        let mut directives = Vec::new();
        let mut seen_directives = std::collections::HashSet::new();
        let mut input = input;

        while !input.trim().is_empty() {
            let (rest, directive) = parse_directive(input)?;
            let name = directive.name.clone();
            if !seen_directives.insert(name) {
                return Err(nom::Err::Failure(CspParseError::DuplicateDirective {
                    name: directive.name,
                    input,
                }));
            }
            directives.push(directive);
            let (rest, _) = space0(rest)?;
            input = rest;
        }

        Ok((input, Policy { directives }))
    }

    /// Parse a CSP policy string into a `Policy` struct.
    pub fn parse(input: &str) -> Result<Policy, ParseError> {
        match Self::parse_policy(input) {
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
    use crate::parser::SourceExpression;

    #[test]
    fn test_parse_policy() {
        let (input, policy) = Policy::parse_policy("default-src 'self'; script-src 'unsafe-inline';").unwrap();
        assert_eq!(input, "");
        assert_eq!(policy.directives.len(), 2);
        assert_eq!(policy.directives[0].name, "default-src");
        assert_eq!(policy.directives[0].source_list, vec![SourceExpression::Self_]);
        assert_eq!(policy.directives[1].name, "script-src");
        assert_eq!(policy.directives[1].source_list, vec![SourceExpression::UnsafeInline]);
    }

    #[test]
    fn test_parse_policy_duplicate() {
        assert!(Policy::parse_policy("default-src 'self'; default-src 'none';").is_err());
    }

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
        assert!(Policy::parse("invalid-directive").is_err());
    }

    #[test]
    fn test_policy_parse_duplicate() {
        assert!(Policy::parse("default-src 'self'; default-src 'none'").is_err());
    }
} 