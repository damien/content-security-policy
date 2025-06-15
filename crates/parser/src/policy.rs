use nom::{
    character::complete::space0,
    IResult,
};
use serde::{Serialize, Deserialize};

use crate::{
    directive::{Directive, parse_directive},
    error::ParseError,
};

/// A Content Security Policy as defined in CSP Level 3.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    /// The ordered set of directives that define the policy's implications.
    pub directives: Vec<Directive>,
}

impl Policy {
    /// Parse a CSP policy string.
    /// 
    /// This method returns a tuple containing the remainder of the input string and the parsed policy.
    /// The remaining input is the part of the input string that was not parsed as a directive,
    /// either because it was invalid or because it was not a directive.
    /// 
    /// If this method returns a tuple containing a non-empty remainder,
    /// it means that the remaining input could not be parsed as a directive and is therefore invalid.
    /// 
    /// If this method returns a tuple containing an empty remainder,
    /// it means that the input string was parsed successfully.
    fn parse_policy(input: &str) -> IResult<&str, Policy, ParseError> {
        let mut directives = Vec::new();
        let mut seen_directives = std::collections::HashSet::new();
        let mut remaining_input = input;
        let original_input = input;

        // Continue parsing directives until the remainder of the CSP policy string is empty
        while !remaining_input.trim().is_empty() {
            // Calculate current position in the input string
            let current_position = original_input.len() - remaining_input.len();

            match parse_directive(remaining_input) {
                Ok((after_directive, directive)) => {
                    // The CSP specification does not allow duplicate directives
                    if !seen_directives.insert(directive.name.clone()) {
                        return Err(nom::Err::Failure(ParseError::DuplicateDirective {
                            name: directive.name,
                            position: current_position,
                        }));
                    }

                    directives.push(directive);

                    let (after_whitespace, _) = space0(after_directive)?;
                    remaining_input = after_whitespace;
                },
                Err(nom::Err::Error(mut e)) | Err(nom::Err::Failure(mut e)) => {
                    // Adjust position in error to be relative to start of policy string
                    match &mut e {
                        ParseError::InvalidDirective { position, .. } => {
                            *position += current_position;
                        },
                        ParseError::InvalidSource { position, .. } => {
                            *position += current_position;
                        },
                        ParseError::DuplicateDirective { position, .. } => {
                            *position += current_position;
                        },
                        ParseError::MissingValue { position, .. } => {
                            *position += current_position;
                        },
                        ParseError::InvalidHost { position, .. } => {
                            *position += current_position;
                        },
                        ParseError::InvalidPort { position, .. } => {
                            *position += current_position;
                        },
                        ParseError::InvalidPath { position, .. } => {
                            *position += current_position;
                        },
                        ParseError::InvalidNonce { position, .. } => {
                            *position += current_position;
                        },
                        ParseError::InvalidHash { position, .. } => {
                            *position += current_position;
                        },
                    }
                    return Err(nom::Err::Failure(e));
                },
                Err(e) => return Err(e),
            }
        }

        Ok((remaining_input, Policy { directives }))
    }

    /// Parse a CSP policy string into a `Policy` struct.
    ///
    /// Returns a `Policy` struct if the input string is a valid CSP policy.
    /// 
    /// Returns an empty `Policy` struct if the input string is empty or whitespace-only, as per the CSP Level 3 spec (§4.2.1 - https://www.w3.org/TR/CSP3/#parse-serialized-policy)
    /// 
    /// Returns a `ParseError` if the input string is invalid.
    /// 
    /// Returns a `ParseError` if the input string is incomplete. An incomplete policy is a policy that is not fully parsed,
    /// in such cases the parser will return the remaining input as a `ParseError::InvalidSource`.
    pub fn parse(input: &str) -> Result<Policy, ParseError> {
        match Self::parse_policy(input) {
            // Per CSP Level 3 spec:
            // 1. Policies are initialized with empty directive sets (§4.2.1 - https://www.w3.org/TR/CSP3/#parse-serialized-policy)
            // 2. Whitespace is trimmed during token processing (§4.2.1 step 2.1)
            // 3. Empty tokens are ignored (§4.2.1 step 2.2)
            // 4. Empty or whitespace-only policies are valid and produce empty policies with no directives (§4.2.1 parsing algorithm)
            Ok((remaining, policy)) => {
                if remaining.trim().is_empty() {
                    Ok(policy)

                } else {
                    Err(ParseError::InvalidSource {
                        value: remaining.to_string(),
                        position: input.len() - remaining.len(),
                    })
                }
            },

            Err(nom::Err::Error(e)) | Err(nom::Err::Failure(e)) => Err(e),

            Err(nom::Err::Incomplete(_)) => Err(ParseError::InvalidSource {
                value: input.to_string(),
                position: input.len(), // Error at the end if incomplete
            }),
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

    #[test]
    fn test_policy_parse_empty() {
        let policy = Policy::parse("").unwrap();
        assert_eq!(policy.directives.len(), 0);
    }

    #[test]
    fn test_policy_parse_whitespace() {
        let policy: Policy = Policy::parse("   ").unwrap();
        assert_eq!(policy.directives.len(), 0);
    }
} 