use nom::IResult;

use crate::Policy;
use super::directive::{parse_directive, validate_directive_name};
use super::parser::CspParseError;

/// Parse a CSP policy string.
pub fn parse_policy(input: &str) -> IResult<&str, Policy, CspParseError<&str>> {
    let mut directives = Vec::new();
    let mut seen_directives = std::collections::HashSet::new();
    for segment in input.split(';') {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        let (_, directive) = match parse_directive(segment) {
            Ok(res) => res,
            Err(e) => return Err(e),
        };
        let name = directive.name.clone();
        if let Err(_e) = validate_directive_name(&name) {
            return Err(nom::Err::Failure(CspParseError::InvalidDirective {
                name,
                input: segment,
            }));
        }
        if !seen_directives.insert(name.clone()) {
            return Err(nom::Err::Failure(CspParseError::DuplicateDirective {
                name,
                input: segment,
            }));
        }
        directives.push(directive);
    }
    Ok(("", Policy { directives }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SourceExpression;

    #[test]
    fn test_parse_policy() {
        let policy = parse_policy("default-src 'self'; script-src 'unsafe-inline'").unwrap();
        assert_eq!(policy.1.directives.len(), 2);
        assert_eq!(policy.1.directives[0].name, "default-src");
        assert_eq!(policy.1.directives[0].source_list, vec![SourceExpression::Self_]);
        assert_eq!(policy.1.directives[1].name, "script-src");
        assert_eq!(policy.1.directives[1].source_list, vec![SourceExpression::UnsafeInline]);
    }

    #[test]
    fn test_parse_policy_with_whitespace() {
        let policy = parse_policy("default-src 'self' ; script-src 'unsafe-inline'").unwrap();
        assert_eq!(policy.1.directives.len(), 2);
        assert_eq!(policy.1.directives[0].name, "default-src");
        assert_eq!(policy.1.directives[0].source_list, vec![SourceExpression::Self_]);
        assert_eq!(policy.1.directives[1].name, "script-src");
        assert_eq!(policy.1.directives[1].source_list, vec![SourceExpression::UnsafeInline]);
    }

    #[test]
    fn test_parse_policy_duplicate_directive() {
        assert!(parse_policy("default-src 'self'; default-src 'none'").is_err());
    }

    #[test]
    fn test_parse_policy_invalid_directive() {
        assert!(parse_policy("invalid-directive 'self'").is_err());
    }
} 