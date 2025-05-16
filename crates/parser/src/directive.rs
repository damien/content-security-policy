use crate::SourceExpression;
use super::parser::{parse_source_list, CspParseError};
use nom::combinator::opt;
use nom::bytes::complete::tag;
use nom::Parser;

/// Valid CSP Level 3 directive names.
const VALID_DIRECTIVES: &[&str] = &[
    "default-src",
    "script-src",
    "script-src-elem",
    "script-src-attr",
    "style-src",
    "style-src-elem",
    "style-src-attr",
    "img-src",
    "media-src",
    "object-src",
    "frame-src",
    "frame-ancestors",
    "form-action",
    "base-uri",
    "connect-src",
    "font-src",
    "manifest-src",
    "worker-src",
    "child-src",
    "prefetch-src",
    "navigate-to",
    "report-uri",
    "report-to",
    "upgrade-insecure-requests",
    "block-all-mixed-content",
    "require-trusted-types-for",
    "sandbox",
];

/// A directive within a Content Security Policy.
#[derive(Debug, Clone, PartialEq)]
pub struct Directive {
    /// The directive name (e.g., "default-src", "script-src").
    pub name: String,
    /// The source list containing the directive's values.
    pub source_list: Vec<SourceExpression>,
}

/// Parse a directive.
pub fn parse_directive(input: &str) -> nom::IResult<&str, Directive, CspParseError<&str>> {
    let (input, name) = nom::bytes::complete::take_while(|c: char| c.is_ascii_alphanumeric() || c == '-')(input)?;
    if !validate_directive_name(name) {
        return Err(nom::Err::Failure(CspParseError::InvalidDirective { name: name.to_string(), input }));
    }
    let (input, _) = nom::character::complete::space0(input)?;
    let (input, source_list) = parse_source_list(input)?;
    let (input, _) = nom::character::complete::space0(input)?;
    let (input, _) = opt(tag(";")).parse(input)?;
    // Reject fetch directives with missing/empty source lists
    if is_fetch_directive(name) && source_list.is_empty() {
        return Err(nom::Err::Failure(CspParseError::MissingValue { directive: name.to_string(), input }));
    }
    Ok((input, Directive {
        name: name.to_string(),
        source_list,
    }))
}

/// Validate a directive name.
pub fn validate_directive_name(name: &str) -> bool {
    VALID_DIRECTIVES.contains(&name)
}

/// Returns true if the directive is a fetch directive (per CSP Level 3)
fn is_fetch_directive(name: &str) -> bool {
    matches!(name,
        "child-src" | "connect-src" | "default-src" | "font-src" | "frame-src" |
        "img-src" | "manifest-src" | "media-src" | "object-src" | "prefetch-src" |
        "script-src" | "script-src-elem" | "script-src-attr" | "style-src" |
        "style-src-elem" | "style-src-attr" | "worker-src"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_directive() {
        let (input, directive) = parse_directive("default-src 'self';").unwrap();
        assert_eq!(input, "");
        assert_eq!(directive.name, "default-src");
        assert_eq!(directive.source_list, vec![SourceExpression::Self_]);
    }

    #[test]
    fn test_parse_directive_invalid() {
        assert!(parse_directive("invalid-directive 'self';").is_err());
    }
} 