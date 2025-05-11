use nom::{
    bytes::complete::take_while,
    character::complete::space0,
    IResult, Parser,
};

use crate::{Directive, ParseError};
use super::parser::{parse_source_list, CspParseError};

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
    "font-src",
    "connect-src",
    "manifest-src",
    "worker-src",
    "child-src",
    "form-action",
    "base-uri",
    "report-to",
    "report-uri",
    "upgrade-insecure-requests",
    "block-all-mixed-content",
    "require-trusted-types-for",
    "sandbox",
];

/// Parse a directive.
pub fn parse_directive(input: &str) -> IResult<&str, Directive, CspParseError<&str>> {
    let (input, name) = take_while(|c: char| c.is_alphanumeric() || c == '-').parse(input)?;
    let (input, _) = space0.parse(input)?;
    let trimmed = input.trim_start();
    let (input, source_list) = if trimmed.is_empty() || trimmed.starts_with(';') {
        // Consume all whitespace
        let (input, _) = space0.parse(input)?;
        // Error: missing value for directive
        return Err(nom::Err::Failure(CspParseError::MissingValue {
            directive: name.to_string(),
            input,
        }));
    } else {
        let (input, _) = space0.parse(input)?;
        let (input, source_list) = parse_source_list(input)?;
        if source_list.is_empty() {
            // Error: missing value for directive
            return Err(nom::Err::Failure(CspParseError::MissingValue {
                directive: name.to_string(),
                input,
            }));
        }
        Ok((input, source_list))
    }?;
    Ok((input, Directive {
        name: name.to_string(),
        source_list,
    }))
}

/// Validate a directive name.
pub fn validate_directive_name(name: &str) -> Result<(), ParseError> {
    if VALID_DIRECTIVES.contains(&name) {
        Ok(())
    } else {
        Err(ParseError::InvalidDirective {
            name: name.to_string(),
            position: 0, // TODO: Track position
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SourceExpression;

    #[test]
    fn test_parse_directive() {
        let directive = parse_directive("default-src 'self'").unwrap();
        assert_eq!(directive.1.name, "default-src");
        assert_eq!(directive.1.source_list, vec![SourceExpression::Self_]);

        let directive = parse_directive("script-src 'unsafe-inline' 'unsafe-eval'").unwrap();
        assert_eq!(directive.1.name, "script-src");
        assert_eq!(directive.1.source_list, vec![
            SourceExpression::UnsafeInline,
            SourceExpression::UnsafeEval,
        ]);
    }

    #[test]
    fn test_validate_directive_name() {
        assert!(validate_directive_name("default-src").is_ok());
        assert!(validate_directive_name("script-src").is_ok());
        assert!(validate_directive_name("invalid-directive").is_err());
    }
} 