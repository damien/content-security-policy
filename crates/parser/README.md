# CSP Parser

A zero-copy, safe Content Security Policy (CSP) Level 3 parser written in Rust using Nom.

## Features

- Zero-copy parsing of CSP policies
- Full CSP Level 3 specification compliance
- Descriptive error messages with source locations
- Safe parsing with no panics

## Usage

```rust
use csp_parser::{Policy, Directive, SourceExpression, ParseError};

// Parse a complete policy
let policy_str = "default-src 'self'; script-src 'unsafe-inline' https:";
let policy: Result<Policy, ParseError> = Policy::parse(policy_str);

// Parse individual directives
let directive_str = "script-src 'unsafe-inline' https:";
let directive: Result<Directive, ParseError> = Directive::parse(directive_str);

// Parse source expressions
let source_str = "'unsafe-inline'";
let source: Result<SourceExpression, ParseError> = SourceExpression::parse(source_str);
```

## Error Handling

The parser provides detailed error messages that include:
- The specific parsing error that occurred
- The location in the input where the error was found
- Suggestions for correcting the error

```rust
match Policy::parse("default-src 'invalid'") {
    Ok(policy) => println!("Valid policy: {:?}", policy),
    Err(e) => println!("Error: {}", e), // "Invalid source expression 'invalid' at position 12"
}
```

## API Design

See [API Design](docs/api-design.md) for detailed documentation of the parser's types and interfaces.

