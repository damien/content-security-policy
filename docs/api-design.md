# CSP Parser API Design

This document outlines the core types and interfaces for the CSP Level 3 parser.

## Core Types

```rust
pub struct Policy {
    pub directives: Vec<Directive>,
}

pub struct Directive {
    pub name: DirectiveName,
    pub source_list: Vec<SourceExpression>,
}

pub enum SourceExpression {
    None,
    Self,
    UnsafeInline,
    UnsafeEval,
    UnsafeHashes,
    StrictDynamic,
    ReportSample,
    WasmUnsafeEval,
    HostSource {
        host: String,
        port: Option<u16>,
        path: Option<String>,
    },
    Scheme(String),
    Nonce(String),
    Hash(HashAlgorithm, Vec<u8>),
}

pub enum ParseError {
    InvalidDirective { name: String, position: usize },
    InvalidSource { value: String, position: usize },
    MissingValue { directive: String, position: usize },
    DuplicateDirective { name: String, position: usize },
    InvalidHost { value: String, position: usize },
    InvalidPort { value: String, position: usize },
    InvalidPath { value: String, position: usize },
    // ... other error variants
}
```

## Implementation Details

- Uses Nom's parser combinators for efficient, zero-copy parsing
- Implements custom error types for CSP-specific parsing errors
- Provides clear documentation inline with the CSP Level 3 spec
- Includes comprehensive test suite with CSP spec examples
