//! Content Security Policy (CSP) Level 3 parser.
//! 
//! This crate provides a parser for CSP policies, directives, and source expressions.
//! Terminology and structure closely follow the CSP Level 3 spec: https://www.w3.org/TR/CSP3/

mod parser;
mod directive;
mod policy;
mod error;

pub use error::ParseError;
pub use parser::SourceExpression;
pub use directive::Directive;
pub use policy::Policy;

