use clap::{Parser, ValueEnum};
use parser::{ParseError, Policy};
use serde_json;

#[derive(Clone, ValueEnum)]
enum Format {
    Json,
    Text,
}

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    policy: String,
    #[arg(short, long, value_enum)]
    format: Option<Format>,
}

fn main() -> Result<(), String> {
    let args = Args::parse();
    let policy = Policy::parse(&args.policy);

    match policy {
        Ok(policy) => {
            match args.format {
                Some(Format::Json) => println!("{}", serde_json::to_string(&policy).unwrap()),
                None | Some(Format::Text) => println!("{:?}", policy),
            }
            Ok(())
        },
        Err(e) => {
            println!("{}", explain_error(args.policy, &e));
            Err("Unable to parse policy".to_string())
        },
    }
}

// Given a parse error, print the relevant line of the policy and highlight the character that caused the error.
// Note that errors only contain the position of the error, not the line number.
// We need to parse the policy to get the line number.
fn explain_error(serialized_policy: String, error: &ParseError) -> String {
    let mut output = String::new();

    output.push_str(&error.to_string());
    output.push_str(":\n\n");

    output.push_str(&serialized_policy);
    output.push_str("\n");

    output.push_str(&" ".repeat(error.position()));
    output.push_str("^\n");

    output
}

// tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_print_error() {
        let test_policy = "script-src 'self'; foo bar";
        let error = Policy::parse(test_policy)
            .expect_err("Valid policy in text that expects an error");

        let output = explain_error(test_policy.to_string(), &error);

        assert_eq!(output, "script-src 'self'; foo bar\n                   ^\nInvalid directive 'foo' at position 19\n");
    }
}