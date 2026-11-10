use hermetic_sealcheck::normalize::{
    clean_line, is_trivial, normalize_diff_line, normalize_line, strip_trailing_comment,
};

#[test]
fn test_clean_line_and_is_trivial() {
    assert_eq!(
        clean_line("   hello   world   # comment", false),
        "hello world"
    );
    assert!(is_trivial("pass"));
    assert!(!is_trivial("def valid_function_definition():"));
}

#[test]
fn test_strip_trailing_comment() {
    assert_eq!(strip_trailing_comment("x = 1 # comment").trim(), "x = 1");
    assert_eq!(
        strip_trailing_comment("s = 'string with # inside' # comment").trim(),
        "s = 'string with # inside'"
    );
    assert_eq!(
        strip_trailing_comment(r#"s = "escaped \" # inside" # comment"#).trim(),
        r#"s = "escaped \" # inside""#
    );
}

#[test]
fn test_normalization_table() {
    struct TestCase {
        input: &'static str,
        is_diff: bool,
        expected: Option<&'static str>,
    }

    let cases = vec![
        // Trivial: < 12 characters
        TestCase {
            input: "pass",
            is_diff: false,
            expected: None,
        },
        TestCase {
            input: "return",
            is_diff: false,
            expected: None,
        },
        TestCase {
            input: "else:",
            is_diff: false,
            expected: None,
        },
        TestCase {
            input: "try:",
            is_diff: false,
            expected: None,
        },
        TestCase {
            input: "finally:",
            is_diff: false,
            expected: None,
        },
        TestCase {
            input: "x = 1",
            is_diff: false,
            expected: None,
        },
        TestCase {
            input: "foo()",
            is_diff: false,
            expected: None,
        },
        // Trivial: brackets & punctuation
        TestCase {
            input: "{}",
            is_diff: false,
            expected: None,
        },
        TestCase {
            input: "[]",
            is_diff: false,
            expected: None,
        },
        TestCase {
            input: "(),",
            is_diff: false,
            expected: None,
        },
        TestCase {
            input: "  );  ",
            is_diff: false,
            expected: None,
        },
        // Trivial: bare keywords
        TestCase {
            input: "return None",
            is_diff: false,
            expected: None,
        },
        TestCase {
            input: "return False",
            is_diff: false,
            expected: None,
        },
        TestCase {
            input: "return True",
            is_diff: false,
            expected: None,
        },
        // Non-trivial lines
        TestCase {
            input: "def test_something_important(self):",
            is_diff: false,
            expected: Some("def test_something_important(self):"),
        },
        TestCase {
            input: "    result = compute_complex_calculation(a, b)    ",
            is_diff: false,
            expected: Some("result = compute_complex_calculation(a, b)"),
        },
        TestCase {
            input: "    value = calculate()  # important calculation",
            is_diff: false,
            expected: Some("value = calculate()"),
        },
        TestCase {
            input: "    msg = 'hash # should # stay'  # comment should go",
            is_diff: false,
            expected: Some("msg = 'hash # should # stay'"),
        },
        // Diff mode with markers
        TestCase {
            input: "+    result = calculate_with_marker(x, y)",
            is_diff: true,
            expected: Some("result = calculate_with_marker(x, y)"),
        },
        TestCase {
            input: "-    old_implementation_call(param1, param2)",
            is_diff: true,
            expected: Some("old_implementation_call(param1, param2)"),
        },
        TestCase {
            input: "     context_line_with_code(arg1, arg2)",
            is_diff: true,
            expected: Some("context_line_with_code(arg1, arg2)"),
        },
        // Diff mode on trivial line
        TestCase {
            input: "+    x = 1",
            is_diff: true,
            expected: None,
        },
    ];

    for c in cases {
        let actual = if c.is_diff {
            normalize_diff_line(c.input)
        } else {
            normalize_line(c.input)
        };
        assert_eq!(
            actual.as_deref(),
            c.expected,
            "failed test case for input: {:?}",
            c.input
        );
    }
}
