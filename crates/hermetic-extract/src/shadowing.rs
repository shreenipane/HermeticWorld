#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::sync::OnceLock;

use crate::report::ReportFlag;

static STDLIB_TEXT: &str = include_str!("data/python_stdlib_3_11.txt");

static STDLIB_SET: OnceLock<HashSet<&'static str>> = OnceLock::new();

pub fn get_stdlib_set() -> &'static HashSet<&'static str> {
    STDLIB_SET.get_or_init(|| {
        STDLIB_TEXT
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    })
}

/// Checks if a newly added path represents a top-level module or package
/// that shadows a standard library module or an installed package.
pub fn check_shadowing(
    path: &str,
    import_roots: &[String],
    installed_packages: &[String],
) -> Option<ReportFlag> {
    let stdlib = get_stdlib_set();

    for root in import_roots {
        let prefix = if root.is_empty() {
            "".to_string()
        } else if root.ends_with('/') {
            root.clone()
        } else {
            format!("{root}/")
        };

        let rest = match path.strip_prefix(&prefix) {
            Some(r) => r,
            None => continue,
        };

        // Case 1: <root>/<name>.py
        if let Some(mod_name) = rest.strip_suffix(".py") {
            if !mod_name.contains('/') && !mod_name.is_empty() {
                if stdlib.contains(mod_name) {
                    return Some(ReportFlag {
                        flag_type: "shadowing".to_string(),
                        path: path.to_string(),
                        detail: format!("module '{mod_name}' shadows Python standard library"),
                    });
                }
                if installed_packages.iter().any(|pkg| pkg == mod_name) {
                    return Some(ReportFlag {
                        flag_type: "shadowing".to_string(),
                        path: path.to_string(),
                        detail: format!(
                            "module '{mod_name}' shadows installed package '{mod_name}'"
                        ),
                    });
                }
            }
        }

        // Case 2: <root>/<name>/__init__.py
        if let Some(pkg_rest) = rest.strip_suffix("/__init__.py") {
            if !pkg_rest.contains('/') && !pkg_rest.is_empty() {
                if stdlib.contains(pkg_rest) {
                    return Some(ReportFlag {
                        flag_type: "shadowing".to_string(),
                        path: path.to_string(),
                        detail: format!("package '{pkg_rest}' shadows Python standard library"),
                    });
                }
                if installed_packages.iter().any(|pkg| pkg == pkg_rest) {
                    return Some(ReportFlag {
                        flag_type: "shadowing".to_string(),
                        path: path.to_string(),
                        detail: format!(
                            "package '{pkg_rest}' shadows installed package '{pkg_rest}'"
                        ),
                    });
                }
            }
        }
    }

    None
}
