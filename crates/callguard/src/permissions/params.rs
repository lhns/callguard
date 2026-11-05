//! `Tool(param:value)`: deny and ask rules on one top-level scalar of a tool's
//! input (Claude's "match by input parameter").

use super::{Rule, is_param_name};

/// What a tool's primary field is called, which no parameter rule may name
/// (Claude ignores such a rule; here it cannot be read).
fn primary(tool: &str) -> &'static [&'static str] {
    match tool {
        "Bash" | "PowerShell" => &["command"],
        "Read" | "Edit" | "Write" | "MultiEdit" => &["file_path"],
        "Grep" | "Glob" | "LS" => &["path"],
        "NotebookEdit" => &["notebook_path"],
        "WebFetch" => &["url"],
        _ => &["command", "file_path", "path", "notebook_path", "url"],
    }
}

/// The parameters a shell, path or WebFetch tool has, where `Bash(git:status)`
/// and `Read(a:b)` are also ordinary specs. None for every other tool, where
/// any identifier before the colon is a parameter.
fn known(tool: &str) -> Option<&'static [&'static str]> {
    Some(match tool {
        "Bash" | "PowerShell" => &["run_in_background", "timeout", "description"],
        "Read" => &["offset", "limit", "pages"],
        "Edit" => &["replace_all"],
        "Grep" => &["pattern", "glob", "type", "output_mode"],
        "Glob" => &["pattern"],
        "NotebookEdit" => &["cell_id", "cell_type", "edit_mode"],
        "Write" | "MultiEdit" | "LS" => &[],
        "WebFetch" => &["prompt"],
        _ => return None,
    })
}

/// Reads the inside of `tool(...)` as a parameter rule. None if it is not one
/// (the tool's own spec syntax applies); the error says why a rule that looks
/// like one cannot be read.
pub(super) fn parse(tool: &str, spec: &str) -> Result<Option<Rule>, String> {
    let Some((left, right)) = spec.split_once(':') else {
        return Ok(None);
    };
    let param = left.trim();
    if !is_param_name(param) {
        return Ok(None);
    }
    if primary(tool).contains(&param) {
        return Err(format!(
            "`{param}:` is the primary field of {tool}, which a parameter rule cannot match; use the tool's own pattern"
        ));
    }
    if known(tool).is_some_and(|k| !k.contains(&param)) {
        return Ok(None);
    }
    let value = right.trim();
    // `Bash(timeout:*)` was the program `timeout` with any arguments; keep
    // that meaning. Any other value is the parameter.
    if matches!(tool, "Bash" | "PowerShell") && param == "timeout" && value == "*" {
        return Ok(None);
    }
    if value.is_empty() {
        return Err(format!("no value after `{param}:`"));
    }
    Ok(Some(Rule::Param {
        tool: tool.to_owned(),
        param: param.to_owned(),
        value: value.to_owned(),
    }))
}
