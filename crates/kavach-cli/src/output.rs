use std::io::{self, Write};

/// Output mode for CLI responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputMode {
    Human,
    Json,
}

/// A structured response that can be rendered as human-readable text or JSON.
#[derive(Debug, serde::Serialize)]
pub struct CliOutput {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl CliOutput {
    pub fn with_message(msg: impl Into<String>) -> Self {
        Self {
            status: "success",
            message: Some(msg.into()),
            data: None,
        }
    }

    pub fn with_data(data: serde_json::Value) -> Self {
        Self {
            status: "success",
            message: None,
            data: Some(data),
        }
    }

    pub fn error(msg: impl Into<String>) -> Self {
        Self {
            status: "error",
            message: Some(msg.into()),
            data: None,
        }
    }

    /// Render to stdout (for success responses).
    pub fn render(&self, mode: OutputMode) {
        match mode {
            OutputMode::Human => self.render_human(&mut io::stdout().lock()),
            OutputMode::Json => self.render_json(&mut io::stdout().lock()),
        }
    }

    /// Render to stderr (for error responses).
    pub fn render_error(&self, mode: OutputMode) {
        match mode {
            OutputMode::Human => self.render_human(&mut io::stderr().lock()),
            OutputMode::Json => self.render_json(&mut io::stderr().lock()),
        }
    }

    fn render_human(&self, w: &mut dyn Write) {
        if let Some(ref msg) = self.message {
            let _ = writeln!(w, "{msg}");
        }
        if let Some(ref data) = self.data {
            match data {
                serde_json::Value::Array(items) => {
                    for item in items {
                        if let serde_json::Value::Object(map) = item {
                            let line: Vec<String> = map
                                .iter()
                                .map(|(k, v)| format!("{k}: {v}", v = render_json_value(v)))
                                .collect();
                            let _ = writeln!(w, "{}", line.join(" | "));
                        } else {
                            let _ = writeln!(w, "{item}");
                        }
                    }
                }
                serde_json::Value::Object(map) => {
                    for (k, v) in map {
                        let _ = writeln!(w, "{k}: {v}", v = render_json_value(v));
                    }
                }
                other => {
                    let _ = writeln!(w, "{other}");
                }
            }
        }
    }

    fn render_json(&self, w: &mut dyn Write) {
        let json = serde_json::to_string_pretty(self).unwrap_or_default();
        let _ = writeln!(w, "{json}");
    }
}

fn render_json_value(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => "null".into(),
        other => other.to_string(),
    }
}
