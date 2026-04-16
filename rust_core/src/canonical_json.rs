use crate::error::AetherError;
use serde_json::Value;

pub fn canonicalize_json(input: &str) -> Result<String, AetherError> {
    let value: Value = serde_json::from_str(input)
        .map_err(|e| AetherError::InternalError(format!("Invalid JSON: {}", e)))?;
    Ok(render_value(&value))
}

fn render_value(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(v) => v.to_string(),
        Value::Number(v) => v.to_string(),
        Value::String(v) => serde_json::to_string(v).unwrap_or_else(|_| "\"\"".to_string()),
        Value::Array(values) => {
            let rendered = values.iter().map(render_value).collect::<Vec<_>>();
            format!("[{}]", rendered.join(","))
        }
        Value::Object(map) => {
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            let rendered = entries
                .into_iter()
                .map(|(key, value)| {
                    let escaped_key =
                        serde_json::to_string(key).unwrap_or_else(|_| "\"\"".to_string());
                    format!("{}:{}", escaped_key, render_value(value))
                })
                .collect::<Vec<_>>();
            format!("{{{}}}", rendered.join(","))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_sorts_keys_and_nested_values() {
        let raw = r#"{"z":"last","full":{"url":"https://cdn","size":1024},"a":"first"}"#;
        let canonical = canonicalize_json(raw).unwrap();
        assert_eq!(
            canonical,
            r#"{"a":"first","full":{"size":1024,"url":"https://cdn"},"z":"last"}"#
        );
    }

    #[test]
    fn canonicalize_handles_arrays_and_escaping() {
        let raw = "{\"arches\":[\"arm64\",\"x86_64\"],\"quote\":\"say \\\"hi\\\"\"}";
        let canonical = canonicalize_json(raw).unwrap();
        assert_eq!(
            canonical,
            r#"{"arches":["arm64","x86_64"],"quote":"say \"hi\""}"#
        );
    }

    #[test]
    fn invalid_json_is_rejected() {
        let err = canonicalize_json("{not-json").unwrap_err();
        assert!(matches!(err, AetherError::InternalError(_)));
    }
}
