use std::fmt;

/// A wrapper for sensitive string values (e.g. authentication tokens, passwords, keys).
///
/// This type ensures that secrets are not accidentally leaked through standard
/// formatting (`Display`, `Debug`) or serialization (`Serialize`).
/// When serialized, `SecretString` is always rendered as `"[REDACTED]"`.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(String);

impl SecretString {
    /// Wraps a string in a `SecretString`.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Explicitly reveals the secret string value when needed by authentication/security routines.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString([REDACTED])")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl<'de> serde::Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self::new(s))
    }
}

impl serde::Serialize for SecretString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // When serialized, always redact the secret value to prevent leaks.
        serializer.serialize_str("[REDACTED]")
    }
}

impl schemars::JsonSchema for SecretString {
    fn schema_name() -> String {
        "SecretString".to_string()
    }

    fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        let mut schema = <String>::json_schema(gen);
        if let schemars::schema::Schema::Object(ref mut o) = schema {
            o.metadata().description = Some(
                "A sensitive string value (e.g. token or secret) redacted in effective configurations"
                    .to_string(),
            );
            o.metadata().write_only = true;
        }
        schema
    }
}
