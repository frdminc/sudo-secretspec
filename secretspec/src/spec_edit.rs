//! Format-preserving edits to a `secretspec.toml` root specification.

use crate::config::Secret;
use miette::{IntoDiagnostic, Result, WrapErr, miette};
use toml_edit::{DocumentMut, InlineTable, Item, Table, Value};

/// Reject names that cannot occupy a flattened secret key in a profile.
pub(crate) fn validate_secret_name(name: &str) -> Result<()> {
    if !crate::config::is_valid_identifier(name) {
        return Err(miette!(
            "Invalid secret name '{}': must be a valid identifier (alphanumeric and underscores, not starting with a number)",
            name
        ));
    }
    if name == "defaults" {
        return Err(miette!(
            "Secret name 'defaults' is reserved for profile defaults"
        ));
    }
    Ok(())
}

/// Add the declaration written by `secretspec add`: a description and,
/// optionally, an explicit requiredness.
///
/// `required` is tri-state, and the third state is the reason it is not a
/// plain `bool`. `None` writes no `required` key, which leaves the secret
/// inheriting `[defaults] required` from its profile. `Some(v)` writes
/// `required = v` explicitly. Collapsing this to "omitted means required"
/// would be wrong: a profile carrying `defaults = { required = false }` makes
/// an omitted key resolve to *optional*, so without an explicit `Some(true)`
/// there would be no way to declare a required secret in such a profile.
#[cfg(feature = "cli")]
pub(crate) fn add_description(
    source: &str,
    profile: &str,
    name: &str,
    description: &str,
    required: Option<bool>,
) -> Result<String> {
    validate_secret_name(name)?;
    if description.trim().is_empty() {
        return Err(miette!("Secret description cannot be empty"));
    }

    let mut secret = InlineTable::new();
    secret.insert("description", Value::from(description));
    if let Some(required) = required {
        secret.insert("required", Value::from(required));
    }
    insert(source, profile, name, secret)
}

/// Add a complete declaration without reformatting the rest of the document.
pub(crate) fn add_secret(
    source: &str,
    profile: &str,
    name: &str,
    secret: &Secret,
) -> Result<String> {
    insert(source, profile, name, secret_inline_table(secret)?)
}

/// Replace a declaration in place, preserving its key decor and table position.
pub(crate) fn replace_secret(
    source: &str,
    profile: &str,
    name: &str,
    secret: &Secret,
) -> Result<String> {
    validate_secret_name(name)?;
    let mut doc = parse(source)?;
    let table = profile_table_mut(&mut doc, profile)?;
    let decor = match table.get(name) {
        Some(Item::Value(value)) => Some(value.decor().clone()),
        Some(Item::Table(table)) => Some(table.decor().clone()),
        Some(Item::ArrayOfTables(_)) | Some(Item::None) => None,
        None => {
            return Err(miette!(
                "Secret '{}' is not declared in profile '{}'",
                name,
                profile
            ));
        }
    };

    let mut replacement = Value::InlineTable(secret_inline_table(secret)?);
    if let Some(decor) = decor {
        *replacement.decor_mut() = decor;
    }
    table.insert(name, Item::Value(replacement));
    Ok(doc.to_string())
}

/// Remove one declaration without reformatting the rest of the document.
pub(crate) fn remove_secret(
    source: &str,
    profile: &str,
    name: &str,
    remove_empty_profile: bool,
) -> Result<String> {
    validate_secret_name(name)?;
    let mut doc = parse(source)?;
    {
        let table = profile_table_mut(&mut doc, profile)?;
        if table.remove(name).is_none() {
            return Err(miette!(
                "Secret '{}' is not declared in profile '{}'",
                name,
                profile
            ));
        }
    }
    if remove_empty_profile {
        let profiles = doc
            .get_mut("profiles")
            .and_then(Item::as_table_like_mut)
            .expect("profile lookup above verified the profiles table");
        let is_empty = profiles
            .get(profile)
            .and_then(Item::as_table_like)
            .is_some_and(toml_edit::TableLike::is_empty);
        if is_empty {
            profiles.remove(profile);
        }
    }
    Ok(doc.to_string())
}

fn insert(source: &str, profile: &str, name: &str, declaration: InlineTable) -> Result<String> {
    validate_secret_name(name)?;
    let mut doc = parse(source)?;
    let profiles = doc
        .get_mut("profiles")
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| miette!("secretspec.toml does not contain a [profiles] table"))?;
    if !profiles.contains_key(profile) {
        profiles.insert(profile, Item::Table(Table::new()));
    }
    let table = profiles
        .get_mut(profile)
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| miette!("Profile '{}' is not a TOML table", profile))?;
    if table.contains_key(name) {
        return Err(miette!(
            "Secret '{}' is already declared in profile '{}'",
            name,
            profile
        ));
    }
    table.insert(name, toml_edit::value(declaration));
    Ok(doc.to_string())
}

fn parse(source: &str) -> Result<DocumentMut> {
    source
        .parse::<DocumentMut>()
        .into_diagnostic()
        .wrap_err("Failed to parse secretspec.toml for editing")
}

fn profile_table_mut<'a>(
    doc: &'a mut DocumentMut,
    profile: &str,
) -> Result<&'a mut dyn toml_edit::TableLike> {
    doc.get_mut("profiles")
        .and_then(Item::as_table_like_mut)
        .and_then(|profiles| profiles.get_mut(profile))
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| miette!("Profile '{}' is not declared in this spec", profile))
}

fn secret_inline_table(secret: &Secret) -> Result<InlineTable> {
    secret
        .validate_description()
        .map_err(|error| miette!(error))?;

    // The value serializer rejects nested tables, which `ref`, `refs`,
    // `extract`, `generate`, and presence-group requiredness can contain.
    let document = toml_edit::ser::to_document(secret)
        .into_diagnostic()
        .wrap_err("Failed to render the secret declaration as TOML")?;
    let mut inline = InlineTable::new();
    for (key, item) in document.as_table().iter() {
        let value = item
            .clone()
            .into_value()
            .map_err(|_| miette!("Secret field '{}' has no inline TOML form", key))?;
        inline.insert(key, value);
    }
    Ok(inline)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC_TEXT: &str = r#"[project]
name = "demo"
revision = "1.0"

# Keep this comment and declaration order.
[profiles.default]
FIRST = { description = "first" }
LAST = { description = "last" }

[profiles.default.TABLE]
description = "full table"
required = false
"#;

    fn secret(description: &str) -> Secret {
        Secret {
            description: Some(description.to_string()),
            required: Some(true),
            ..Secret::default()
        }
    }

    #[test]
    fn add_replace_and_remove_restore_the_exact_spec_text() {
        let added = add_secret(SPEC_TEXT, "default", "SCRATCH", &secret("temporary")).unwrap();
        assert!(added.contains("# Keep this comment"));
        assert!(added.find("FIRST").unwrap() < added.find("LAST").unwrap());
        assert!(added.contains("[profiles.default.TABLE]"));

        let replaced =
            replace_secret(&added, "default", "SCRATCH", &secret("replacement")).unwrap();
        assert!(replaced.contains("replacement"));

        let restored = remove_secret(&replaced, "default", "SCRATCH", false).unwrap();
        assert_eq!(restored, SPEC_TEXT);
    }

    #[test]
    fn remove_cleans_up_only_profiles_marked_as_synthesized() {
        let added = add_secret(SPEC_TEXT, "production", "SCRATCH", &secret("temporary")).unwrap();
        let restored = remove_secret(&added, "production", "SCRATCH", true).unwrap();
        assert_eq!(restored, SPEC_TEXT);

        let with_empty_profile = format!("{SPEC_TEXT}\n[profiles.production]\n");
        let added = add_secret(
            &with_empty_profile,
            "production",
            "SCRATCH",
            &secret("temporary"),
        )
        .unwrap();
        let restored = remove_secret(&added, "production", "SCRATCH", false).unwrap();
        assert_eq!(restored, with_empty_profile);
    }

    #[test]
    fn complete_secret_edits_use_the_shared_description_rule() {
        let whitespace = add_secret(SPEC_TEXT, "default", "SPACE", &secret(" "));
        assert!(whitespace.is_ok());

        let empty = add_secret(SPEC_TEXT, "default", "EMPTY", &secret(""))
            .unwrap_err()
            .to_string();
        assert!(empty.contains("description cannot be empty"), "{empty}");
    }

    #[test]
    fn invalid_edit_targets_are_rejected_without_changing_source() {
        let duplicate = add_secret(SPEC_TEXT, "default", "FIRST", &secret("duplicate"))
            .unwrap_err()
            .to_string();
        assert!(duplicate.contains("already declared"), "{duplicate}");

        let missing = replace_secret(SPEC_TEXT, "default", "MISSING", &secret("replacement"))
            .unwrap_err()
            .to_string();
        assert!(missing.contains("not declared"), "{missing}");

        let missing = remove_secret(SPEC_TEXT, "missing", "FIRST", false)
            .unwrap_err()
            .to_string();
        assert!(missing.contains("not declared in this spec"), "{missing}");
    }

    const MANIFEST: &str = r#"[project]
name = "demo"
revision = "1.0"

[profiles.default]
EXISTING = { description = "already here" }
"#;

    #[test]
    #[cfg(feature = "cli")]
    fn add_description_omits_required_when_unspecified() {
        // Asserted on the emitted declaration, not on the whole document: a
        // whole-file `contains("required")` would also be satisfied (or
        // broken) by any sibling or comment carrying that word.
        let added = add_description(MANIFEST, "default", "SCRATCH", "temp", None).unwrap();
        assert!(
            added.contains("SCRATCH = { description = \"temp\" }"),
            "{added}"
        );
    }

    #[test]
    #[cfg(feature = "cli")]
    fn add_description_writes_the_requiredness_it_is_given() {
        let optional =
            add_description(MANIFEST, "default", "SCRATCH", "temp", Some(false)).unwrap();
        assert!(
            optional.contains("SCRATCH = { description = \"temp\", required = false }"),
            "{optional}"
        );

        // The other half of the tri-state, and the reason it is not a bool:
        // a profile carrying `defaults = { required = false }` makes an
        // omitted key resolve to optional, so `Some(true)` is the only way to
        // declare a required secret there.
        let required = add_description(MANIFEST, "default", "SCRATCH", "temp", Some(true)).unwrap();
        assert!(
            required.contains("SCRATCH = { description = \"temp\", required = true }"),
            "{required}"
        );
    }

    #[test]
    #[cfg(feature = "cli")]
    fn every_requiredness_state_round_trips_byte_exactly() {
        // Mixed shapes are where `toml_edit` is likeliest to reserialize: a
        // `required` table (presence group), a quoted key, and a full
        // `[profiles.x.y]` table.
        let manifest = r#"[project]
name = "demo"
revision = "1.0"

[profiles.default]
GROUPED = { description = "in a group", required = { at_least_one = "auth" } }
"dotted.name" = { description = "quoted key" }

[profiles.default.NESTED]
description = "declared as a full table"
required = false
"#;
        for source in [MANIFEST, manifest] {
            for requiredness in [None, Some(true), Some(false)] {
                let added =
                    add_description(source, "default", "SCRATCH", "temp", requiredness).unwrap();
                assert_ne!(added, source, "add did not change anything");
                let removed = remove_secret(&added, "default", "SCRATCH", false).unwrap();
                assert_eq!(removed, source, "failed for {requiredness:?}");
            }
        }
    }

    #[test]
    #[cfg(feature = "cli")]
    fn an_optional_declaration_actually_resolves_as_optional() {
        // The product claim, asserted through the parser rather than through
        // the emitted text: the written bytes have to compile to a secret the
        // engine treats as not-required.
        let added = add_description(MANIFEST, "default", "SCRATCH", "temp", Some(false)).unwrap();
        crate::Spec::from_toml(&added).expect("edited manifest must validate");
        let config: crate::config::Config =
            toml::from_str(&added).expect("edited manifest must parse");
        assert_eq!(
            config.profiles["default"].secrets["SCRATCH"].required,
            Some(false)
        );
    }
}
