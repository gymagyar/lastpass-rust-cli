//! Platform-neutral command behavior, separated from CLI I/O for testing.
use crate::model::{Account, Field, Vault};
use anyhow::{Context, Result, ensure};
use rand::{Rng, rngs::OsRng};

pub enum Search {
    Exact,
    Substring,
    Regex,
}
pub fn matches<'a>(vault: &'a Vault, pattern: &str, mode: &Search) -> Result<Vec<&'a Account>> {
    let regex = if matches!(mode, Search::Regex) {
        Some(regex::Regex::new(pattern).context("Invalid regular expression")?)
    } else {
        None
    };
    let mut found = Vec::new();
    for a in &vault.accounts {
        let fullname = a.fullname();
        let is_match = match mode {
            Search::Exact => a.id == pattern || a.name == pattern || fullname == pattern,
            Search::Substring => [&a.id, &a.name, &fullname, &a.url, &a.username]
                .iter()
                .any(|v| v.contains(pattern)),
            Search::Regex => [&a.id, &a.name, &fullname, &a.url, &a.username]
                .iter()
                .any(|v| regex.as_ref().is_some_and(|r| r.is_match(v))),
        };
        if is_match {
            found.push(a);
        }
    }
    // Exact IDs take priority over duplicate names, as in find_unique_account.
    if matches!(mode, Search::Exact) && found.iter().any(|a| a.id == pattern) {
        found.retain(|a| a.id == pattern);
    }
    Ok(found)
}
pub fn unique_index(vault: &Vault, pattern: &str) -> Result<usize> {
    if let Some(i) = vault.accounts.iter().position(|a| a.id == pattern) {
        return Ok(i);
    }
    let found: Vec<usize> = vault
        .accounts
        .iter()
        .enumerate()
        .filter_map(|(i, a)| (a.name == pattern || a.fullname() == pattern).then_some(i))
        .collect();
    ensure!(!found.is_empty(), "No matching vault item");
    ensure!(found.len() == 1, "Multiple matches; use a unique item ID");
    Ok(found[0])
}
pub fn set_fullname(a: &mut Account, fullname: &str, vault: &Vault) -> Result<()> {
    let mut inner = fullname;
    if let Some((folder, rest)) = fullname.split_once('/') {
        if folder.starts_with("Shared-") {
            let share = vault
                .shares
                .iter()
                .find(|s| s.name.eq_ignore_ascii_case(folder))
                .context("Shared folder not found")?;
            ensure!(!share.readonly, "Shared folder is read-only");
            a.share_id = share.id.clone();
            a.share_name = share.name.clone();
            inner = rest;
        } else {
            a.share_id.clear();
            a.share_name.clear();
        }
    } else {
        a.share_id.clear();
        a.share_name.clear();
    }
    if let Some((group, name)) = inner.rsplit_once('/') {
        a.group = group.into();
        a.name = name.into();
    } else {
        a.group.clear();
        a.name = inner.into();
    }
    Ok(())
}
pub fn generate_password(length: usize, symbols: bool) -> Result<String> {
    ensure!(
        (4..=4096).contains(&length),
        "Password length must be between 4 and 4096"
    );
    let sets: &[&[u8]] = if symbols {
        &[
            b"abcdefghijkmnopqrstuvwxyz",
            b"ABCDEFGHJKLMNPQRSTUVWXYZ",
            b"23456789",
            b"!@#$%^&*()-_=+[]{}:,.?",
        ]
    } else {
        &[
            b"abcdefghijkmnopqrstuvwxyz",
            b"ABCDEFGHJKLMNPQRSTUVWXYZ",
            b"23456789",
        ]
    };
    let chars: Vec<u8> = sets.iter().flat_map(|s| s.iter().copied()).collect();
    let mut rng = OsRng;
    let mut bytes = Vec::with_capacity(length);
    for set in sets {
        bytes.push(set[rng.gen_range(0..set.len())]);
    }
    while bytes.len() < length {
        bytes.push(chars[rng.gen_range(0..chars.len())]);
    }
    use rand::seq::SliceRandom;
    bytes.shuffle(&mut rng);
    Ok(String::from_utf8(bytes)?)
}
pub fn note_type(shortname: &str) -> Option<(String, Vec<String>)> {
    let templates: serde_json::Value =
        serde_json::from_str(include_str!("../assets/note_templates.json")).ok()?;
    let n = templates.as_array()?.iter().find(|v| {
        v["shortname"]
            .as_str()
            .is_some_and(|s| s.eq_ignore_ascii_case(shortname))
    })?;
    Some((
        n["name"].as_str()?.into(),
        n["fields"]
            .as_array()?
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
    ))
}
pub enum EditChoice {
    Any,
    Username,
    Password,
    Url,
    Name,
    Notes,
    Field(String),
}
fn normalize_url(value: &str) -> String {
    if value.is_empty() || value.contains("://") {
        value.into()
    } else {
        format!("http://{value}")
    }
}
pub fn edit_value(a: &mut Account, choice: &EditChoice, input: &str, vault: &Vault) -> Result<()> {
    let value = input
        .strip_suffix('\n')
        .unwrap_or(input)
        .strip_suffix('\r')
        .unwrap_or(input.strip_suffix('\n').unwrap_or(input));
    match choice {
        EditChoice::Username => {
            if a.is_note() {
                set_note_field(a, "Username", value)
            } else {
                a.username = value.into();
            }
        }
        EditChoice::Password => {
            if a.is_note() {
                set_note_field(a, "Password", value)
            } else {
                a.password = value.into();
            }
        }
        EditChoice::Url => {
            if a.is_note() {
                set_note_field(a, "URL", &normalize_url(value));
            } else {
                a.url = normalize_url(value);
            }
        }
        EditChoice::Name => set_fullname(a, value, vault)?,
        EditChoice::Notes => {
            if a.is_note() && a.note.starts_with("NoteType:") {
                set_note_field(a, "Notes", value)
            } else {
                a.note = value.into();
            }
        }
        EditChoice::Field(name) => {
            if a.is_note() {
                set_note_field(a, name, value)
            } else if let Some(f) = a.fields.iter_mut().find(|f| f.name == *name) {
                f.value = value.into();
            } else {
                a.fields.push(Field {
                    name: name.clone(),
                    kind: "text".into(),
                    value: value.into(),
                    checked: false,
                });
            }
        }
        EditChoice::Any => {
            if a.is_note() {
                return edit_note(a, input, vault);
            }
            let note = a.is_note();
            let mut name_seen = false;
            let mut multiline: String = String::new();
            let mut is_notes = false;
            for line in input.lines() {
                if is_notes {
                    if !multiline.is_empty() {
                        multiline.push('\n');
                    }
                    multiline.push_str(line);
                    continue;
                }
                let Some((name, value)) = line.split_once(':') else {
                    if note {
                        if let Some((last_name, _)) = a.note_fields().last() {
                            let field = last_name.clone();
                            let mut old = a.field_value(&field).unwrap_or_default();
                            old.push('\n');
                            old.push_str(line);
                            set_note_field(a, &field, &old);
                        }
                    }
                    continue;
                };
                let value = value.strip_prefix(' ').unwrap_or(value);
                match name {
                    "Name" if !name_seen => {
                        name_seen = true;
                        set_fullname(a, value, vault)?;
                    }
                    "Username" if !note => a.username = value.into(),
                    "Password" if !note => a.password = value.into(),
                    "URL" if !note => a.url = normalize_url(value),
                    "Reprompt" => {
                        a.pwprotect = matches!(value.to_lowercase().as_str(), "yes" | "1" | "true")
                    }
                    "Favorite" => {
                        a.favorite = matches!(value.to_lowercase().as_str(), "yes" | "1" | "true")
                    }
                    "Application" => {
                        a.is_app = true;
                        a.appname = value.into();
                    }
                    "Notes" => {
                        is_notes = true;
                        multiline = value.into();
                    }
                    _ if note => set_note_field(a, name, value),
                    _ => {
                        if let Some(f) = a.fields.iter_mut().find(|f| f.name == name) {
                            f.value = value.into();
                        } else {
                            a.fields.push(Field {
                                name: name.into(),
                                kind: "text".into(),
                                value: value.into(),
                                checked: false,
                            });
                        }
                    }
                }
            }
            if is_notes {
                if note {
                    set_note_field(a, "Notes", &multiline)
                } else {
                    a.note = multiline;
                }
            }
        }
    }
    Ok(())
}
fn edit_note(a: &mut Account, input: &str, vault: &Vault) -> Result<()> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut name_seen = false;
    let ssh = a.note.lines().next().is_some_and(|line| {
        line.trim() == "NoteType:SSH Key" || line.trim() == "NoteType: SSH Key"
    });
    let ssh_fields = note_type("ssh-key").map(|(_, f)| f).unwrap_or_default();
    for line in input.lines() {
        let last = pairs.last().map(|(name, _)| name.as_str());
        let split = line.split_once(':');
        let continuation = last == Some("Notes")
            || split.is_none()
            || (last == Some("Private Key")
                && ssh
                && split.is_some_and(|(name, _)| {
                    !ssh_fields.iter().any(|n| n == name) && name != "Notes"
                }));
        if continuation {
            if let Some((_, value)) = pairs.last_mut() {
                value.push('\n');
                value.push_str(line);
            }
            continue;
        }
        let (name, value) = split.context("Missing note field")?;
        let value = value.strip_prefix(' ').unwrap_or(value);
        match name {
            "Name" if !name_seen => {
                name_seen = true;
                set_fullname(a, value, vault)?;
            }
            "Reprompt" => {
                a.pwprotect = matches!(value.to_lowercase().as_str(), "yes" | "1" | "true")
            }
            "Favorite" => {
                a.favorite = matches!(value.to_lowercase().as_str(), "yes" | "1" | "true")
            }
            _ => pairs.push((name.into(), value.into())),
        }
    }
    for (name, value) in pairs {
        set_note_field(a, &name, &value);
    }
    Ok(())
}
pub fn set_note_field(a: &mut Account, name: &str, value: &str) {
    let mut fields = a.note_fields();
    if let Some((_, v)) = fields.iter_mut().find(|(k, _)| k == name) {
        *v = value.into();
    } else {
        fields.push((name.into(), value.into()));
    }
    a.note = fields
        .iter()
        .map(|(k, v)| format!("{k}:{v}"))
        .collect::<Vec<_>>()
        .join("\n");
}
pub fn format_account(fmt: &str, a: &Account, field: Option<(&str, &str)>) -> String {
    let mut output = String::new();
    let mut chars = fmt.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            output.push(c);
            continue;
        }
        let mut code = chars.next().unwrap_or('%');
        if code == '%' {
            output.push('%');
            continue;
        }
        let slash = code == '/';
        if slash {
            code = chars.next().unwrap_or('%');
        }
        let kind = code;
        code = chars.next().unwrap_or('%');
        let value = if kind == 'a' {
            match code {
                'i' => a.id.clone(),
                'n' => a.name.clone(),
                'N' => a.fullname(),
                'u' => a.username.clone(),
                'p' => a.password.clone(),
                's' => a.share_name.clone(),
                'g' => a.group.clone(),
                'l' => a.url.clone(),
                'm' => a.last_modified_gmt.clone(),
                'U' => a.last_touch.clone(),
                _ => String::new(),
            }
        } else if kind == 'f' {
            match (code, field) {
                ('n', Some((n, _))) => n.into(),
                ('v', Some((_, v))) => v.into(),
                _ => String::new(),
            }
        } else {
            String::new()
        };
        if !value.is_empty() {
            output.push_str(&value);
            if slash {
                output.push('/');
            }
        }
    }
    output
}
pub fn display_account(a: &Account, title: &str, field_fmt: &str) -> String {
    let a = a.expanded();
    let mut out = format!("{}\n", format_account(title, &a, None));
    let mut pairs = vec![
        ("Username".to_owned(), a.username.clone()),
        ("Password".to_owned(), a.password.clone()),
        ("URL".to_owned(), a.url.clone()),
    ];
    if a.is_app {
        pairs.push(("Application".into(), a.appname.clone()));
    }
    pairs.extend(a.fields.iter().map(|f| {
        (
            f.name.clone(),
            if f.kind == "checkbox" {
                if f.checked {
                    "Checked".into()
                } else {
                    "Unchecked".into()
                }
            } else {
                f.value.clone()
            },
        )
    }));
    if a.pwprotect {
        pairs.push(("Reprompt".into(), "Yes".into()));
    }
    pairs.push(("Notes".into(), a.note.clone()));
    for (name, value) in pairs {
        if !(value.is_empty() || name == "URL" && value == "http://") {
            out.push_str(&format_account(field_fmt, &a, Some((&name, &value))));
            out.push('\n');
        }
    }
    out
}
pub fn export_csv(vault: &Vault, fields: &[String]) -> Result<Vec<u8>> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    writer.write_record(fields)?;
    for a in &vault.accounts {
        let row: Vec<String> = fields
            .iter()
            .map(|f| match f.as_str() {
                "url" => a.url.clone(),
                "username" => a.username.clone(),
                "password" => a.password.clone(),
                "extra" | "note" => a.note.clone(),
                "name" => a.name.clone(),
                "grouping" | "group" => a.group.clone(),
                "fav" => {
                    if a.favorite {
                        "1".into()
                    } else {
                        "0".into()
                    }
                }
                "id" => a.id.clone(),
                "fullname" => a.fullname(),
                "last_touch" => a.last_touch.clone(),
                "last_modified_gmt" => a.last_modified_gmt.clone(),
                "attachpresent" => {
                    if a.attachpresent {
                        "1".into()
                    } else {
                        "0".into()
                    }
                }
                _ => String::new(),
            })
            .collect();
        writer.write_record(row)?;
    }
    writer.into_inner().map_err(Into::into)
}
pub fn import_csv(bytes: &[u8], vault: &Vault, keep_dupes: bool) -> Result<Vec<Account>> {
    let mut reader = csv::Reader::from_reader(bytes);
    let headers = reader.headers()?.clone();
    ensure!(
        headers.iter().any(|h| h == "name"),
        "CSV must contain a name column"
    );
    let mut result: Vec<Account> = Vec::new();
    for row in reader.records() {
        let row = row?;
        let value = |name: &str| -> String {
            headers
                .iter()
                .position(|h| h == name)
                .and_then(|i| row.get(i))
                .unwrap_or("")
                .into()
        };
        let mut a = Account::default();
        a.id = "0".into();
        a.name = value("name");
        a.group = value("grouping");
        a.url = value("url");
        a.username = value("username");
        a.password = value("password");
        a.note = value("extra");
        a.favorite = value("fav") == "1";
        let duplicate = |b: &Account| {
            a.name == b.name && a.group == b.group && a.username == b.username && a.url == b.url
        };
        if keep_dupes || (!vault.accounts.iter().any(duplicate) && !result.iter().any(duplicate)) {
            result.push(a);
        }
    }
    Ok(result)
}
