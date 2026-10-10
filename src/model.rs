use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Default, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Field {
    pub name: String,
    pub kind: String,
    pub value: String,
    pub checked: bool,
}
#[derive(Default, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Attachment {
    pub id: String,
    pub parent: String,
    pub mimetype: String,
    pub storagekey: String,
    pub size: String,
    pub filename: String,
}
#[derive(Default, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Account {
    pub id: String,
    pub name: String,
    pub group: String,
    pub url: String,
    pub username: String,
    pub password: String,
    pub note: String,
    pub last_touch: String,
    pub last_modified_gmt: String,
    pub favorite: bool,
    pub pwprotect: bool,
    pub is_app: bool,
    pub appname: String,
    pub app_extra: String,
    pub attachkey: String,
    pub attachpresent: bool,
    pub fields: Vec<Field>,
    pub attachments: Vec<Attachment>,
    pub share_id: String,
    pub share_name: String,
}
impl Account {
    pub fn fullname(&self) -> String {
        let inner = if self.group.is_empty() {
            self.name.clone()
        } else {
            format!("{}/{}", self.group, self.name)
        };
        if self.share_name.is_empty() {
            inner
        } else {
            format!("{}/{}", self.share_name, inner)
        }
    }
    pub fn is_group(&self) -> bool {
        self.url == "http://group"
    }
    pub fn is_note(&self) -> bool {
        self.url == "http://sn"
    }
    pub fn field_value(&self, name: &str) -> Option<String> {
        if let Some(field) = self.fields.iter().find(|f| f.name == name) {
            return Some(field.value.clone());
        }
        if self.is_note() && self.note.starts_with("NoteType:") {
            for (k, v) in self.note_fields() {
                if k == name {
                    return Some(v);
                }
            }
        }
        None
    }
    pub fn note_fields(&self) -> Vec<(String, String)> {
        let mut pairs: Vec<(String, String)> = Vec::new();
        let templates: serde_json::Value =
            serde_json::from_str(include_str!("../assets/note_templates.json")).unwrap_or_default();
        let typename = self
            .note
            .lines()
            .next()
            .and_then(|s| s.strip_prefix("NoteType:"))
            .map(str::trim)
            .unwrap_or("");
        let known = templates
            .as_array()
            .and_then(|n| n.iter().find(|n| n["name"].as_str() == Some(typename)))
            .and_then(|n| n["fields"].as_array());
        for line in self.note.lines() {
            if let Some((name, value)) = pairs.last_mut() {
                if name == "Notes" {
                    value.push('\n');
                    value.push_str(line);
                    continue;
                }
            }
            // Secure-note fields have no space after ':' in the modern wire
            // format; old notes use a space. Preserve either representation.
            if let Some((name, value)) = line.split_once(':') {
                let multiline =
                    pairs.last().is_some_and(|(n, _)| n == "Private Key") && typename == "SSH Key";
                let valid =
                    known.is_some_and(|fields| fields.iter().any(|f| f.as_str() == Some(name)));
                if !name.is_empty() && (!multiline || valid || name == "Notes") {
                    pairs.push((
                        name.to_owned(),
                        value.strip_prefix(' ').unwrap_or(value).to_owned(),
                    ));
                    continue;
                }
            }
            if let Some((_, value)) = pairs.last_mut() {
                value.push('\n');
                value.push_str(line);
            }
        }
        pairs
    }
    pub fn expanded(&self) -> Self {
        let mut result = self.clone();
        if self.is_note() && self.note.starts_with("NoteType:") {
            result.url.clear();
            result.note.clear();
            for (name, value) in self.note_fields() {
                match name.as_str() {
                    "Username" => result.username = value,
                    "Password" => result.password = value,
                    "URL" => result.url = value,
                    "Notes" => result.note = value,
                    _ => result.fields.push(Field {
                        name,
                        value,
                        kind: "text".into(),
                        checked: false,
                    }),
                }
            }
        }
        result
    }
    pub fn json_value(&self) -> serde_json::Value {
        let mut value = serde_json::json!({"id":self.id,"name":self.name,"fullname":self.fullname(),
            "username":self.username,"password":self.password,"last_modified_gmt":self.last_modified_gmt,
            "last_touch":self.last_touch,"group":self.group,"url":self.url,"note":self.note});
        if !self.share_name.is_empty() {
            value["share"] = self.share_name.clone().into();
        }
        value
    }
}
#[derive(Default, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Share {
    pub id: String,
    pub name: String,
    pub key: [u8; 32],
    pub readonly: bool,
    pub chunk: Vec<u8>,
}
#[derive(Default, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Vault {
    pub version: u64,
    pub accounts: Vec<Account>,
    pub shares: Vec<Share>,
    pub decryption_errors: usize,
    #[serde(default)]
    pub unavailable_shares: usize,
    #[serde(default)]
    pub unavailable_accounts: usize,
    pub pending_updates: bool,
}
#[derive(Default, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Session {
    pub username: String,
    pub uid: String,
    pub sessionid: String,
    pub token: String,
    pub server: String,
    pub private_key: Vec<u8>,
    pub iterations: u32,
    pub url_encryption: bool,
    pub url_logging: bool,
}
