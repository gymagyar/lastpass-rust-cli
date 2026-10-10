use anyhow::{Context, Result, bail, ensure};
use quick_xml::{Reader, events::Event};
use std::collections::BTreeMap;
use zeroize::Zeroize;

#[derive(Default, Clone)]
pub struct Node {
    pub name: String,
    pub attrs: BTreeMap<String, String>,
    pub text: String,
    pub children: Vec<Node>,
}
impl Drop for Node {
    fn drop(&mut self) {
        self.name.zeroize();
        self.text.zeroize();
        for (mut key, mut value) in std::mem::take(&mut self.attrs) {
            key.zeroize();
            value.zeroize();
        }
    }
}
impl Node {
    pub fn find(&self, name: &str) -> Option<&Node> {
        if self.name == name {
            Some(self)
        } else {
            self.children.iter().find_map(|n| n.find(name))
        }
    }
    pub fn child(&self, name: &str) -> Option<&Node> {
        self.children.iter().find(|n| n.name == name)
    }
    pub fn value(&self, name: &str) -> String {
        self.child(name).map(|n| n.text.clone()).unwrap_or_default()
    }
    pub fn attr(&self, name: &str) -> String {
        self.attrs.get(name).cloned().unwrap_or_default()
    }
}
pub fn parse(bytes: &[u8]) -> Result<Node> {
    ensure!(bytes.len() <= 8 * 1024 * 1024, "XML response too large");
    let mut reader = Reader::from_reader(bytes);
    let mut stack = vec![Node::default()];
    loop {
        match reader.read_event().context("Invalid XML response")? {
            Event::Start(e) => {
                ensure!(stack.len() < 128, "XML nesting limit exceeded");
                stack.push(read_node(e, reader.decoder())?);
            }
            Event::Empty(e) => stack
                .last_mut()
                .context("Missing XML parent")?
                .children
                .push(read_node(e, reader.decoder())?),
            Event::End(_) => {
                ensure!(stack.len() > 1, "Invalid XML closing tag");
                let n = stack.pop().context("Missing XML node")?;
                stack
                    .last_mut()
                    .context("Missing XML parent")?
                    .children
                    .push(n);
            }
            Event::Text(e) => {
                let decoded = e.decode()?;
                let value = quick_xml::escape::unescape(&decoded)?;
                stack
                    .last_mut()
                    .context("Missing XML node")?
                    .text
                    .push_str(&value);
            }
            Event::CData(e) => stack
                .last_mut()
                .context("Missing XML node")?
                .text
                .push_str(&e.decode()?),
            Event::DocType(_) => bail!("DTD is not accepted in LastPass responses"),
            Event::GeneralRef(e) => {
                let name = e.decode()?;
                let entity = format!("&{name};");
                stack
                    .last_mut()
                    .context("Missing XML node")?
                    .text
                    .push_str(&quick_xml::escape::unescape(&entity)?);
            }
            Event::Eof => break,
            _ => {}
        }
    }
    ensure!(stack.len() == 1, "Unclosed XML response");
    let root = stack.pop().context("Missing XML root")?;
    ensure!(root.children.len() == 1, "Missing XML root");
    Ok(root.children[0].clone())
}
fn read_node(
    e: quick_xml::events::BytesStart<'_>,
    decoder: quick_xml::encoding::Decoder,
) -> Result<Node> {
    let mut node = Node::default();
    node.name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
    for attr in e.attributes() {
        let a = attr.context("Invalid XML attribute")?;
        node.attrs.insert(
            String::from_utf8_lossy(a.key.as_ref()).into_owned(),
            a.decode_and_unescape_value(decoder)?.into_owned(),
        );
    }
    Ok(node)
}
pub fn error_message(root: &Node) -> Option<String> {
    root.find("error").map(|e| {
        let message = e.attr("message");
        if message.is_empty() {
            let cause = e.attr("cause");
            if cause.is_empty() {
                "LastPass rejected the request".into()
            } else {
                cause
            }
        } else {
            message.replace(" Upgrade your browser extension so you can enter it.", "")
        }
    })
}
pub fn check_reply(bytes: &[u8]) -> Result<()> {
    let trimmed = std::str::from_utf8(bytes)
        .context("Invalid server response")?
        .trim();
    ensure!(!trimmed.is_empty(), "Server returned no acknowledgement");
    if trimmed.starts_with('<') {
        let root = parse(bytes)?;
        ensure!(
            root.attr("rc").is_empty() || root.attr("rc") == "OK",
            "LastPass API rejected the request"
        );
        if let Some(error) = error_message(&root) {
            bail!("LastPass rejected the request: {error}");
        }
        if let Some(error) = root.find("errorcode") {
            ensure!(
                error.text == "0" || error.text.is_empty(),
                "LastPass API error {}",
                error.text
            );
        }
        if let Some(result) = root.find("result") {
            ensure!(
                result.attr("errorcode").is_empty() || result.attr("errorcode") == "0",
                "LastPass API rejected the request"
            );
        }
        ensure!(
            root.name != "html",
            "LastPass returned an HTML page instead of an acknowledgement"
        );
    } else if trimmed.starts_with('{') {
        let v: serde_json::Value = serde_json::from_str(trimmed)?;
        ensure!(
            v.get("error").is_none() && v.get("success") != Some(&false.into()),
            "LastPass rejected the request"
        );
    } else {
        ensure!(
            trimmed == "OK" || trimmed == "ok" || trimmed == "1" || trimmed.starts_with("aid="),
            "Unrecognized server acknowledgement"
        );
    }
    Ok(())
}
