use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct DomainEntry {
    pub name: String,
    pub ip: IpAddr,
}

fn parse_line(line: &str) -> Option<DomainEntry> {
    // some cleanup
    let line = line.replace("\t", " ").trim().to_string();
    // remove empty lines or comments.
    if line == "" || line.starts_with("#") {
        return None;
    }
    // parse the line and make sure it has at least 2 items.
    let line_items: Vec<&str> = line.split(" ").map(|e| e).filter(|e| e != &"").collect();
    // we only want
    let ip = if let Some(ip) = line_items.get(0) {
        ip.to_string()
    } else {
        return None;
    };
    let mut name = if let Some(name) = line_items.get(1) {
        name.to_string()
    } else {
        return None;
    };
    if let Ok(ip) = ip.parse() {
        if !name.ends_with(".") {
            name = format!("{}.", name);
        }
        return Some(DomainEntry { ip: ip, name: name });
    }
    None
}

async fn load_host_file(p: Option<String>) -> anyhow::Result<Vec<DomainEntry>> {
    let p = match p {
        Some(p) => p,
        None => return Ok(vec![]),
    };
    let content = tokio::fs::read_to_string(p).await?;
    let out = content
        .split("\n")
        .into_iter()
        .map(parse_line)
        .flatten()
        .collect();
    return Ok(out);
}

pub async fn load_domain_list(p: Option<String>) -> anyhow::Result<Vec<DomainEntry>> {
    let out = load_host_file(p).await?;
    let out = out
        .into_iter()
        .filter(|e| e.ip.to_string() == "0.0.0.0")
        .collect();
    Ok(out)
}

pub async fn load_host_list(p: Option<String>) -> anyhow::Result<Vec<DomainEntry>> {
    let out = load_host_file(p).await?;
    Ok(out)
}
