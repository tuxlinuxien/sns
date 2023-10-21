use anyhow::Result;

pub async fn ip_bin() -> Result<()> {
    let mut cmd = tokio::process::Command::new("which");
    cmd.arg("ip");
    let output = cmd.output().await.unwrap();
    if !output.status.success() {
        return Err(anyhow::anyhow!("command 'ip' was not found on your system"));
    }
    Ok(())
}

pub fn check_flags(tcp: bool, udp: bool) -> Result<()> {
    if tcp == false && udp == false {
        return Err(anyhow::anyhow!(
            "at least one of TCP or UDP must be enabled"
        ));
    }
    Ok(())
}
