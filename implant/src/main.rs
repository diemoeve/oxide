mod config;
mod transport;

use oxide_shared::packet::Packet;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = config::Config::lab_default();
    println!("[*] Connecting to {}:{}...", config.host, config.port);

    let mut transport = transport::Transport::connect(&config).await?;
    println!("[+] TLS handshake complete");

    let checkin = Packet::new("checkin", serde_json::json!({
        "hwid": "skeleton-hwid",
        "hostname": "test-host",
    }));
    transport.send(checkin).await?;
    println!("[+] Sent check-in");

    let ack = transport.receive().await?;
    println!("[+] Received: {} (type={})", ack.id, ack.packet_type);

    Ok(())
}
